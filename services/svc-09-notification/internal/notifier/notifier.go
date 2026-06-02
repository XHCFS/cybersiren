// Package notifier turns emails.verdict events into rate-limited alerts. It
// reads per-org notification preferences (threshold + channels), decides whether
// a verdict warrants an alert, enforces one alert per campaign per org per hour,
// and dispatches to the enabled channels. ARCH-SPEC Step 6a.
package notifier

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	valkeygo "github.com/valkey-io/valkey-go"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

const (
	// defaultThreshold mirrors organisations.notification_threshold's default.
	defaultThreshold = 70
	// rateLimitTTLSeconds is the per-campaign-per-org alert suppression window.
	rateLimitTTLSeconds = 3600
)

// defaultChannels is used when an org has no channels configured.
var defaultChannels = []string{"webhook"}

// highSeverityLabels always alert regardless of the numeric threshold.
var highSeverityLabels = map[string]bool{"phishing": true, "malware": true}

// Queries is the slice of the sqlc API the notifier needs (*dbsqlc.Queries
// satisfies it; tests use a fake).
type Queries interface {
	GetOrgNotificationConfig(ctx context.Context, id int64) (dbsqlc.GetOrgNotificationConfigRow, error)
	ListOrgAdminEmails(ctx context.Context, orgID int64) ([]string, error)
}

// Notifier processes verdicts into alerts.
type Notifier struct {
	q   Queries
	vk  valkeygo.Client
	log zerolog.Logger
}

// New builds a Notifier. pool may be a *pgxpool.Pool wrapped by dbsqlc.New.
func New(q Queries, vk valkeygo.Client, log zerolog.Logger) *Notifier {
	return &Notifier{q: q, vk: vk, log: log}
}

// NewFromPool is the production constructor.
func NewFromPool(pool *pgxpool.Pool, vk valkeygo.Client, log zerolog.Logger) *Notifier {
	return New(dbsqlc.New(pool), vk, log)
}

// ShouldNotify reports whether a verdict warrants an alert: a high-severity
// label always does, otherwise the risk score must meet the org threshold.
func ShouldNotify(label string, riskScore, threshold int) bool {
	if highSeverityLabels[label] {
		return true
	}
	return riskScore >= threshold
}

// parseChannels decodes the notification_channels JSONB array, falling back to
// the default when empty or malformed.
func parseChannels(raw []byte) []string {
	if len(raw) == 0 {
		return defaultChannels
	}
	var channels []string
	if err := json.Unmarshal(raw, &channels); err != nil || len(channels) == 0 {
		return defaultChannels
	}
	return channels
}

// Process evaluates one verdict and dispatches an alert if warranted. It never
// returns an error for a "no alert" outcome; it returns an error only when the
// Kafka offset should not be committed (none today — alerts are best-effort).
func (n *Notifier) Process(ctx context.Context, v contracts.EmailsVerdict) error {
	log := n.log.With().Int64("email_id", v.Meta.EmailID).Int64("org_id", v.Meta.OrgID).Logger()
	if v.Meta.OrgID == 0 {
		log.Debug().Msg("verdict without org_id; skipping notification")
		return nil
	}

	threshold := defaultThreshold
	channels := defaultChannels
	if cfg, err := n.q.GetOrgNotificationConfig(ctx, v.Meta.OrgID); err != nil {
		log.Warn().Err(err).Msg("org notification config lookup failed; using defaults")
	} else {
		if cfg.NotificationThreshold.Valid {
			threshold = int(cfg.NotificationThreshold.Int32)
		}
		channels = parseChannels(cfg.NotificationChannels)
	}

	if !ShouldNotify(v.VerdictLabel, v.RiskScore, threshold) {
		log.Debug().Str("verdict", v.VerdictLabel).Int("risk", v.RiskScore).Int("threshold", threshold).Msg("below notify threshold")
		return nil
	}

	if !n.allowAlert(ctx, v.Meta.OrgID, v.CampaignID, v.Meta.EmailID) {
		log.Info().Msg("alert suppressed by per-campaign rate limit")
		return nil
	}

	n.dispatch(ctx, log, v, channels)
	return nil
}

// allowAlert enforces one alert per (org, campaign) per hour via Valkey SET NX.
// Verdicts without a campaign are keyed by email_id so each still alerts once.
// A Valkey error fails open (allow) so alerts aren't silently dropped.
func (n *Notifier) allowAlert(ctx context.Context, orgID int64, campaignID *int64, emailID int64) bool {
	if n.vk == nil {
		return true
	}
	scope := fmt.Sprintf("e%d", emailID)
	if campaignID != nil {
		scope = fmt.Sprintf("c%d", *campaignID)
	}
	key := fmt.Sprintf("notif:{%d}:%s", orgID, scope)
	err := n.vk.Do(ctx, n.vk.B().Set().Key(key).Value("1").Nx().ExSeconds(rateLimitTTLSeconds).Build()).Error()
	if err == nil {
		return true // key set ⇒ first alert in the window
	}
	if valkeygo.IsValkeyNil(err) {
		return false // NX failed ⇒ already alerted
	}
	n.log.Warn().Err(err).Msg("rate-limit check failed; allowing alert")
	return true
}

// dispatch sends the alert to each enabled channel. Webhook/Slack are stubbed as
// structured log lines; email resolves the org's admin recipients. Real
// transports slot in behind this without changing Process.
func (n *Notifier) dispatch(ctx context.Context, log zerolog.Logger, v contracts.EmailsVerdict, channels []string) {
	for _, ch := range channels {
		ev := log.Info().Str("channel", ch).Str("verdict", v.VerdictLabel).Int("risk_score", v.RiskScore)
		if v.CampaignID != nil {
			ev = ev.Int64("campaign_id", *v.CampaignID)
		}
		switch ch {
		case "email":
			recipients, err := n.q.ListOrgAdminEmails(ctx, v.Meta.OrgID)
			if err != nil {
				log.Warn().Err(err).Msg("resolve admin recipients failed")
				recipients = nil
			}
			ev.Strs("recipients", recipients).Msg("ALERT email (stub)")
		case "webhook", "slack":
			ev.Msg("ALERT " + ch + " (stub)")
		default:
			ev.Msg("ALERT unknown channel (stub)")
		}
	}
}
