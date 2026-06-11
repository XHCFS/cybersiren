package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	db "github.com/saif/cybersiren/db/sqlc"
)

// Channel names recognised in organisations.notification_channels. Slack/Teams
// are out of scope for P2; an org may list "slack" in its JSONB but SVC-09
// only acts on email + webhook.
const (
	ChannelEmail   = "email"
	ChannelWebhook = "webhook"
)

// ErrOrgNotFound signals that the verdict's org row is missing (or
// soft-deleted). It is treated as a non-retryable skip — there is nobody to
// notify and replaying will never produce a row.
var ErrOrgNotFound = errors.New("notifier: organisation not found")

// OrgPrefs is the per-org notification configuration SVC-09 reads for each
// verdict: the alert threshold, the enabled channel set, and the admin email
// recipients.
type OrgPrefs struct {
	OrgID     int64
	Threshold int
	// Channels is the set of channel names enabled for the org, lower-cased.
	Channels map[string]struct{}
	// AdminEmails are the role='admin' recipient addresses (may be empty).
	AdminEmails []string
}

// HasChannel reports whether the org has the named channel enabled.
func (p OrgPrefs) HasChannel(name string) bool {
	_, ok := p.Channels[name]
	return ok
}

// OrgReader loads OrgPrefs from Postgres. It is the read-only seam the notifier
// depends on; the production implementation is PGOrgReader, tests use a fake.
type OrgReader interface {
	Load(ctx context.Context, orgID int64) (OrgPrefs, error)
}

// PGOrgReader reads org notification config + admin contacts via the
// sqlc-generated queries (GetOrganisationByID, ListOrgAdmins). organisations
// and users are control-plane tables (not RLS-forced), so these reads run
// directly on the pool without the app.current_org_id GUC; the org_id filter
// is the tenant boundary.
type PGOrgReader struct {
	pool *pgxpool.Pool
	// log surfaces the F3 observability signal: an undecodable
	// notification_channels column is degraded to opt-out (no NACK), but we WARN
	// so a config typo is distinguishable from a real opt-out. The zerolog zero
	// value is a no-op writer, so calling it unconditionally is safe.
	log zerolog.Logger
}

// NewPGOrgReader wraps a pgx pool with the service logger (used to surface a
// malformed notification_channels column — see Load / parseChannels). Pass
// zerolog.Nop() when no logging is wanted.
func NewPGOrgReader(pool *pgxpool.Pool, log zerolog.Logger) *PGOrgReader {
	return &PGOrgReader{pool: pool, log: log}
}

func (r *PGOrgReader) Load(ctx context.Context, orgID int64) (OrgPrefs, error) {
	if r == nil || r.pool == nil {
		return OrgPrefs{}, fmt.Errorf("notifier: nil postgres pool")
	}
	q := db.New(r.pool)

	org, err := q.GetOrganisationByID(ctx, orgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OrgPrefs{}, ErrOrgNotFound
		}
		return OrgPrefs{}, fmt.Errorf("get organisation %d: %w", orgID, err)
	}

	threshold := DefaultThreshold
	if org.NotificationThreshold.Valid {
		threshold = int(org.NotificationThreshold.Int32)
	}

	// A malformed notification_channels column is NOT a transient failure:
	// replaying the same row will never decode. Treating it as an error here
	// would NACK the message and wedge the partition forever on one bad org row
	// (blocking every other org on that partition too). parseChannels instead
	// degrades an undecodable column to the empty set (org opts out of alerts),
	// so the offset commits — same outcome as the NULL/empty case. We WARN on the
	// malformed case so a config typo is observable and not silently
	// indistinguishable from a deliberate opt-out (F3). The zerolog zero value is
	// a no-op writer, so this is safe even if no logger was supplied.
	channels, invalid := parseChannels(org.NotificationChannels)
	if invalid {
		r.log.Warn().
			Int64("org_id", orgID).
			Msg("notification_channels is not a JSON string array; treating org as opted-out of alerts")
	}

	admins, err := q.ListOrgAdmins(ctx, orgID)
	if err != nil {
		return OrgPrefs{}, fmt.Errorf("list org admins %d: %w", orgID, err)
	}
	emails := make([]string, 0, len(admins))
	for _, a := range admins {
		if e := strings.TrimSpace(a.Email); e != "" {
			emails = append(emails, e)
		}
	}

	return OrgPrefs{
		OrgID:       orgID,
		Threshold:   threshold,
		Channels:    channels,
		AdminEmails: emails,
	}, nil
}

// parseChannels decodes the notification_channels JSONB (a JSON array of
// strings) into a lower-cased set. A NULL/empty column means "no channels
// enabled" — a valid, non-error state (the org has opted out of alerts). A
// column that is valid JSONB but not a []string (e.g. an object like
// {"email":true}, or a bare string) is treated the same way: the org gets an
// empty channel set rather than an error. This is deliberate — a decode error
// is not transient, so propagating it would NACK the verdict and wedge the
// partition on one malformed org row. parseChannels therefore never returns an
// error; it fails closed to "no channels" on bad data.
//
// The second return value, invalid, is true ONLY when the column was non-empty
// AND failed to decode into a []string. The caller (Load) WARNs in that case so
// a config typo is observable rather than silently indistinguishable from a
// deliberate NULL/empty opt-out (F3). invalid is false for a valid array, NULL,
// or empty.
func parseChannels(raw []byte) (map[string]struct{}, bool) {
	out := map[string]struct{}{}
	if len(raw) == 0 {
		return out, false
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		// Undecodable as a []string: opt the org out (empty set) instead of
		// erroring, so the offset commits rather than NACKing forever. Flag it as
		// invalid so the caller can surface it.
		return out, true
	}
	for _, c := range list {
		c = strings.ToLower(strings.TrimSpace(c))
		if c != "" {
			out[c] = struct{}{}
		}
	}
	return out, false
}
