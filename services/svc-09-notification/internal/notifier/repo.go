package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

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
}

// NewPGOrgReader wraps a pgx pool.
func NewPGOrgReader(pool *pgxpool.Pool) *PGOrgReader {
	return &PGOrgReader{pool: pool}
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

	channels, err := parseChannels(org.NotificationChannels)
	if err != nil {
		return OrgPrefs{}, fmt.Errorf("parse notification_channels for org %d: %w", orgID, err)
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
// enabled" — a valid, non-error state (the org has opted out of alerts).
func parseChannels(raw []byte) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	if len(raw) == 0 {
		return out, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	for _, c := range list {
		c = strings.ToLower(strings.TrimSpace(c))
		if c != "" {
			out[c] = struct{}{}
		}
	}
	return out, nil
}
