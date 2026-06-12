// Package dedup is svc-01's ingestion dedup gate. The primary path is a Valkey
// atomic claim (SET dedup:{org}:{message_id} "1" NX EX 7d, mirroring svc-09's
// rate-limit claim in store.go); on Valkey error/unavailability it degrades to a
// read-only check of the email_identities registry (migration 015) inside
// WithOrgTx.
//
// svc-02 remains the SOLE writer of both the emails table and the
// email_identities registry (it has the DB-assigned internal_id; svc-01 does
// not). svc-01's DB fallback is therefore a READ — GetEmailIdentity — not a
// claim: it suppresses an obvious re-publish when Valkey is down, while the
// authoritative cross-partition dedup still happens at svc-02's
// RegisterEmailIdentity. A duplicate that slips through a Valkey outage is
// caught there (ON CONFLICT DO NOTHING), so the pipeline never double-persists.
package dedup

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	valkeygo "github.com/valkey-io/valkey-go"

	db "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/shared/postgres/repository"
)

// ClaimTTLSeconds is the dedup window: 7 days, per the spec Redis key table
// (dedup:{org_id}:{message_id}, 604800s TTL).
const ClaimTTLSeconds = 604800

// Deduper claims (org_id, message_id) once per window. New returns true for the
// first sighting (publish), false for a duplicate (suppress).
type Deduper struct {
	valkey valkeygo.Client
	pool   *pgxpool.Pool
}

// New builds a Deduper. valkey may be nil (every claim then degrades to the DB
// read fallback); pool may be nil only in tests that never exercise the
// fallback.
func New(valkey valkeygo.Client, pool *pgxpool.Pool) *Deduper {
	return &Deduper{valkey: valkey, pool: pool}
}

// Claim returns true if this is the first sighting of (orgID, messageID) within
// the dedup window, false if it is a duplicate. An empty messageID is never
// deduplicated (NULL message_ids are excluded from the registry, mirroring
// svc-02) — it always returns true.
func (d *Deduper) Claim(ctx context.Context, orgID int64, messageID string) (bool, error) {
	if messageID == "" {
		return true, nil
	}

	// Primary: atomic Valkey claim. SET key "1" NX EX ttl — the first writer in
	// the window gets OK (new), subsequent writers get nil (duplicate). The TTL
	// is armed in the same command, so a crashed round-trip can never leave a
	// key without expiry (mirrors svc-09 store.go).
	if d.valkey != nil {
		key := claimKey(orgID, messageID)
		_, err := d.valkey.Do(ctx,
			d.valkey.B().Set().Key(key).Value("1").Nx().ExSeconds(ClaimTTLSeconds).Build(),
		).ToString()
		switch {
		case err == nil:
			return true, nil // claimed → new
		case valkeygo.IsValkeyNil(err):
			return false, nil // key already present → duplicate
		default:
			// Valkey error: fall through to the DB read fallback rather than
			// fail the ingest on a cache blip.
		}
	}

	// Fallback: read the email_identities registry under the org GUC. A present
	// row is a duplicate; absence means proceed (svc-02 does the authoritative
	// registration). Treat a fallback error as "not a known duplicate" — better
	// to publish (svc-02's ON CONFLICT dedups) than to drop a real email.
	return d.dbFallback(ctx, orgID, messageID)
}

func (d *Deduper) dbFallback(ctx context.Context, orgID int64, messageID string) (bool, error) {
	if d.pool == nil {
		// No Valkey and no pool: cannot dedup. Publish; svc-02 backstops.
		return true, nil
	}
	var seen bool
	err := repository.WithOrgTx(ctx, d.pool, orgID, func(q *db.Queries) error {
		_, getErr := q.GetEmailIdentity(ctx, db.GetEmailIdentityParams{OrgID: orgID, MessageID: messageID})
		switch {
		case getErr == nil:
			seen = true // already registered → duplicate
			return nil
		case errors.Is(getErr, pgx.ErrNoRows):
			seen = false // first sighting (so far)
			return nil
		default:
			return fmt.Errorf("get email identity: %w", getErr)
		}
	})
	if err != nil {
		return false, fmt.Errorf("dedup db fallback: %w", err)
	}
	return !seen, nil
}

// claimKey builds the dedup:{org_id}:{message_id} Valkey key.
func claimKey(orgID int64, messageID string) string {
	return fmt.Sprintf("dedup:%d:%s", orgID, messageID)
}
