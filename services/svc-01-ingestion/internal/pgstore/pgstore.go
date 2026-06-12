// Package pgstore wires svc-01's narrow control-plane reads (api_keys lookup,
// organisations limit) onto the generated sqlc db.Queries. These are
// control-plane reads that resolve the tenant BEFORE org context exists, so they
// run on the raw pool and are NOT subject to the app.current_org_id GUC (see
// db/queries/auth_reads.sql).
package pgstore

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/auth"
)

// KeyStore adapts db.Queries to auth.KeyReader, mapping the generated
// GetAPIKeyByPrefixRow onto the auth package's transport-free APIKeyRow.
type KeyStore struct {
	pool *pgxpool.Pool
}

// NewKeyStore builds a KeyStore over the pool.
func NewKeyStore(pool *pgxpool.Pool) *KeyStore { return &KeyStore{pool: pool} }

// GetAPIKeyByPrefix returns the candidate api_keys rows for a lookup prefix.
func (s *KeyStore) GetAPIKeyByPrefix(ctx context.Context, keyPrefix string) ([]auth.APIKeyRow, error) {
	rows, err := db.New(s.pool).GetAPIKeyByPrefix(ctx, keyPrefix)
	if err != nil {
		return nil, fmt.Errorf("get api_keys by prefix: %w", err)
	}
	out := make([]auth.APIKeyRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, auth.APIKeyRow{
			ID:        r.ID,
			OrgID:     r.OrgID,
			KeyHash:   r.KeyHash,
			ExpiresAt: timePtr(r.ExpiresAt),
			RevokedAt: timePtr(r.RevokedAt),
		})
	}
	return out, nil
}

// timePtr maps a pgtype.Timestamptz to a *time.Time (nil when NULL).
func timePtr(ts pgtype.Timestamptz) *time.Time {
	if !ts.Valid {
		return nil
	}
	t := ts.Time
	return &t
}

// TouchAPIKeyLastUsed records that the key authenticated a request.
func (s *KeyStore) TouchAPIKeyLastUsed(ctx context.Context, id int64) error {
	if err := db.New(s.pool).TouchAPIKeyLastUsed(ctx, id); err != nil {
		return fmt.Errorf("touch api_keys last_used_at: %w", err)
	}
	return nil
}

// OrgStore adapts db.Queries to ingest.OrgReader, returning
// organisations.monthly_ingestion_limit (nil = unlimited).
type OrgStore struct {
	pool *pgxpool.Pool
}

// NewOrgStore builds an OrgStore over the pool.
func NewOrgStore(pool *pgxpool.Pool) *OrgStore { return &OrgStore{pool: pool} }

// MonthlyLimit reads organisations.monthly_ingestion_limit; a NULL column (or a
// missing org) maps to nil = unlimited.
func (s *OrgStore) MonthlyLimit(ctx context.Context, orgID int64) (*int32, error) {
	org, err := db.New(s.pool).GetOrganisationByID(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("get organisation by id: %w", err)
	}
	if !org.MonthlyIngestionLimit.Valid {
		return nil, nil
	}
	v := org.MonthlyIngestionLimit.Int32
	return &v, nil
}
