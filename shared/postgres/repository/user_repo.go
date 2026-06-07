package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/saif/cybersiren/db/sqlc"
)

// UserRepository serves the control-plane identity reads (api_keys, users,
// organisations) that resolve a tenant BEFORE org context exists, plus the
// org-scoped audit_log read.
//
// api_keys / users / organisations are NOT RLS-forced: the API-key lookup is
// what establishes which org a request belongs to, so it must run before any
// app.current_org_id GUC can be set. These reads therefore go straight to the
// pool. audit_log IS RLS-forced, so its read runs under an org-scoped tx.
type UserRepository struct {
	pool *pgxpool.Pool
	q    *db.Queries
}

// NewUserRepository constructs a UserRepository over the pool.
func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	r := &UserRepository{pool: pool}
	if pool != nil {
		r.q = db.New(pool)
	}
	return r
}

// GetAPIKeyByHash resolves an API key by its stored hash. The caller MUST still
// reject the key when revoked_at is set or expires_at is in the past.
func (r *UserRepository) GetAPIKeyByHash(ctx context.Context, keyHash string) (db.GetAPIKeyByHashRow, error) {
	if err := r.ready(); err != nil {
		return db.GetAPIKeyByHashRow{}, err
	}
	row, err := r.q.GetAPIKeyByHash(ctx, keyHash)
	if err != nil {
		return db.GetAPIKeyByHashRow{}, fmt.Errorf("get api_key by hash: %w", err)
	}
	return row, nil
}

// TouchAPIKeyLastUsed records that an API key was used.
func (r *UserRepository) TouchAPIKeyLastUsed(ctx context.Context, id int64) error {
	if err := r.ready(); err != nil {
		return err
	}
	if err := r.q.TouchAPIKeyLastUsed(ctx, id); err != nil {
		return fmt.Errorf("touch api_key last_used: %w", err)
	}
	return nil
}

// GetOrganisationByID reads an organisation (ingestion limit, notification
// config) by id.
func (r *UserRepository) GetOrganisationByID(ctx context.Context, id int64) (db.Organisation, error) {
	if err := r.ready(); err != nil {
		return db.Organisation{}, err
	}
	org, err := r.q.GetOrganisationByID(ctx, id)
	if err != nil {
		return db.Organisation{}, fmt.Errorf("get organisation by id: %w", err)
	}
	return org, nil
}

// GetUserByID reads a user by id.
func (r *UserRepository) GetUserByID(ctx context.Context, id int64) (db.GetUserByIDRow, error) {
	if err := r.ready(); err != nil {
		return db.GetUserByIDRow{}, err
	}
	u, err := r.q.GetUserByID(ctx, id)
	if err != nil {
		return db.GetUserByIDRow{}, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}

// GetUserByEmail reads a user by (org_id, email) for login.
func (r *UserRepository) GetUserByEmail(ctx context.Context, orgID int64, email string) (db.GetUserByEmailRow, error) {
	if err := r.ready(); err != nil {
		return db.GetUserByEmailRow{}, err
	}
	u, err := r.q.GetUserByEmail(ctx, db.GetUserByEmailParams{OrgID: orgID, Email: email})
	if err != nil {
		return db.GetUserByEmailRow{}, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

// ListAuditLog reads the audit trail for an org. audit_log is RLS-forced, so
// this runs inside an org-scoped tx even though it is a read.
func (r *UserRepository) ListAuditLog(ctx context.Context, orgID int64, limit, offset int32) ([]db.ListAuditLogForOrgRow, error) {
	if r == nil || r.pool == nil {
		return nil, errors.New("user repository: nil pool")
	}
	var rows []db.ListAuditLogForOrgRow
	err := WithOrgTx(ctx, r.pool, orgID, func(q *db.Queries) error {
		got, err := q.ListAuditLogForOrg(ctx, db.ListAuditLogForOrgParams{
			OrgID:  orgID,
			Limit:  limit,
			Offset: offset,
		})
		if err != nil {
			return fmt.Errorf("list audit_log for org: %w", err)
		}
		rows = got
		return nil
	})
	return rows, err
}

func (r *UserRepository) ready() error {
	if r == nil {
		return errors.New("user repository is nil")
	}
	if r.pool == nil || r.q == nil {
		return errors.New("user repository: not initialised")
	}
	return nil
}
