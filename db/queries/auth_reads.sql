-- =============================================================================
-- auth_reads.sql — identity / tenancy reads for SVC-01 ingestion + auth layer
-- =============================================================================
-- These read the control-plane tables (api_keys, users, organisations) that
-- resolve the tenant BEFORE org context exists, so they are NOT subject to the
-- app.current_org_id GUC. audit_log reads are operator-facing.
-- =============================================================================

-- name: GetAPIKeyByHash :one
-- Resolves an API key by its stored hash for request authentication. Callers
-- must still check expires_at / revoked_at against NOW() before trusting it.
SELECT
    id,
    org_id,
    user_id,
    name,
    key_prefix,
    scopes,
    last_used_at,
    expires_at,
    revoked_at
FROM api_keys
WHERE key_hash = $1;

-- name: TouchAPIKeyLastUsed :exec
-- Records that an API key was used for a request.
UPDATE api_keys
SET last_used_at = NOW()
WHERE id = $1;

-- name: GetOrganisationByID :one
-- Reads an organisation by id, including ingestion limit and notification
-- config. Soft-deleted orgs are excluded.
SELECT *
FROM organisations
WHERE id = $1
  AND deleted_at IS NULL;

-- name: GetUserByID :one
-- Reads a user by id. Soft-deleted users are excluded.
SELECT
    id,
    org_id,
    email,
    display_name,
    role,
    last_login_at,
    created_at
FROM users
WHERE id = $1
  AND deleted_at IS NULL;

-- name: GetUserByEmail :one
-- Reads a user by (org_id, email) for login. Soft-deleted users are excluded.
SELECT
    id,
    org_id,
    email,
    display_name,
    role,
    last_login_at,
    created_at
FROM users
WHERE org_id = $1
  AND email = $2
  AND deleted_at IS NULL;

-- name: ListAuditLogForOrg :many
-- Operator-facing audit trail for an organisation, newest first.
SELECT
    id,
    org_id,
    user_id,
    api_key_id,
    action,
    entity_type,
    entity_id,
    diff,
    ip_address,
    created_at
FROM audit_log
WHERE org_id = $1
ORDER BY created_at DESC, id DESC
LIMIT $2 OFFSET $3;
