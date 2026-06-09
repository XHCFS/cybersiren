-- =============================================================================
-- auth_reads.sql — identity / tenancy reads for SVC-01 ingestion + auth layer
-- =============================================================================
-- These read the control-plane tables (api_keys, users, organisations) that
-- resolve the tenant BEFORE org context exists, so they are NOT subject to the
-- app.current_org_id GUC. audit_log reads are operator-facing.
-- =============================================================================

-- name: GetAPIKeyByPrefix :many
-- Resolves candidate API keys by their stored lookup prefix (api_keys.key_prefix
-- — the leading fragment of the plaintext key produced by shared/auth
-- KeyManager.LookupPrefix). api_keys.key_hash is a *salted bcrypt* hash, so a
-- presented key can NEVER be matched by hash equality; the caller fetches the
-- candidate row(s) by their indexed prefix and then bcrypt-compares the presented
-- key against each key_hash (shared/auth ValidateKey). A prefix is selective but
-- not guaranteed unique, so this returns :many. Callers MUST still reject a key
-- whose revoked_at is set or whose expires_at is in the past.
SELECT
    id,
    org_id,
    user_id,
    name,
    key_prefix,
    key_hash,
    scopes,
    last_used_at,
    expires_at,
    revoked_at
FROM api_keys
WHERE key_prefix = $1;

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
