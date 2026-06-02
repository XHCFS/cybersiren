-- =============================================================================
-- auth.sql — shared authentication lookups (shared/auth package)
-- =============================================================================
-- Used by SVC-01 ingestion and SVC-10 API to authenticate API keys against the
-- api_keys table. ARCH-SPEC §1 step 1, §14 step 1.
-- =============================================================================

-- name: GetAPIKeyByHash :one
-- Resolves an API key by its sha256 hash. The caller enforces revoked_at /
-- expires_at; both are returned so a single round-trip covers validation.
SELECT id, org_id, user_id, scopes, expires_at, revoked_at
FROM api_keys
WHERE key_hash = $1;

-- name: TouchAPIKeyLastUsed :exec
-- Records that a key authenticated successfully (ARCH-SPEC: last_used_at must be
-- updated on every successful key auth).
UPDATE api_keys SET last_used_at = NOW() WHERE id = $1;
