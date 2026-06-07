-- =============================================================================
-- enrichment_results.sql — cached third-party enrichment lookups (SVC-03/04)
-- =============================================================================
-- One row per (entity_type, entity_id, provider) UNIQUE; re-fetches UPSERT the
-- cached response and refresh the TTL. expires_at drives cache validity.
-- org_id is set for RLS scoping; email_fetched_at carries the emails partition
-- key when entity_type = 'email'.
-- =============================================================================

-- name: UpsertEnrichmentResult :one
-- Caches a provider's enrichment for an entity, refreshing the parsed vote
-- summary, raw payload and TTL on re-fetch. Returns the row id.
INSERT INTO enrichment_results (
    entity_type,
    entity_id,
    email_fetched_at,
    provider,
    raw_response,
    malicious_votes,
    harmless_votes,
    suspicious_votes,
    reputation_score,
    fetched_at,
    ttl_seconds,
    expires_at,
    org_id
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8,
    $9,
    NOW(),
    $10,
    $11,
    $12
)
ON CONFLICT (entity_type, entity_id, provider) DO UPDATE SET
    raw_response     = EXCLUDED.raw_response,
    malicious_votes  = EXCLUDED.malicious_votes,
    harmless_votes   = EXCLUDED.harmless_votes,
    suspicious_votes = EXCLUDED.suspicious_votes,
    reputation_score = EXCLUDED.reputation_score,
    fetched_at       = NOW(),
    ttl_seconds      = EXCLUDED.ttl_seconds,
    expires_at       = EXCLUDED.expires_at
RETURNING id;

-- name: GetFreshEnrichmentResult :one
-- Reads a still-valid cached enrichment for an entity+provider. Returns no rows
-- when the cache is missing or expired so the caller re-fetches.
SELECT *
FROM enrichment_results
WHERE entity_type = $1
  AND entity_id = $2
  AND provider = $3
  AND deleted_at IS NULL
  AND (expires_at IS NULL OR expires_at > NOW());
