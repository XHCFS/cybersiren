-- =============================================================================
-- email_campaign_snapshot.sql — campaign linkage lookup for dedupe replay
-- =============================================================================
-- Used by SVC-08 when a verdict row already exists for the same
-- (entity_id, email_fetched_at) partition key and the engine needs to
-- republish emails.verdict without recomputing campaign linkage.
-- =============================================================================

-- name: GetEmailCampaignSnapshot :one
SELECT
    e.campaign_id,
    COALESCE((c.analysis_metadata->>'email_count')::int, 0) AS email_count
FROM emails e
JOIN campaigns c ON c.id = e.campaign_id AND c.deleted_at IS NULL
WHERE e.internal_id = $1
  AND e.fetched_at = $2::timestamptz;
