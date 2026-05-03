-- =============================================================================
-- emails_scores.sql — emails risk-score updates owned by SVC-08 Decision Engine
-- =============================================================================
-- See ARCH-SPEC §1 Step 5 and docs/design/svc-07-08-design-brief.md §3.10.
-- Updates the partitioned emails table by composite (internal_id, fetched_at)
-- key.
-- =============================================================================

-- name: UpdateEmailScores :exec
-- Sets the final risk scores and campaign linkage for a fully-scored email.
-- analysis_metadata is JSONB; pass NULL to keep the existing value untouched
-- (sqlc maps []byte/nil to NULL).
UPDATE emails
SET risk_score            = $3,
    header_risk_score     = $4,
    content_risk_score    = $5,
    url_risk_score        = $6,
    attachment_risk_score = $7,
    campaign_id           = $8,
    analysis_metadata     = $9
WHERE internal_id = $1 AND fetched_at = $2;
