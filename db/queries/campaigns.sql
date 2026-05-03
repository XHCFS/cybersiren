-- =============================================================================
-- campaigns.sql — campaign fingerprint / rolling-average queries for SVC-08
-- =============================================================================
-- See ARCH-SPEC §8.1 and docs/design/svc-07-08-design-brief.md §3.8.3.
--
-- The unique key on campaigns is `UNIQUE NULLS NOT DISTINCT (org_id, fingerprint)`
-- per migration 013_fix_multitenancy. The brief's example used
-- `ON CONFLICT (fingerprint)` — the actual schema requires the composite key.
--
-- email_count is stored inside the existing analysis_metadata JSONB blob to
-- avoid a schema migration for v1. A future migration may promote it to a
-- dedicated INTEGER column.
-- =============================================================================

-- name: GetCampaignByFingerprint :one
-- Read campaign history before computing the rolling-average update. The
-- returned email_count drives the empirical-Bayes shrinkage in SVC-08
-- (campaign-informed scoring). Returns no rows for a brand-new campaign.
SELECT
    id,
    risk_score,
    COALESCE((analysis_metadata->>'email_count')::int, 0) AS email_count
FROM campaigns
WHERE org_id = $1
  AND fingerprint = $2
  AND deleted_at IS NULL;

-- name: UpsertCampaign :one
-- Idempotent UPSERT: appends to an existing campaign or creates a new one.
-- The risk_score is updated as a rolling arithmetic mean over the email
-- count stored in analysis_metadata.
--
-- Returns:
--   id          — the campaign primary key.
--   is_new      — true when the row was just inserted (xmax IS 0 on insert).
--   email_count — the email count AFTER this email is incorporated.
INSERT INTO campaigns (
    org_id,
    fingerprint,
    name,
    threat_type,
    target_brand,
    first_seen,
    last_seen,
    risk_score,
    analysis_metadata,
    tags
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    NOW(),
    NOW(),
    $6,
    jsonb_build_object('email_count', 1),
    $7
)
ON CONFLICT (org_id, fingerprint) DO UPDATE SET
    last_seen        = NOW(),
    risk_score       = ROUND(
        ( COALESCE(campaigns.risk_score, 0)::numeric *
          COALESCE((campaigns.analysis_metadata->>'email_count')::int, 0)
          + EXCLUDED.risk_score::numeric )
        /
        ( COALESCE((campaigns.analysis_metadata->>'email_count')::int, 0) + 1 )
    )::int,
    analysis_metadata = jsonb_set(
        COALESCE(campaigns.analysis_metadata, '{}'::jsonb),
        '{email_count}',
        to_jsonb( COALESCE((campaigns.analysis_metadata->>'email_count')::int, 0) + 1 )
    )
RETURNING
    id,
    (xmax = 0) AS is_new,
    COALESCE((analysis_metadata->>'email_count')::int, 1) AS email_count;
