-- name: UpsertTIIndicator :execresult
-- Upserts a single TI indicator. Use with batch loop from Go for chunk processing.
-- ON CONFLICT (feed_id, indicator_type, indicator_value):
--   update last_seen, merge threat_tags (distinct), GREATEST risk_score.
--   Do NOT overwrite first_seen or created_at.
INSERT INTO ti_indicators (
    feed_id,
    indicator_type,
    indicator_value,
    threat_type,
    brand_id,
    target_brand,
    threat_tags,
    source_id,
    first_seen,
    last_seen,
    confidence,
    risk_score,
    is_active,
    raw_metadata
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
    $10,
    $11,
    $12,
    $13,
    $14
)
ON CONFLICT (feed_id, indicator_type, indicator_value)
DO UPDATE
SET
    last_seen = EXCLUDED.last_seen,
    threat_tags = (
        SELECT ARRAY(
            SELECT DISTINCT tag
            FROM unnest(
                COALESCE(ti_indicators.threat_tags, '{}'::TEXT[]) ||
                COALESCE(EXCLUDED.threat_tags, '{}'::TEXT[])
            ) AS tag
            WHERE tag IS NOT NULL
              AND btrim(tag) <> ''
            ORDER BY tag
        )
    ),
    risk_score = GREATEST(ti_indicators.risk_score, EXCLUDED.risk_score);

-- name: DeactivateStaleFeedIndicators :execrows
-- Sets is_active = FALSE for indicators belonging to feed_id
-- not seen since the cutoff timestamp.
UPDATE ti_indicators
SET
    is_active = FALSE,
    updated_at = CURRENT_TIMESTAMP
WHERE feed_id = $1
  AND is_active = TRUE
  AND (last_seen IS NULL OR last_seen < $2);

-- name: ListActiveDomainIndicators :many
-- SELECT id, indicator_value, risk_score, threat_type
-- FROM ti_indicators WHERE indicator_type = 'domain' AND is_active = TRUE
SELECT
    id,
    indicator_value,
    risk_score,
    threat_type
FROM ti_indicators
WHERE indicator_type = 'domain'
  AND is_active = TRUE;
