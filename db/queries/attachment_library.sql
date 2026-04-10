-- name: UpsertMalwareHash :exec
-- Upserts a malware hash into the attachment_library table.
-- ON CONFLICT (sha256): set is_malicious = TRUE, take GREATEST risk_score,
-- merge threat_tags (union, distinct, sorted), touch updated_at.
INSERT INTO attachment_library (sha256, is_malicious, risk_score, threat_tags)
VALUES ($1, TRUE, $2, $3)
ON CONFLICT (sha256)
DO UPDATE
SET
    is_malicious = TRUE,
    risk_score   = GREATEST(attachment_library.risk_score, EXCLUDED.risk_score),
    threat_tags  = (
        SELECT ARRAY(
            SELECT DISTINCT tag
            FROM unnest(
                COALESCE(attachment_library.threat_tags, '{}'::TEXT[]) ||
                COALESCE(EXCLUDED.threat_tags, '{}'::TEXT[])
            ) AS tag
            WHERE tag IS NOT NULL
              AND btrim(tag) <> ''
            ORDER BY tag
        )
    ),
    updated_at   = NOW();

-- name: ListMaliciousHashes :many
-- Returns all malicious hashes for populating the TI hash cache.
SELECT
    id,
    sha256,
    risk_score,
    threat_tags
FROM attachment_library
WHERE is_malicious = TRUE
  AND deleted_at IS NULL;
