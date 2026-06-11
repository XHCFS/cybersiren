-- name: UpsertParsedAttachment :one
-- SVC-02 Parser content-derived UPSERT (ARCH-SPEC §14 step 2). Keyed on the
-- sha256 UNIQUE constraint so re-observing the same attachment binary is
-- idempotent and returns the existing attachment_library.id used as the
-- email_attachments.attachment_id FK.
--
-- Per spec §14 step 2 the parser writes sha256/md5/sha1/actual_extension/
-- size_bytes/entropy; is_malicious/risk_score/threat_tags are left at DEFAULT
-- (SVC-05/SVC-11 own them). storage_uri is written here (G6 overrides the spec's
-- "left at default") once the binary has been uploaded to object storage; it is
-- only set/refreshed when a non-NULL value is supplied so a later hash-only or
-- failed-upload re-observation never nulls an existing pointer.
INSERT INTO attachment_library (
    sha256,
    md5,
    sha1,
    actual_extension,
    size_bytes,
    entropy,
    storage_uri
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7
)
ON CONFLICT (sha256)
DO UPDATE
SET
    md5              = COALESCE(EXCLUDED.md5, attachment_library.md5),
    sha1             = COALESCE(EXCLUDED.sha1, attachment_library.sha1),
    actual_extension = COALESCE(EXCLUDED.actual_extension, attachment_library.actual_extension),
    size_bytes       = COALESCE(EXCLUDED.size_bytes, attachment_library.size_bytes),
    entropy          = COALESCE(EXCLUDED.entropy, attachment_library.entropy),
    storage_uri      = COALESCE(EXCLUDED.storage_uri, attachment_library.storage_uri),
    updated_at       = NOW(),
    deleted_at       = NULL
RETURNING id;

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
    risk_score   = CASE
        WHEN attachment_library.risk_score IS NULL THEN EXCLUDED.risk_score
        WHEN EXCLUDED.risk_score IS NULL THEN attachment_library.risk_score
        ELSE GREATEST(attachment_library.risk_score, EXCLUDED.risk_score)
    END,
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
    updated_at   = NOW(),
    deleted_at   = NULL;

-- name: RecordAttachmentRisk :exec
-- SVC-05 heuristic-only risk record (ARCH-SPEC §1 step 3c, with a platform-
-- global-library safety carve-out): when heuristics flag a file dangerous but
-- there is NO hash/VT confirmation, record risk_score + threat_tags on the
-- shared attachment_library row WITHOUT setting is_malicious. is_malicious is
-- reserved for confirmed malice (UpsertMalwareHash) so one org's heuristic false
-- positive on a common file (e.g. a legitimate macro-enabled Office document)
-- cannot permanently brand that sha256 malicious for every tenant (the library
-- has no org_id; a TRUE flag short-circuits all future lookups to score 90).
INSERT INTO attachment_library (sha256, risk_score, threat_tags)
VALUES ($1, $2, $3)
ON CONFLICT (sha256)
DO UPDATE
SET
    risk_score   = CASE
        WHEN attachment_library.risk_score IS NULL THEN EXCLUDED.risk_score
        WHEN EXCLUDED.risk_score IS NULL THEN attachment_library.risk_score
        ELSE GREATEST(attachment_library.risk_score, EXCLUDED.risk_score)
    END,
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
    updated_at   = NOW(),
    deleted_at   = NULL;
-- is_malicious is intentionally NOT in the UPDATE SET: it keeps its current
-- value (DEFAULT FALSE for a parser-created row; unchanged if already TRUE).

-- name: ListMaliciousHashes :many
-- Returns all malicious hashes for populating the TI hash cache.
SELECT
    id,
    sha256,
    risk_score,
    threat_tags,
    updated_at
FROM attachment_library
WHERE is_malicious = TRUE
  AND deleted_at IS NULL;

-- name: GetAttachmentBySha256 :one
-- SVC-05 per-attachment hash lookup (ARCH-SPEC §1 step 3c). Resolves the
-- attachment_library row by its sha256 UNIQUE index so SVC-05 can read the
-- is_malicious / risk_score / threat_tags verdict (and the library id used as
-- the email_attachments.attachment_id FK and the VT cache entity_id). Returns
-- no rows when the binary has never been observed.
SELECT
    id,
    sha256,
    is_malicious,
    risk_score,
    threat_tags
FROM attachment_library
WHERE sha256 = $1
  AND deleted_at IS NULL;
