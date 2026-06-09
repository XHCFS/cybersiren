-- =============================================================================
-- email_attachments.sql — per-email attachment links (SVC-02 Parser)
-- =============================================================================
-- Links an email (composite partition key) to an attachment_library row by its
-- content hash. Primary key is (email_id, email_fetched_at, attachment_id), so
-- a re-parsed email re-attaching the same library entry is idempotent.
-- =============================================================================

-- name: InsertEmailAttachment :exec
-- Inserts one attachment link (SVC-02). ON CONFLICT DO NOTHING keeps the write
-- idempotent across redelivery of the same parsed email. Per ARCH-SPEC §14
-- step 2 the parser does NOT set risk_score / analysis_metadata — they stay at
-- DEFAULT 0 / NULL until SVC-05 UPDATEs them after scoring (§15 gap #2).
INSERT INTO email_attachments (
    email_id,
    email_fetched_at,
    attachment_id,
    filename,
    content_type,
    content_id,
    disposition,
    org_id
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8
)
ON CONFLICT (email_id, email_fetched_at, attachment_id) DO NOTHING;

-- name: ListEmailAttachments :many
-- Lists attachments for an email by composite partition key. org-scoped via RLS.
SELECT attachment_id, filename, content_type, disposition, risk_score
FROM email_attachments
WHERE email_id = $1
  AND email_fetched_at = $2
ORDER BY attachment_id;
