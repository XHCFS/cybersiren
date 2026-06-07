-- =============================================================================
-- email_attachments.sql — per-email attachment links (SVC-02 Parser)
-- =============================================================================
-- Links an email (composite partition key) to an attachment_library row by its
-- content hash. Primary key is (email_id, email_fetched_at, attachment_id), so
-- a re-parsed email re-attaching the same library entry is idempotent.
-- =============================================================================

-- name: InsertEmailAttachment :exec
-- Inserts one attachment link. ON CONFLICT DO NOTHING keeps the write
-- idempotent across redelivery of the same parsed email.
INSERT INTO email_attachments (
    email_id,
    email_fetched_at,
    attachment_id,
    filename,
    content_type,
    analysis_metadata,
    content_id,
    disposition,
    risk_score,
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
    $10
)
ON CONFLICT (email_id, email_fetched_at, attachment_id) DO NOTHING;

-- name: ListEmailAttachments :many
-- Lists attachments for an email by composite partition key. org-scoped via RLS.
SELECT attachment_id, filename, content_type, disposition, risk_score
FROM email_attachments
WHERE email_id = $1
  AND email_fetched_at = $2
ORDER BY attachment_id;
