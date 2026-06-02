-- =============================================================================
-- svc05_attachments.sql — attachment scoring lookups owned by SVC-05
-- =============================================================================
-- SVC-05 resolves each attachment's library row by sha256 (for the malicious
-- short-circuit + entropy/magic-byte heuristics + the attachment_id needed to
-- write the per-email score back), then UPDATEs email_attachments.risk_score.
-- ARCH-SPEC Step 3c, §15 Gap #2.
-- =============================================================================

-- name: GetAttachmentBySHA256 :one
-- Returns the library row used to score an attachment. SVC-02 inserts this row
-- before publishing analysis.attachments, so it exists at consume time.
SELECT id, is_malicious, entropy, actual_extension, size_bytes
FROM attachment_library
WHERE sha256 = $1;

-- name: UpdateEmailAttachmentRiskScore :exec
-- Writes the scored risk back to the per-email attachment occurrence.
UPDATE email_attachments
SET risk_score = $4
WHERE email_id = $1 AND email_fetched_at = $2 AND attachment_id = $3;
