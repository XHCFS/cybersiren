-- =============================================================================
-- email_recipients.sql — to/cc/bcc recipients of a parsed email (SVC-02)
-- =============================================================================
-- recipient_type is constrained to ('to','cc','bcc'). org_id is set for RLS.
-- =============================================================================

-- name: InsertEmailRecipient :one
-- Appends one recipient for an email by its composite partition key.
INSERT INTO email_recipients (
    email_id,
    email_fetched_at,
    org_id,
    address,
    display_name,
    recipient_type
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6
)
RETURNING id;

-- name: ListEmailRecipients :many
-- Lists recipients for an email by composite partition key. org-scoped via RLS.
SELECT id, address, display_name, recipient_type
FROM email_recipients
WHERE email_id = $1
  AND email_fetched_at = $2
ORDER BY id;
