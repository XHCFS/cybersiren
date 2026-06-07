-- =============================================================================
-- emails.sql — partitioned emails table writes owned by SVC-02 Parser
-- =============================================================================
-- See ARCH-SPEC §1 Step 2 and docs/internals for the parser persistence model.
--
-- G5/G17 two-id model: the DB assigns internal_id (BIGSERIAL surrogate) and we
-- RETURN it. The logical email_id is carried SEPARATELY on the wire — there is
-- NO internal_id == email_id invariant. Callers must read the returned
-- (internal_id, fetched_at) composite key and propagate it to the partitioned
-- child tables (email_urls, email_attachments, email_recipients).
--
-- RLS (spec §16 D12): emails has FORCE ROW LEVEL SECURITY; the surrounding
-- transaction MUST issue `SET LOCAL app.current_org_id = <org>` (see the repo
-- WithOrgTx helper) so org_id is checked against the tenant GUC on write.
-- =============================================================================

-- name: InsertEmail :one
-- Inserts a freshly parsed email and returns the DB-assigned surrogate key
-- plus the partition key needed by every downstream child-row insert.
-- fetched_at is supplied by the caller (assigned at ingestion) so it stays
-- stable across the whole persist transaction.
INSERT INTO emails (
    fetched_at,
    org_id,
    message_id,
    sender_name,
    sender_email,
    sender_domain,
    reply_to_email,
    return_path,
    originating_ip,
    auth_spf,
    auth_dkim,
    auth_dmarc,
    auth_arc,
    mailer_agent,
    in_reply_to,
    references_list,
    subject,
    sent_timestamp,
    headers_json,
    body_plain,
    body_html,
    analysis_metadata
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
    $14,
    $15,
    $16,
    $17,
    $18,
    $19,
    $20,
    $21,
    $22
)
RETURNING internal_id, fetched_at;

-- name: GetEmailByInternalID :one
-- Reads a single email row by its composite partition key. org-scoped via RLS.
SELECT *
FROM emails
WHERE internal_id = $1
  AND fetched_at = $2
  AND deleted_at IS NULL;
