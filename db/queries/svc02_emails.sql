-- =============================================================================
-- svc02_emails.sql — email persistence owned by SVC-02 Parser
-- =============================================================================
-- One transaction per email writes the canonical emails row plus its junction
-- tables. SVC-02 sets internal_id explicitly to the logical email_id carried on
-- the Kafka envelope so SVC-08's later UPDATE … WHERE internal_id = $1 hits this
-- exact row (ARCH-SPEC §1 step 2, §14 step 2). Score/campaign/metadata columns
-- are left at defaults — the Decision Engine fills them.
-- =============================================================================

-- name: InsertEmail :execrows
-- Inserts the canonical email row with an explicit internal_id (= envelope
-- email_id) and fetched_at, which together form the partition key. ON CONFLICT
-- DO NOTHING makes redelivery of the same Kafka message idempotent; the writer
-- uses the returned row count to skip junction writes when the row already
-- existed (avoiding duplicate email_urls / email_attachments PK conflicts).
INSERT INTO emails (
    internal_id, fetched_at, org_id,
    message_id,
    sender_name, sender_email, sender_domain, reply_to_email, return_path,
    auth_spf, auth_dkim, auth_dmarc, auth_arc,
    mailer_agent, in_reply_to, references_list,
    content_charset, precedence, list_id,
    subject, sent_timestamp, headers_json,
    body_plain, body_html
) VALUES (
    $1, $2, $3,
    $4,
    $5, $6, $7, $8, $9,
    $10, $11, $12, $13,
    $14, $15, $16,
    $17, $18, $19,
    $20, $21, $22,
    $23, $24
)
ON CONFLICT (internal_id, fetched_at) DO NOTHING;

-- name: UpsertEnrichedThreatBare :one
-- Ensures a bare enriched_threats row exists for a URL and returns its id for
-- the email_urls.threat_id FK. Enrichment columns are filled later by SVC-03.
-- source_feed='email' + is_global=TRUE satisfy the table's two CHECK constraints
-- (chk_enriched_threats_feed_or_source and chk_enriched_threats_global_or_org)
-- for an email-observed row; url is globally unique, so the enrichment record is
-- shared and the per-tenant link lives on email_urls.org_id.
INSERT INTO enriched_threats (url, domain, tld, source_feed, is_global)
VALUES ($1, $2, $3, 'email', TRUE)
ON CONFLICT (url) DO UPDATE
SET domain    = COALESCE(EXCLUDED.domain, enriched_threats.domain),
    tld       = COALESCE(EXCLUDED.tld, enriched_threats.tld),
    last_seen = NOW()
RETURNING id;

-- name: InsertEmailURL :exec
-- Links an email to an enriched_threats row, preserving the anchor visible text.
INSERT INTO email_urls (email_id, email_fetched_at, threat_id, visible_text, org_id)
VALUES ($1, $2, $3, $4, $5);

-- name: UpsertAttachmentLibrary :one
-- Deduplicates attachment binaries by sha256 (global, cross-tenant) and returns
-- the library id for the email_attachments FK.
INSERT INTO attachment_library (sha256, md5, sha1, size_bytes, entropy, actual_extension)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (sha256) DO UPDATE
SET md5              = COALESCE(EXCLUDED.md5, attachment_library.md5),
    sha1             = COALESCE(EXCLUDED.sha1, attachment_library.sha1),
    size_bytes       = COALESCE(EXCLUDED.size_bytes, attachment_library.size_bytes),
    entropy          = COALESCE(EXCLUDED.entropy, attachment_library.entropy),
    actual_extension = COALESCE(EXCLUDED.actual_extension, attachment_library.actual_extension)
RETURNING id;

-- name: InsertEmailAttachment :exec
-- Records one attachment occurrence on an email, joined to attachment_library.
INSERT INTO email_attachments (
    email_id, email_fetched_at, attachment_id,
    filename, content_type, content_id, disposition, org_id
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: InsertEmailRecipient :exec
-- Records one To/Cc/Bcc recipient of an email.
INSERT INTO email_recipients (
    email_id, email_fetched_at, org_id, address, display_name, recipient_type
) VALUES ($1, $2, $3, $4, $5, $6);
