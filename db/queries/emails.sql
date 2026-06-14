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
--
-- Columns are exactly the set ARCH-SPEC §14 step 2 assigns to the parser
-- (including x_originating_ip / content_charset / precedence / list_id /
-- vendor_security_tags, which also ride analysis.headers). The score / verdict
-- columns (risk_score, header/content/url/attachment_risk_score, campaign_id,
-- analysis_metadata) are DELIBERATELY omitted — §14 step 2 keeps them at
-- DEFAULT 0 / NULL until the Decision Engine UPDATEs them in step 5.
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
    x_originating_ip,
    mailer_agent,
    in_reply_to,
    references_list,
    content_charset,
    precedence,
    list_id,
    vendor_security_tags,
    subject,
    sent_timestamp,
    headers_json,
    body_plain,
    body_html
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
    $22,
    $23,
    $24,
    $25,
    $26
)
RETURNING internal_id, fetched_at;

-- name: GetEmailByInternalID :one
-- Reads a single email row by its composite partition key. org-scoped via RLS.
SELECT *
FROM emails
WHERE internal_id = $1
  AND fetched_at = $2
  AND deleted_at IS NULL;

-- name: ListEmailsByOrg :many
-- svc-10 analyst-console list view: a page of an org's emails, newest fetched_at
-- first, with the list-row columns plus the denormalised current verdict label
-- (emails.current_verdict_label, kept in sync by trg_sync_email_verdict_label).
-- The logical UUIDv7 email_id is surfaced via a LEFT JOIN to the email_identities
-- dedup registry so the SPA can deep-link to the detail view; it is NULL for
-- emails registered before migration 035 or with no Message-ID. emails is
-- FORCE-RLS, so this read MUST run inside a tx that has set app.current_org_id
-- (WithOrgTx). email_identities has NO RLS policy, so the join is constrained to
-- the same tenant by the explicit ei.org_id predicate. LIMIT/OFFSET paginate.
SELECT
    e.internal_id,
    e.fetched_at,
    ei.email_id,
    e.message_id,
    e.sender_email,
    e.sender_name,
    e.sender_domain,
    e.subject,
    e.risk_score,
    e.current_verdict_label,
    e.sent_at
FROM emails e
LEFT JOIN email_identities ei
    ON  ei.internal_id = e.internal_id
    AND ei.fetched_at  = e.fetched_at
    AND ei.org_id      = $1
WHERE e.org_id = $1
  AND e.deleted_at IS NULL
ORDER BY e.fetched_at DESC, e.internal_id DESC
LIMIT $2 OFFSET $3;

-- name: GetEmailIdentity :one
-- Looks up the canonical (internal_id, fetched_at) for an (org_id, message_id)
-- pair in the cross-partition dedup registry. email_identities has NO RLS
-- policy, so org-scoping here is enforced solely by the explicit
-- `WHERE org_id = $1` predicate — NOT by the RLS GUC. A future variant that
-- drops that predicate trusting RLS would leak rows across tenants. Returns no
-- row when the message was never registered.
SELECT internal_id, fetched_at
FROM email_identities
WHERE org_id = $1
  AND message_id = $2;

-- name: RegisterEmailIdentity :one
-- Claims (org_id, message_id) for this ingestion. ON CONFLICT DO NOTHING makes
-- the claim atomic: a returned internal_id means we won the claim (new message),
-- while no row means another ingestion already registered it (duplicate signal).
-- email_id is the logical UUIDv7 (G5/G17), stamped here so the read side can map
-- it back to (internal_id, fetched_at); it is NULL when the email carries no
-- usable Message-ID (such emails are not registered). email_identities has NO
-- RLS policy: the write is scoped to the caller's tenant by the explicit org_id
-- value in the VALUES list, NOT by the RLS GUC.
INSERT INTO email_identities (org_id, message_id, internal_id, fetched_at, email_id)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (org_id, message_id) DO NOTHING
RETURNING internal_id;

-- name: DeleteEmailByKey :exec
-- Orphan cleanup: removes the emails row this ingestion inserted when it then
-- lost the email_identities claim to a racing ingestion. Keyed on the composite
-- partition key. Runs inside WithOrgTx so the RLS GUC scopes the delete.
DELETE FROM emails
WHERE internal_id = $1
  AND fetched_at = $2;
