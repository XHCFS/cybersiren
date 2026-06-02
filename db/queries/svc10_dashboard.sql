-- =============================================================================
-- svc10_dashboard.sql — read + auth queries for the SVC-10 API/dashboard
-- =============================================================================
-- All list/detail reads are org-scoped (the org_id comes from the caller's JWT).
-- ARCH-SPEC Step 6b.
-- =============================================================================

-- name: GetUserForLogin :one
-- Resolves a login by email (emails are unique per org; LIMIT 1 covers the rare
-- cross-org duplicate). Returns the bcrypt hash for verification.
SELECT id, org_id, email, role, password_hash
FROM users
WHERE email = $1 AND deleted_at IS NULL
LIMIT 1;

-- name: TouchUserLastLogin :exec
UPDATE users SET last_login_at = NOW() WHERE id = $1;

-- name: ListEmailsByOrg :many
-- Paged scan list with the denormalised current verdict label + final score.
SELECT internal_id, fetched_at, sender_email, sender_domain, subject,
       risk_score, current_verdict_label
FROM emails
WHERE org_id = $1 AND deleted_at IS NULL
ORDER BY fetched_at DESC
LIMIT $2 OFFSET $3;

-- name: GetEmailForOrg :one
-- Scan detail header (org-scoped so one tenant can't read another's email).
SELECT internal_id, fetched_at, message_id, sender_name, sender_email, sender_domain,
       reply_to_email, return_path, subject, auth_spf, auth_dkim, auth_dmarc,
       header_risk_score, content_risk_score, attachment_risk_score, url_risk_score,
       risk_score, current_verdict_label, campaign_id
FROM emails
WHERE internal_id = $1 AND org_id = $2 AND deleted_at IS NULL;

-- name: ListEmailURLsForDetail :many
SELECT eu.id, et.url, eu.visible_text, et.domain, et.risk_score, et.threat_type
FROM email_urls eu
JOIN enriched_threats et ON et.id = eu.threat_id
WHERE eu.email_id = $1;

-- name: ListEmailAttachmentsForDetail :many
SELECT ea.attachment_id, ea.filename, ea.content_type, ea.risk_score,
       al.sha256, al.is_malicious, al.actual_extension
FROM email_attachments ea
JOIN attachment_library al ON al.id = ea.attachment_id
WHERE ea.email_id = $1;

-- name: ListEmailRecipientsForDetail :many
SELECT address, display_name, recipient_type
FROM email_recipients
WHERE email_id = $1;

-- name: ListEmailVerdicts :many
SELECT label, confidence, source, model_version, created_at
FROM verdicts
WHERE entity_type = 'email' AND entity_id = $1
ORDER BY created_at DESC;

-- name: GetOrgStats :one
-- Headline dashboard counters for an org.
SELECT
    count(*)                                                  AS total,
    count(*) FILTER (WHERE current_verdict_label = 'phishing')   AS phishing,
    count(*) FILTER (WHERE current_verdict_label = 'suspicious') AS suspicious,
    count(*) FILTER (WHERE risk_score >= 70)                  AS high_risk,
    count(*) FILTER (WHERE fetched_at >= NOW() - INTERVAL '24 hours') AS last_24h
FROM emails
WHERE org_id = $1 AND deleted_at IS NULL;

-- name: ListCampaignsByOrg :many
SELECT id, name, fingerprint, threat_type, target_brand, risk_score, first_seen, last_seen
FROM campaigns
WHERE org_id = $1 AND deleted_at IS NULL
ORDER BY last_seen DESC NULLS LAST
LIMIT $2;
