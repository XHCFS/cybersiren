-- =============================================================================
-- email_urls.sql — URLs extracted from a parsed email (SVC-02 Parser)
-- =============================================================================
-- email_urls links an email (composite partition key internal_id, fetched_at)
-- to the enriched_threats row for the URL, preserving the anchor visible_text.
-- threat_id is nullable (ON DELETE SET NULL) so the email↔URL link survives a
-- TI purge. org_id is set for RLS scoping.
-- =============================================================================

-- name: InsertEmailURL :one
-- Appends one extracted URL for an email. Returns the row id so callers can
-- record email_url_ti_matches against it.
INSERT INTO email_urls (
    email_id,
    email_fetched_at,
    threat_id,
    visible_text,
    org_id
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
)
RETURNING id;

-- name: ListEmailURLs :many
-- Lists URLs for an email by its composite partition key. org-scoped via RLS.
SELECT id, threat_id, visible_text
FROM email_urls
WHERE email_id = $1
  AND email_fetched_at = $2
ORDER BY id;
