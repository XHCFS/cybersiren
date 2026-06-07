-- =============================================================================
-- email_url_ti_matches.sql — audit trail of TI feed matches against email URLs
-- =============================================================================
-- Records which ti_indicator was matched for each email_url and how. See the
-- email_url_ti_matches table comment (migration 026). match_type is constrained
-- to ('exact','domain','ip','cidr','hash'). The row is keyed UNIQUE on
-- (email_url_id, ti_indicator_id).
--
-- This table has no org_id column; isolation is inherited through the parent
-- email_urls row (RLS-scoped) and the FK cascade.
-- =============================================================================

-- name: InsertEmailURLTIMatch :exec
-- Records a TI match for an email URL. ON CONFLICT DO NOTHING keeps the audit
-- write idempotent when the same indicator matches the same URL twice.
INSERT INTO email_url_ti_matches (
    email_url_id,
    ti_indicator_id,
    match_type
) VALUES (
    $1,
    $2,
    $3
)
ON CONFLICT (email_url_id, ti_indicator_id) DO NOTHING;

-- name: ListEmailURLTIMatches :many
-- Lists TI matches for a given email_url.
SELECT id, ti_indicator_id, match_type, matched_at
FROM email_url_ti_matches
WHERE email_url_id = $1
ORDER BY id;
