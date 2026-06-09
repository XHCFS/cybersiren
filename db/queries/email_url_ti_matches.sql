-- =============================================================================
-- email_url_ti_matches.sql — audit trail of TI feed matches against email URLs
-- =============================================================================
-- Records which ti_indicator was matched for each email_url and how. See the
-- email_url_ti_matches table comment (migration 026). match_type is constrained
-- to ('exact','domain','ip','cidr','hash'). The row is keyed UNIQUE on
-- (email_url_id, ti_indicator_id).
--
-- As of migration 033 this table has its own org_id and is FORCE-RLS with a
-- tenant_isolation policy, so isolation is ENFORCED (not merely "inherited"):
-- the surrounding tx must set app.current_org_id (see WithOrgTx).
-- =============================================================================

-- name: InsertEmailURLTIMatch :exec
-- Records a TI match for an email URL. org_id is NOT taken from the caller: it
-- is derived from the parent email_urls row, which is itself RLS-scoped to the
-- current org. So if email_url_id belongs to another tenant (or does not
-- exist), the SELECT yields no source row and nothing is inserted — fail-closed,
-- and structurally impossible to attach a match to a URL the org cannot see.
-- ON CONFLICT DO NOTHING keeps the audit write idempotent when the same
-- indicator matches the same URL twice; email_url_id is globally unique to one
-- org, so a conflict can only ever be with a same-org row.
INSERT INTO email_url_ti_matches (
    org_id,
    email_url_id,
    ti_indicator_id,
    match_type
)
SELECT
    eu.org_id,
    eu.id,
    sqlc.arg(ti_indicator_id),
    sqlc.arg(match_type)
FROM email_urls eu
WHERE eu.id = sqlc.arg(email_url_id)
ON CONFLICT (email_url_id, ti_indicator_id) DO NOTHING;

-- name: ListEmailURLTIMatches :many
-- Lists TI matches for a given email_url. RLS scopes the rows to the org whose
-- GUC is set on the surrounding tx.
SELECT id, ti_indicator_id, match_type, matched_at
FROM email_url_ti_matches
WHERE email_url_id = $1
ORDER BY id;
