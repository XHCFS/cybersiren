-- =============================================================================
-- console_reads.sql — read-only composite-detail queries for the svc-10
-- analyst console (MVP-7). These back GET /api/v1/emails/{id} and the verdict /
-- rule-hit explainability panels. All reads against RLS-forced tables (verdicts,
-- rule_hits, enriched_threats) MUST run inside a tx that has set
-- app.current_org_id (WithOrgTx). email_identities has NO RLS policy, so its
-- read is scoped by the explicit org_id predicate.
-- =============================================================================

-- name: ResolveEmailByEmailID :one
-- Maps the opaque logical UUIDv7 email_id (G5/G17) onto the canonical physical
-- partition key (internal_id, fetched_at) via the email_identities dedup
-- registry. email_identities is NOT RLS-forced, so the org_id predicate is the
-- tenant boundary — a foreign tenant's email_id yields no row (fail-closed).
-- Returns no row when the email_id was never registered (NULL-message_id emails
-- and pre-035 rows are not resolvable by email_id).
SELECT internal_id, fetched_at
FROM email_identities
WHERE org_id = $1
  AND email_id = $2;

-- name: GetCurrentVerdictForEmail :one
-- The current (most-recent) verdict for an email, from the current_verdicts view
-- (DISTINCT ON (entity_type, entity_id) ORDER BY created_at DESC — migration
-- 005). entity_type is pinned to 'email' and entity_id = emails.internal_id.
-- The underlying verdicts table is RLS-forced, so this runs inside WithOrgTx.
-- Returns no row when the email has no verdict yet.
SELECT
    entity_type,
    entity_id,
    label,
    confidence,
    source,
    model_version,
    notes,
    created_by,
    created_at
FROM current_verdicts
WHERE entity_type = 'email'
  AND entity_id = $1;

-- name: ListVerdictsForEmail :many
-- Full append-only verdict history for an email, newest first, for the verdict
-- timeline panel. entity_type='email', entity_id=emails.internal_id. The
-- email_fetched_at predicate keeps the read inside the email's partition.
-- verdicts is RLS-forced (runs inside WithOrgTx).
SELECT
    id,
    label,
    confidence,
    source,
    model_version,
    notes,
    created_by,
    created_at
FROM verdicts
WHERE entity_type = 'email'
  AND entity_id = $1
  AND email_fetched_at = $2
ORDER BY created_at DESC, id DESC;

-- name: ListRuleHitsForEmail :many
-- Rule-firing history for an email (score explainability). Keyed on the
-- polymorphic pointer (entity_type='email', entity_id=emails.internal_id) plus
-- the partition's email_fetched_at. LEFT JOIN rules so the (possibly archived)
-- rule's name/version/status/target surface alongside the denormalised
-- point-in-time rule_version + score_impact snapshots on the hit row. rule_hits
-- is RLS-forced (runs inside WithOrgTx); rules is RLS-forced too and is admitted
-- by the same org GUC. A NULL rule_id (archived rule) leaves the joined rule
-- columns NULL — the snapshot columns on the hit still explain the score.
SELECT
    rh.id,
    rh.rule_id,
    rh.rule_version,
    rh.score_impact,
    rh.match_detail,
    rh.fired_at,
    r.name        AS rule_name,
    r.description AS rule_description,
    r.target      AS rule_target
FROM rule_hits rh
LEFT JOIN rules r ON r.id = rh.rule_id
WHERE rh.entity_type = 'email'
  AND rh.entity_id = $1
  AND rh.email_fetched_at = $2
ORDER BY rh.fired_at DESC, rh.id DESC;

-- name: GetEnrichedThreatByID :one
-- Reads one enriched_threats row (the TI / enrichment record an email_url points
-- to via threat_id) for the URL-threat detail panel. enriched_threats is
-- RLS-forced and its policy admits org-owned OR is_global rows, so this runs
-- inside WithOrgTx. Soft-deleted rows are excluded. Returns no row when the
-- threat_id is NULL/purged or hidden by the tenant boundary.
SELECT *
FROM enriched_threats
WHERE id = $1
  AND deleted_at IS NULL;

-- name: ListRulesForOrg :many
-- Read-only rules list for the console (MVP-7: NO write/CRUD). Returns the org's
-- rules plus platform-global rules (org_id IS NULL). NOTE: rules is RLS-forced
-- and its tenant_isolation policy (migration 018) requires org_id IS NOT NULL
-- AND org_id = current — so under RLS the global (org_id IS NULL) rules are NOT
-- visible to this read; the (org_id = @org_id OR org_id IS NULL) form is kept for
-- parity with ListActiveRulesForTargets, and the explicit org filter is the
-- effective boundary. Ordered by id for a stable page.
SELECT
    id,
    org_id,
    name,
    description,
    version,
    status,
    target,
    score_impact,
    created_at
FROM rules
WHERE (org_id = @org_id OR org_id IS NULL)
ORDER BY id;
