-- =============================================================================
-- rules.sql — queries for SVC-04 (Header) and SVC-08 (Decision Engine)
-- =============================================================================
-- See ARCH-SPEC §13 (table origin) and §14 step 3b.
-- =============================================================================

-- name: ListActiveRulesForTargets :many
-- Returns every active rule whose target is in the given list (e.g. {'header','email'})
-- and whose org scope either matches the caller or is global (org_id IS NULL).
-- The (org_id IS NULL) branch lets a single SQL form serve both org-scoped
-- and platform-wide rules.
SELECT
    id,
    org_id,
    name,
    description,
    version,
    status,
    target,
    score_impact,
    logic,
    rule_group_id,
    created_at
FROM rules
WHERE status = 'active'
  AND target::text = ANY(@targets::text[])
  AND (org_id = @org_id OR org_id IS NULL)
ORDER BY id;

-- name: InsertRuleHit :one
-- Records a single rule fire. entity_type / entity_id form a polymorphic
-- pointer; SVC-04 always uses entity_type='email' + entity_id=emails.internal_id.
-- score_impact and rule_version are denormalized snapshots; they must NOT be
-- updated after insert (003 enrichments comment).
INSERT INTO rule_hits (
    rule_id,
    rule_version,
    entity_type,
    entity_id,
    email_fetched_at,
    score_impact,
    match_detail
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7
)
RETURNING id;
