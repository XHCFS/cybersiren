-- =============================================================================
-- verdicts.sql — queries for SVC-08 Decision Engine
-- =============================================================================
-- See ARCH-SPEC §1 Step 5 and docs/design/svc-07-08-design-brief.md §3.10.
-- The verdicts table is APPEND-ONLY: never UPDATE / DELETE a verdict row.
-- =============================================================================

-- name: InsertVerdict :one
-- Records a single verdict for an email (entity_type='email').
-- entity_id  = emails.internal_id
-- email_fetched_at = emails.fetched_at (required for partitioned-table joins;
--                    see migration 014_fix_polymorphic_email_key).
-- source must be one of the verdict_source enum values: model | analyst | feed | rule.
INSERT INTO verdicts (
    entity_type,
    entity_id,
    email_fetched_at,
    label,
    confidence,
    source,
    model_version,
    org_id
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8
)
RETURNING id;
