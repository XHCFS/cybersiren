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

-- name: FindExistingVerdictForEmail :one
-- Idempotency probe for SVC-08 replay: returns the verdict already recorded for
-- this email partition key plus its stored kafka_verdict_wire (as text) so the
-- engine can republish byte-for-byte without recomputing. Returns no rows on
-- first processing.
SELECT id, COALESCE(kafka_verdict_wire::text, '') AS kafka_wire
FROM verdicts
WHERE entity_type = $1::entity_type_enum
  AND entity_id = $2
  AND email_fetched_at IS NOT NULL
  AND email_fetched_at = $3::timestamptz
LIMIT 1;

-- name: UpdateVerdictKafkaWire :exec
-- Persists the emails.verdict JSON written for this verdict so redelivery can
-- republish identical bytes. Written in the same tx as the verdict insert.
UPDATE verdicts SET kafka_verdict_wire = $1::jsonb WHERE id = $2;
