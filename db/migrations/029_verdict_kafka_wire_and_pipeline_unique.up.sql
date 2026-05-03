-- Immutable emails.verdict JSON stored at pipeline commit for idempotent Kafka
-- republish (exact wire from the successful decision pass).
ALTER TABLE verdicts
    ADD COLUMN IF NOT EXISTS kafka_verdict_wire JSONB;

COMMENT ON COLUMN verdicts.kafka_verdict_wire IS
    'JSON payload last written to emails.verdict for this row (SVC-08). Populated in '
    'the same transaction as INSERT for automated sources so redelivery can publish '
    'byte-for-byte parity without recomputing rules. NULL on legacy rows until backfilled.';

-- Pre-flight guard: fail with a clear error before index build if
-- duplicates already exist for the indexed predicate.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM verdicts
        WHERE entity_type = 'email'::entity_type_enum
          AND email_fetched_at IS NOT NULL
          AND source IN ('model'::verdict_source, 'rule'::verdict_source)
        GROUP BY entity_id, email_fetched_at
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION
            'migration 029 aborted: duplicate verdicts for (entity_id, email_fetched_at) under source IN (model, rule); reconcile duplicates before rerun';
    END IF;
END
$$;

-- One automated (model|rule) verdict per partitioned email row — defense in depth
-- against concurrent double-insert and ambiguous commit replay.
CREATE UNIQUE INDEX IF NOT EXISTS uq_verdicts_pipeline_email_partition
    ON verdicts (entity_id, email_fetched_at)
    WHERE entity_type = 'email'::entity_type_enum
      AND email_fetched_at IS NOT NULL
      AND source IN ('model'::verdict_source, 'rule'::verdict_source);
