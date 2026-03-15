-- ============================================================
--  010_fix_entity_type_enum.sql
--  Replace per-table entity_type TEXT + CHECK with a single
--  shared enum type across all five tables that use it.
-- ============================================================

-- ============================================================
--  SAFETY NOTE
--  The ALTER COLUMN … USING casts every existing TEXT value to
--  the enum. If any row contains a value outside
--  ('email', 'threat', 'attachment', 'campaign') the migration
--  will abort with "invalid input value for enum".
--  Run a pre-flight check if unsure:
--
--    SELECT DISTINCT entity_type FROM verdicts
--    UNION SELECT DISTINCT entity_type FROM enrichment_jobs
--    UNION SELECT DISTINCT entity_type FROM enrichment_results
--    UNION SELECT DISTINCT entity_type FROM rule_hits
--    UNION SELECT DISTINCT entity_type FROM audit_log
--    ORDER BY 1;
--
--  Any unexpected value must be corrected or removed before
--  applying this migration.
-- ============================================================


-- ============================================================
--  1.  CREATE entity_type_enum
--
--  'campaign' is now also valid in enrichment_jobs and
--  enrichment_results (previously excluded by their CHECK
--  constraints) — this is intentional: campaigns can be
--  enriched the same way as other entity types.
--
--  To add a new entity type in the future:
--    ALTER TYPE entity_type_enum ADD VALUE 'new_value';
--  No CHECK constraints need to be updated.
-- ============================================================

CREATE TYPE entity_type_enum AS ENUM (
    'email',
    'threat',
    'attachment',
    'campaign'
);

COMMENT ON TYPE entity_type_enum IS
    'Canonical set of entity kinds used across the platform (verdicts, '
    'enrichment_jobs, enrichment_results, rule_hits, audit_log). '
    '''campaign'' is intentionally valid in enrichment tables — this was '
    'previously inconsistent with per-table CHECK constraints. '
    'To introduce a new entity type: ALTER TYPE entity_type_enum ADD VALUE ''new_value'';';


-- ============================================================
--  1b. DROP dependent views before altering columns
--
--  Views and materialized views that reference entity_type must
--  be dropped before we can ALTER the column type.
--  - current_verdicts (from 005) will be recreated below
--  - Materialized views (from 004) will be recreated in 017
-- ============================================================

-- Drop regular views
DROP VIEW IF EXISTS current_verdicts;

-- Drop materialized views
DROP MATERIALIZED VIEW IF EXISTS mv_threat_summary;
DROP MATERIALIZED VIEW IF EXISTS mv_campaign_summary;
DROP MATERIALIZED VIEW IF EXISTS mv_feed_health;
DROP MATERIALIZED VIEW IF EXISTS mv_rule_performance;
DROP MATERIALIZED VIEW IF EXISTS mv_org_ingestion_summary;


-- ============================================================
--  Helper: drop a CHECK constraint on entity_type by
--  discovering its name from pg_constraint at runtime.
--  This avoids hard-coding auto-generated constraint names
--  that may differ between environments or pg_dump restores.
-- ============================================================


-- ============================================================
--  2a.  verdicts
-- ============================================================

DO $$
DECLARE
    v_conname TEXT;
BEGIN
    SELECT conname INTO v_conname
    FROM   pg_constraint
    WHERE  conrelid = 'verdicts'::regclass
      AND  contype  = 'c'
      AND  pg_get_constraintdef(oid) ILIKE '%entity_type%';

    IF v_conname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE verdicts DROP CONSTRAINT %I', v_conname);
    END IF;
END;
$$;

ALTER TABLE verdicts
    ALTER COLUMN entity_type TYPE entity_type_enum
    USING entity_type::entity_type_enum;


-- ============================================================
--  2b.  enrichment_jobs
-- ============================================================

DO $$
DECLARE
    v_conname TEXT;
BEGIN
    SELECT conname INTO v_conname
    FROM   pg_constraint
    WHERE  conrelid = 'enrichment_jobs'::regclass
      AND  contype  = 'c'
      AND  pg_get_constraintdef(oid) ILIKE '%entity_type%';

    IF v_conname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE enrichment_jobs DROP CONSTRAINT %I', v_conname);
    END IF;
END;
$$;

ALTER TABLE enrichment_jobs
    ALTER COLUMN entity_type TYPE entity_type_enum
    USING entity_type::entity_type_enum;


-- ============================================================
--  2c.  enrichment_results
-- ============================================================

DO $$
DECLARE
    v_conname TEXT;
BEGIN
    SELECT conname INTO v_conname
    FROM   pg_constraint
    WHERE  conrelid = 'enrichment_results'::regclass
      AND  contype  = 'c'
      AND  pg_get_constraintdef(oid) ILIKE '%entity_type%';

    IF v_conname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE enrichment_results DROP CONSTRAINT %I', v_conname);
    END IF;
END;
$$;

-- The UNIQUE constraint on (entity_type, entity_id, provider) references the
-- entity_type column. Postgres allows the column type to change as long as the
-- UNIQUE index can be rebuilt, which ALTER COLUMN … USING handles atomically.
ALTER TABLE enrichment_results
    ALTER COLUMN entity_type TYPE entity_type_enum
    USING entity_type::entity_type_enum;


-- ============================================================
--  2d.  rule_hits
-- ============================================================

DO $$
DECLARE
    v_conname TEXT;
BEGIN
    SELECT conname INTO v_conname
    FROM   pg_constraint
    WHERE  conrelid = 'rule_hits'::regclass
      AND  contype  = 'c'
      AND  pg_get_constraintdef(oid) ILIKE '%entity_type%';

    IF v_conname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE rule_hits DROP CONSTRAINT %I', v_conname);
    END IF;
END;
$$;

ALTER TABLE rule_hits
    ALTER COLUMN entity_type TYPE entity_type_enum
    USING entity_type::entity_type_enum;


-- ============================================================
--  2e.  audit_log
--
--  audit_log.entity_type had no CHECK constraint in 002, so
--  the DO block is a no-op guard kept for consistency.
--  The column is nullable (no NOT NULL in 002), so existing
--  NULL values are preserved through the cast.
-- ============================================================

DO $$
DECLARE
    v_conname TEXT;
BEGIN
    SELECT conname INTO v_conname
    FROM   pg_constraint
    WHERE  conrelid = 'audit_log'::regclass
      AND  contype  = 'c'
      AND  pg_get_constraintdef(oid) ILIKE '%entity_type%';

    IF v_conname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE audit_log DROP CONSTRAINT %I', v_conname);
    END IF;
END;
$$;

ALTER TABLE audit_log
    ALTER COLUMN entity_type TYPE entity_type_enum
    USING entity_type::entity_type_enum;


-- ============================================================
--  3. RECREATE current_verdicts VIEW
--
--  Recreate the view that was dropped in step 1b, now with
--  entity_type as entity_type_enum instead of TEXT.
-- ============================================================

CREATE VIEW current_verdicts AS
SELECT DISTINCT ON (entity_type, entity_id)
    entity_type,
    entity_id,
    label,
    confidence,
    source,
    model_version,
    notes,
    created_by,
    created_at
FROM verdicts
ORDER BY entity_type, entity_id, created_at DESC;
