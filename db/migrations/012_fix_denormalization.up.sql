-- ============================================================
--  012_fix_denormalization.sql
--
--  Hardens two areas of denormalization in the schema:
--
--    #59  Immutability guard on rules that have existing hits.
--    #60  Document rule_hits point-in-time snapshot columns.
--    #61  Require at least one feed identifier on enriched_threats.
-- ============================================================


-- ============================================================
--  #59 — rules immutability trigger
--
--  A rule row must not be edited once any rule_hits reference it,
--  because rule_hits.rule_version and rule_hits.score_impact are
--  intentional point-in-time snapshots of the rule at firing time.
--  Allowing edits after hits exist would silently invalidate those
--  snapshots and make historical verdicts unexplainable.
--
--  Enforcement strategy:
--    • BEFORE UPDATE trigger raises an exception when the rule
--      already has ≥ 1 hit.  The caller must INSERT a new rule row
--      with an incremented version field instead.
--    • Rules with zero hits (e.g. drafts) can still be freely edited.
--
--  Idempotency:
--    • CREATE OR REPLACE FUNCTION replaces any earlier definition.
--    • DROP TRIGGER IF EXISTS + CREATE TRIGGER is repeatable.
-- ============================================================

CREATE OR REPLACE FUNCTION rules_immutable_after_hits()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_hit_count BIGINT;
BEGIN
    -- Guard: rule_hits may not yet exist on a fresh install that has
    -- not yet applied 003_add_enrichments.sql.  If the table is absent,
    -- no hits can exist, so the update is always safe.
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_catalog.pg_class  c
        JOIN   pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE  n.nspname = current_schema()
          AND  c.relname = 'rule_hits'
          AND  c.relkind = 'r'          -- ordinary table
    ) THEN
        RETURN NEW;
    END IF;

    SELECT COUNT(*) INTO v_hit_count
    FROM   rule_hits
    WHERE  rule_id = OLD.id;

    IF v_hit_count > 0 THEN
        RAISE EXCEPTION
            'Rule id=% (name=%, version=%) is immutable: it has % existing '
            'hit(s) in rule_hits.  To change the rule logic, INSERT a new '
            'rules row with an incremented version.',
            OLD.id, OLD.name, OLD.version, v_hit_count
            USING ERRCODE = 'restrict_violation';
    END IF;

    RETURN NEW;
END;
$$;

-- Drop first so the CREATE below is repeatable (CREATE TRIGGER has no
-- IF NOT EXISTS / OR REPLACE in PG 15).
DROP TRIGGER IF EXISTS trg_rules_immutable_after_hits ON rules;

CREATE TRIGGER trg_rules_immutable_after_hits
    BEFORE UPDATE ON rules
    FOR EACH ROW
    EXECUTE FUNCTION rules_immutable_after_hits();


-- ============================================================
--  #60 — document rule_hits point-in-time snapshot columns
--
--  COMMENT ON COLUMN is always idempotent: it replaces any
--  existing comment for the column.
-- ============================================================

COMMENT ON COLUMN rule_hits.rule_version IS
    'Point-in-time snapshot of rules.version at the moment this hit was '
    'recorded.  Denormalized intentionally so that the firing context is '
    'preserved even if the parent rules row is later versioned or archived.  '
    'Must not be updated after insert.';

COMMENT ON COLUMN rule_hits.score_impact IS
    'Point-in-time snapshot of rules.score_impact at the moment this hit was '
    'recorded.  Denormalized intentionally so that historical risk scores '
    'remain stable and explainable even after the rule is re-tuned.  '
    'Must not be updated after insert.';


-- ============================================================
--  #61 — require at least one feed identifier on enriched_threats
--
--  Background:
--    • source_feed TEXT was the original free-text feed label (001).
--    • feed_id BIGINT FK → feeds was added in 003 as its typed replacement.
--    • Neither column currently has a NOT NULL constraint, so rows with
--      both NULL are currently accepted, making provenance untrackable.
--
--  Constraint:
--    At least one of (feed_id, source_feed) must be non-NULL.
--    This is the weakest possible provenance requirement and is
--    backwards-compatible: any existing row that already has either
--    column populated continues to satisfy it.
--
--  Idempotency:
--    Wrapped in a DO block that checks pg_constraint before adding,
--    so re-running the migration on an already-patched database is safe.
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_catalog.pg_constraint
        WHERE  conrelid = 'enriched_threats'::regclass
          AND  conname   = 'chk_enriched_threats_feed_or_source'
    ) THEN
        ALTER TABLE enriched_threats
            ADD CONSTRAINT chk_enriched_threats_feed_or_source
            CHECK (
                feed_id    IS NOT NULL
             OR source_feed IS NOT NULL
            );
    END IF;
END;
$$;

-- source_feed: backwards-compat column retained from 001
COMMENT ON COLUMN enriched_threats.source_feed IS
    'Deprecated free-text feed label, retained for backwards compatibility '
    'with records ingested before the feeds table was introduced in migration '
    '003.  New inserts must populate feed_id instead.  This column will be '
    'dropped in a future migration once all legacy rows have been back-filled.';

-- feed_id: canonical feed reference added in 003
COMMENT ON COLUMN enriched_threats.feed_id IS
    'Foreign key to the feeds table (added in migration 003).  This is the '
    'canonical feed identifier and must be populated on all new inserts.  '
    'Supersedes the deprecated source_feed TEXT column.';
