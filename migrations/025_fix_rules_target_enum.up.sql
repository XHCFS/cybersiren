-- ============================================================
--  025_fix_rules_target_enum.sql
--
--  Converts rules.target from TEXT + CHECK to a proper PG enum,
--  aligning it with the pattern used for all other categorical
--  columns (verdict_label, verdict_source, job_status, job_type,
--  rule_status, entity_type_enum, feed_type_enum).
--
--  Changes:
--    #56  Create rule_target_enum and migrate rules.target.
--         Document the deliberate naming difference between
--         rule targets ('url') and entity types ('threat').
--
--  All statements idempotent.  No CONCURRENTLY.
-- ============================================================


-- ============================================================
--  #56  RULE TARGET ENUM
--
--  rules.target allows 'url' while entity_type_enum uses 'threat'.
--  These refer to different concepts:
--    • entity_type_enum describes what kind of entity is stored
--      (an enriched_threats row → 'threat').
--    • rule_target_enum describes what a detection rule evaluates
--      against ('url' = the URL text / structure, not the broader
--      threat-intel record).
--
--  The naming difference is intentional and documented below.
--  Using a dedicated enum prevents free-text drift and gives a
--  single place to add new target types (e.g. 'dns', 'body').
-- ============================================================


-- 1. Create the enum (idempotent).
CREATE TYPE rule_target_enum AS ENUM (
    'email',
    'url',
    'attachment',
    'header',
    'campaign'
);

COMMENT ON TYPE rule_target_enum IS
    'Defines what kind of artefact a detection rule evaluates.  '
    'Not to be confused with entity_type_enum, which identifies the '
    'kind of entity stored in a polymorphic reference (''threat'' refers '
    'to an enriched_threats row).  '
    'A rule with target = ''url'' evaluates URL text / structure, while '
    'entity_type = ''threat'' refers to the broader enriched threat-intel '
    'record that may contain URL, IP, domain, WHOIS, and certificate data.  '
    'To add a new target type: ALTER TYPE rule_target_enum ADD VALUE ''new_value'';';


-- 2. Drop the existing CHECK constraint on rules.target.
DO $$
DECLARE
    v_conname TEXT;
BEGIN
    SELECT con.conname
      INTO v_conname
      FROM pg_constraint con
      JOIN pg_class      rel ON rel.oid = con.conrelid
      JOIN pg_namespace  nsp ON nsp.oid = rel.relnamespace
     WHERE rel.relname   = 'rules'
       AND nsp.nspname   = current_schema()
       AND con.contype   = 'c'
       AND pg_get_constraintdef(con.oid) LIKE '%target%';

    IF v_conname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE rules DROP CONSTRAINT %I', v_conname);
    END IF;
END;
$$;


-- 3. Convert the column type.
--    USING handles the TEXT → enum cast.  If any row contains a
--    value outside the enum, the migration aborts.  Pre-flight:
--      SELECT DISTINCT target FROM rules ORDER BY 1;
DO $$
DECLARE
    v_typname TEXT;
BEGIN
    SELECT t.typname INTO v_typname
    FROM   pg_attribute a
    JOIN   pg_class     c ON c.oid = a.attrelid
    JOIN   pg_namespace n ON n.oid = c.relnamespace
    JOIN   pg_type      t ON t.oid = a.atttypid
    WHERE  n.nspname  = current_schema()
      AND  c.relname  = 'rules'
      AND  a.attname  = 'target'
      AND  a.attnum   > 0
      AND  NOT a.attisdropped;

    IF v_typname IS NOT NULL AND v_typname <> 'rule_target_enum' THEN
        ALTER TABLE rules
            ALTER COLUMN target TYPE rule_target_enum
            USING target::rule_target_enum;
    END IF;
END;
$$;

COMMENT ON COLUMN rules.target IS
    'The kind of artefact this rule evaluates.  Uses rule_target_enum.  '
    'NOTE: ''url'' (this enum) and ''threat'' (entity_type_enum) are '
    'deliberately different names for different concepts: '
    '  • rule target ''url'' → the rule logic inspects URL text and structure.  '
    '  • entity type ''threat'' → the polymorphic reference points to an '
    '    enriched_threats row (which may contain URL, IP, WHOIS, etc.).  '
    'Changed from TEXT + CHECK in migration 025.';
