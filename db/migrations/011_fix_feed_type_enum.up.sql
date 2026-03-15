-- ============================================================
--  011_fix_feed_type_enum.sql
--  Converts feeds.feed_type from TEXT + CHECK constraint to a
--  proper PG enum, aligning it with every other categorical
--  column in this schema (verdict_label, verdict_source,
--  job_status, job_type, rule_status, user_role).
--
--  Idempotent: safe to re-run.
-- ============================================================


-- ============================================================
--  STEP 1 — Create the enum type (idempotent)
-- ============================================================

CREATE TYPE feed_type_enum AS ENUM (
    'threat_intel',
    'reputation',
    'blocklist',
    'sandbox'
);


-- ============================================================
--  STEP 2 — Drop the CHECK constraint by discovering its name
--            from pg_constraint (idempotent: no-op if gone)
-- ============================================================

DO $$
DECLARE
    v_constraint_name TEXT;
BEGIN
    SELECT con.conname
      INTO v_constraint_name
      FROM pg_constraint con
      JOIN pg_class      rel ON rel.oid = con.conrelid
      JOIN pg_namespace  nsp ON nsp.oid = rel.relnamespace
     WHERE rel.relname   = 'feeds'
       AND nsp.nspname   = current_schema()
       AND con.contype   = 'c'                          -- CHECK constraint
       AND pg_get_constraintdef(con.oid) LIKE '%feed_type%';

    IF v_constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE feeds DROP CONSTRAINT %I', v_constraint_name);
    END IF;
END;
$$;


-- ============================================================
--  STEP 3 — Alter the column type TEXT → feed_type_enum
--            (idempotent: no-op if already the enum type)
-- ============================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND table_name   = 'feeds'
           AND column_name  = 'feed_type'
           AND data_type    = 'text'          -- 'USER-DEFINED' once converted
    ) THEN
        ALTER TABLE feeds
            ALTER COLUMN feed_type TYPE feed_type_enum
            USING feed_type::feed_type_enum;
    END IF;
END;
$$;
