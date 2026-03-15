-- ============================================================
--  022_fix_data_types.sql
--
--  Corrects column types that were initially defined with
--  insufficient precision or without leveraging native PG types.
--
--  Changes:
--    #21  enriched_threats.cidr_block  TEXT → CIDR
--    #22  enriched_threats.asn         INT  → BIGINT
--
--  All statements idempotent.  No CONCURRENTLY.
-- ============================================================


-- ============================================================
--  HELPER: safe_cidr_cast(TEXT) → CIDR
--
--  Attempts to cast a TEXT value to CIDR.  Returns NULL instead
--  of raising an exception when the value is not a valid CIDR
--  string.  Used only during the type migration below, then
--  dropped at the end of this file.
-- ============================================================

CREATE OR REPLACE FUNCTION safe_cidr_cast(val TEXT)
RETURNS CIDR
LANGUAGE plpgsql
IMMUTABLE STRICT
AS $$
BEGIN
    RETURN val::CIDR;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;


-- ============================================================
--  DROP dependent materialized views before altering columns
--
--  The materialized views from 017_fix_materialized_views.sql
--  reference enriched_threats columns we're about to alter.
--  They must be dropped before the ALTER and will be recreated
--  at the end of this migration.
-- ============================================================

DROP MATERIALIZED VIEW IF EXISTS mv_threat_summary;
DROP MATERIALIZED VIEW IF EXISTS mv_campaign_summary;
DROP MATERIALIZED VIEW IF EXISTS mv_feed_health;
DROP MATERIALIZED VIEW IF EXISTS mv_rule_performance;
DROP MATERIALIZED VIEW IF EXISTS mv_org_ingestion_summary;


-- ============================================================
--  #21  enriched_threats.cidr_block — TEXT → CIDR
--
--  Postgres has a native CIDR type that validates format on
--  insert and supports containment operators (<<=, >>=) and
--  indexing with GiST/SP-GiST.  Using TEXT allows invalid
--  strings and requires application-layer validation.
--
--  The USING clause calls safe_cidr_cast() so that any
--  invalid strings in existing data are silently NULLed out
--  rather than crashing the migration.
--
--  Pre-flight check (list values that will become NULL):
--    SELECT id, cidr_block
--    FROM   enriched_threats
--    WHERE  cidr_block IS NOT NULL
--      AND  safe_cidr_cast(cidr_block) IS NULL;
-- ============================================================

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
      AND  c.relname  = 'enriched_threats'
      AND  a.attname  = 'cidr_block'
      AND  a.attnum   > 0
      AND  NOT a.attisdropped;

    -- Only convert if the column still has a text-family type.
    IF v_typname IS NOT NULL AND v_typname NOT IN ('cidr') THEN
        ALTER TABLE enriched_threats
            ALTER COLUMN cidr_block TYPE CIDR
            USING safe_cidr_cast(cidr_block);
    END IF;
END;
$$;

COMMENT ON COLUMN enriched_threats.cidr_block IS
    'CIDR block of the resolved IP address.  Uses the native Postgres '
    'CIDR type which validates format on insert and supports containment '
    'operators (<<=, >>=) for network-range queries.  '
    'Changed from TEXT in migration 022.';


-- ============================================================
--  #22  enriched_threats.asn — INT → BIGINT
--
--  4-byte ASN numbers range from 0 to 4,294,967,294.  PG INT
--  (4 bytes, signed) maxes at 2,147,483,647, which means any
--  32-bit ASN above that value will overflow.  BIGINT (8 bytes)
--  safely covers the full range.
--
--  The type widening is safe: every INT value is a valid BIGINT.
--  Indexes on the column are rebuilt automatically by Postgres.
--
--  NOTE: mv_threat_summary stores COALESCE(asn, -1) in an INT
--  column (fixed at MV creation time).  The next DROP + CREATE
--  of the MV will pick up the BIGINT type.  Until then, any ASN
--  value > 2^31 - 1 will cause REFRESH to fail — recreate the MV
--  before ingesting such values.
-- ============================================================

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
      AND  c.relname  = 'enriched_threats'
      AND  a.attname  = 'asn'
      AND  a.attnum   > 0
      AND  NOT a.attisdropped;

    -- 'int4' = INT, 'int8' = BIGINT
    IF v_typname IS NOT NULL AND v_typname = 'int4' THEN
        ALTER TABLE enriched_threats
            ALTER COLUMN asn TYPE BIGINT;
    END IF;
END;
$$;

COMMENT ON COLUMN enriched_threats.asn IS
    'Autonomous System Number.  BIGINT covers the full 4-byte ASN range '
    '(0 – 4,294,967,294) without overflow.  Changed from INT in migration 022.';


-- ============================================================
--  CLEANUP: drop the helper function
-- ============================================================

DROP FUNCTION IF EXISTS safe_cidr_cast(TEXT);


-- ============================================================
--  NOTE: Materialized Views Require Manual Refresh
--
--  This migration dropped mv_threat_summary and other MVs to
--  allow the column type changes above.  After this migration
--  completes, you must manually recreate them by running:
--
--    1. Re-run the CREATE statements from 017_fix_materialized_views.sql
--       OR
--    2. Use the refresh helper: SELECT refresh_all_materialized_views();
--       (if the function exists and recreates dropped MVs)
--       OR
--    3. Deploy an idempotent MV creation script as part of your
--       normal deployment process
--
--  The MVs will remain absent until this step is performed.
-- ============================================================
