-- ============================================================
--  006_fix_partitioning.sql
--
--  Addresses three partitioning gaps in the emails table:
--
--  #35  Reusable helper to create monthly partitions on demand
--       (replaces copy-pasting CREATE TABLE … PARTITION OF).
--  #36  Document emails_default so operators understand when
--       and why rows end up there and how to remediate them.
--  #37  Reusable helper to detach (archive) a monthly partition
--       once it is past the retention window.
--
--  All statements are idempotent.
--  No CONCURRENTLY — assumes the migrator runs inside a transaction.
--  No existing partition or table structure is altered.
-- ============================================================


-- ============================================================
--  #35  create_email_partition_if_missing(year, month)
--
--  Creates the standard monthly partition emails_YYYY_MM as a
--  child of the emails partitioned table.  The call is a no-op
--  when the partition already exists.
--
--  Naming convention mirrors the existing partitions:
--      emails_2025_01 … emails_2027_12
--
--  Usage:
--      SELECT create_email_partition_if_missing(2029, 3);
-- ============================================================

CREATE OR REPLACE FUNCTION create_email_partition_if_missing(year INT, month INT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_partition_name TEXT;
    v_start_date     DATE;
    v_end_date       DATE;
BEGIN
    -- Validate inputs to produce a clear error instead of a cryptic date failure.
    IF year  IS NULL OR year  < 1 THEN
        RAISE EXCEPTION 'create_email_partition_if_missing: year must be a positive integer, got %', year;
    END IF;
    IF month IS NULL OR month NOT BETWEEN 1 AND 12 THEN
        RAISE EXCEPTION 'create_email_partition_if_missing: month must be between 1 and 12, got %', month;
    END IF;

    v_partition_name := format('emails_%s_%s',
                               lpad(year::TEXT,  4, '0'),
                               lpad(month::TEXT, 2, '0'));

    v_start_date := make_date(year, month, 1);
    v_end_date   := v_start_date + INTERVAL '1 month';

    -- Idempotency guard: skip if a child table with this name already exists
    -- under the emails parent in the current search-path schema.
    IF EXISTS (
        SELECT 1
        FROM   pg_class    c
        JOIN   pg_inherits i ON i.inhrelid  = c.oid
        JOIN   pg_class    p ON p.oid       = i.inhparent
        WHERE  p.relname        = 'emails'
          AND  c.relname        = v_partition_name
          AND  c.relnamespace   = (SELECT oid FROM pg_namespace
                                   WHERE  nspname = current_schema())
    ) THEN
        RAISE NOTICE 'Partition % already exists — skipping.', v_partition_name;
        RETURN;
    END IF;

    EXECUTE format(
        'CREATE TABLE %I PARTITION OF emails FOR VALUES FROM (%L) TO (%L)',
        v_partition_name, v_start_date, v_end_date
    );

    RAISE NOTICE 'Created partition % covering [%, %)',
                 v_partition_name, v_start_date, v_end_date;
END;
$$;

COMMENT ON FUNCTION create_email_partition_if_missing(INT, INT) IS
    'Creates the standard monthly partition emails_YYYY_MM as a child of the emails '
    'range-partitioned table if it does not already exist. '
    'The call is idempotent — invoking it for an existing partition emits a NOTICE and returns. '
    'Intended to be called ahead of each new calendar month, e.g. via a scheduled job '
    'that runs on the 1st of the preceding month: '
    'SELECT create_email_partition_if_missing(EXTRACT(YEAR FROM now())::INT, '
    '                                         EXTRACT(MONTH FROM now())::INT + 1);';


-- ============================================================
--  #35  Pre-create all 12 months of 2028
--
--  Extends the hardcoded coverage that ends at 2027-12 in 005.
-- ============================================================

SELECT create_email_partition_if_missing(2028,  1);
SELECT create_email_partition_if_missing(2028,  2);
SELECT create_email_partition_if_missing(2028,  3);
SELECT create_email_partition_if_missing(2028,  4);
SELECT create_email_partition_if_missing(2028,  5);
SELECT create_email_partition_if_missing(2028,  6);
SELECT create_email_partition_if_missing(2028,  7);
SELECT create_email_partition_if_missing(2028,  8);
SELECT create_email_partition_if_missing(2028,  9);
SELECT create_email_partition_if_missing(2028, 10);
SELECT create_email_partition_if_missing(2028, 11);
SELECT create_email_partition_if_missing(2028, 12);


-- ============================================================
--  #36  Document emails_default
--
--  emails_default is the DEFAULT partition of the emails table.
--  Rows whose fetched_at value does not match any named monthly
--  partition are routed here by Postgres automatically.
--
--  Detecting unexpected rows:
--      -- Count rows that bypassed all named partitions:
--      SELECT count(*) FROM ONLY emails_default;
--
--      -- Inspect which date ranges are present:
--      SELECT date_trunc('month', fetched_at) AS month,
--             count(*)
--      FROM   ONLY emails_default
--      GROUP  BY 1
--      ORDER  BY 1;
--
--  Remediation (move rows into the correct named partition):
--    1. Create the missing partition:
--           SELECT create_email_partition_if_missing(YYYY, MM);
--    2. Detach emails_default temporarily:
--           ALTER TABLE emails DETACH PARTITION emails_default;
--    3. Move the rows (outside any lock contention):
--           INSERT INTO emails SELECT * FROM ONLY emails_default
--               WHERE fetched_at >= 'YYYY-MM-01'
--                 AND fetched_at <  'YYYY-MM-01'::date + INTERVAL '1 month';
--           DELETE FROM emails_default
--               WHERE fetched_at >= 'YYYY-MM-01'
--                 AND fetched_at <  'YYYY-MM-01'::date + INTERVAL '1 month';
--    4. Re-attach emails_default:
--           ALTER TABLE emails ATTACH PARTITION emails_default DEFAULT;
--
--  NOTE: The detach/re-attach in step 2–4 requires an ACCESS EXCLUSIVE
--  lock on emails.  Schedule during a low-traffic window.
-- ============================================================

COMMENT ON TABLE emails_default IS
    'DEFAULT catch-all partition for the emails range-partitioned table. '
    'Rows land here when fetched_at does not fall within any named monthly '
    'partition (emails_YYYY_MM).  Under normal operation this table should '
    'remain empty; non-zero row counts indicate a missing partition. '
    ''
    'Detect unexpected rows: '
    '    SELECT count(*) FROM ONLY emails_default; '
    ''
    'Remediation: create the missing named partition with '
    'create_email_partition_if_missing(year, month), then detach '
    'emails_default, move the rows via INSERT … SELECT / DELETE, and '
    're-attach it as DEFAULT.  See migration 006_fix_partitioning.sql '
    'for the full step-by-step procedure.';


-- ============================================================
--  #37  archive_email_partition(year, month)
--
--  Detaches the named monthly partition from emails so that it
--  is no longer scanned by queries against the parent table.
--  The underlying table is NOT dropped — it remains available
--  for manual export (COPY … TO) or explicit DROP TABLE.
--
--  Suggested retention policy — 24 months:
--      Run archive_email_partition() for any partition whose
--      upper bound is older than (current_date - INTERVAL '24 months').
--      Keep the detached table for 30 days to allow a COPY export
--      before issuing DROP TABLE emails_YYYY_MM.
--      This gives a total on-disk window of ~25 months while keeping
--      the live partition tree lean (≤ 25 attached partitions).
--
--  Usage:
--      SELECT archive_email_partition(2025, 1);
-- ============================================================

CREATE OR REPLACE FUNCTION archive_email_partition(year INT, month INT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_partition_name TEXT;
BEGIN
    -- Validate inputs.
    IF year  IS NULL OR year  < 1 THEN
        RAISE EXCEPTION 'archive_email_partition: year must be a positive integer, got %', year;
    END IF;
    IF month IS NULL OR month NOT BETWEEN 1 AND 12 THEN
        RAISE EXCEPTION 'archive_email_partition: month must be between 1 and 12, got %', month;
    END IF;

    v_partition_name := format('emails_%s_%s',
                               lpad(year::TEXT,  4, '0'),
                               lpad(month::TEXT, 2, '0'));

    -- Idempotency guard: if the partition is not currently attached to emails,
    -- there is nothing to detach — emit a notice and return cleanly.
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_class    c
        JOIN   pg_inherits i ON i.inhrelid  = c.oid
        JOIN   pg_class    p ON p.oid       = i.inhparent
        WHERE  p.relname        = 'emails'
          AND  c.relname        = v_partition_name
          AND  c.relnamespace   = (SELECT oid FROM pg_namespace
                                   WHERE  nspname = current_schema())
    ) THEN
        RAISE NOTICE 'Partition % is not attached to emails — nothing to detach.', v_partition_name;
        RETURN;
    END IF;

    -- Detach without CONCURRENTLY so this can run inside a transaction.
    -- ACCESS EXCLUSIVE lock on emails is acquired for the duration.
    EXECUTE format('ALTER TABLE emails DETACH PARTITION %I', v_partition_name);

    RAISE NOTICE
        'Partition % has been detached from emails and is no longer scanned '
        'by queries on the parent table.  The table still exists — use '
        'COPY % TO ''/path/to/export.csv'' CSV HEADER  to export its data, '
        'or DROP TABLE % to remove it entirely.',
        v_partition_name, v_partition_name, v_partition_name;
END;
$$;

COMMENT ON FUNCTION archive_email_partition(INT, INT) IS
    'Detaches the named monthly partition (emails_YYYY_MM) from the emails '
    'parent table so it is excluded from all future query scans. '
    'The underlying table is preserved — it can be exported with COPY or '
    'dropped with DROP TABLE at the operator''s discretion. '
    'The call is idempotent: if the partition is already detached (or never '
    'existed) a NOTICE is raised and the function returns without error. '
    ''
    'Suggested 24-month retention policy: '
    'Archive any partition whose upper bound is older than '
    'current_date - INTERVAL ''24 months''.  Retain the detached table for '
    'at least 30 days to allow a COPY export before dropping it.  '
    'This keeps the live partition tree to ≤ 25 attached partitions while '
    'providing a ~25-month on-disk window.';
