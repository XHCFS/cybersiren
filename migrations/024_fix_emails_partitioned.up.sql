-- ============================================================
--  024_fix_emails_partitioned.sql
--
--  Adds two columns to the partitioned emails table that were
--  deferred in 008_add_missing_schema.sql due to partitioning
--  complexity.  PG13+ supports both ALTER TABLE ADD COLUMN and
--  row-level BEFORE triggers on partitioned parents, which
--  automatically propagate to all existing and future partitions.
--
--  Changes:
--    #47  emails.updated_at — TIMESTAMPTZ + BEFORE UPDATE trigger
--    #50  emails.sent_at    — TIMESTAMPTZ + BEFORE INSERT trigger
--                              (computed from sent_timestamp)
--
--  Depends on: 001_initial_schema.sql (set_updated_at function)
--  All statements idempotent.  No CONCURRENTLY.
-- ============================================================


-- ============================================================
--  #47  emails.updated_at
--
--  Mutable columns (risk_score, all sub-scores, campaign_id,
--  org_id, current_verdict_label, deleted_at) can change after
--  initial insert.  Without updated_at there is no record of
--  when the last modification occurred.
--
--  The set_updated_at() trigger function already exists (001).
--  Creating the trigger on the partitioned parent automatically
--  installs it on every child partition (PG13+).
-- ============================================================

ALTER TABLE emails
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

COMMENT ON COLUMN emails.updated_at IS
    'Timestamp of the last modification to this row.  '
    'Maintained by trg_emails_updated_at (BEFORE UPDATE) which calls '
    'set_updated_at() — the same function used by enriched_threats, '
    'campaigns, organisations, users, and feeds.  '
    'Added in migration 024 (deferred from 008 due to partitioning).';

-- CREATE OR REPLACE TRIGGER is PG14+.
-- drop + create for PG13 compat (though the project targets PG15+).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_trigger
        WHERE  tgname  = 'trg_emails_updated_at'
          AND  tgrelid = 'emails'::regclass
    ) THEN
        CREATE TRIGGER trg_emails_updated_at
            BEFORE UPDATE ON emails
            FOR EACH ROW EXECUTE FUNCTION set_updated_at();
    END IF;
END;
$$;


-- ============================================================
--  #50  emails.sent_at
--
--  sent_timestamp BIGINT stores the raw Unix epoch from email
--  headers.  Every date-range query must wrap it in
--  to_timestamp(), which is cumbersome and defeats index usage.
--
--  sent_at is a computed TIMESTAMPTZ column maintained by a
--  BEFORE INSERT OR UPDATE trigger.  A GENERATED ALWAYS column
--  would be cleaner, but to_timestamp(double precision) is
--  marked STABLE (not IMMUTABLE) in some PG builds, and
--  GENERATED expressions require IMMUTABLE.  A trigger avoids
--  the volatility concern entirely.
--
--  Index: a standard B-tree on sent_at enables date-range
--  queries without wrapping sent_timestamp.
-- ============================================================

ALTER TABLE emails
    ADD COLUMN IF NOT EXISTS sent_at TIMESTAMPTZ;

COMMENT ON COLUMN emails.sent_at IS
    'Computed TIMESTAMPTZ derived from sent_timestamp via '
    'to_timestamp(sent_timestamp).  Maintained by '
    'trg_emails_sent_at (BEFORE INSERT OR UPDATE OF sent_timestamp).  '
    'NULL when sent_timestamp IS NULL.  '
    'Use this column for date-range queries instead of wrapping '
    'sent_timestamp in to_timestamp() at query time.  '
    'Added in migration 024 (deferred from 008 due to partitioning).';


-- Trigger function: compute sent_at from sent_timestamp.
CREATE OR REPLACE FUNCTION fn_set_email_sent_at()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.sent_timestamp IS NOT NULL THEN
        NEW.sent_at := to_timestamp(NEW.sent_timestamp::double precision);
    ELSE
        NEW.sent_at := NULL;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION fn_set_email_sent_at() IS
    'BEFORE INSERT / UPDATE trigger function that computes '
    'emails.sent_at from emails.sent_timestamp via to_timestamp().  '
    'Sets sent_at to NULL when sent_timestamp IS NULL.';

-- Install on the partitioned parent — propagates to all partitions.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_trigger
        WHERE  tgname  = 'trg_emails_sent_at'
          AND  tgrelid = 'emails'::regclass
    ) THEN
        CREATE TRIGGER trg_emails_sent_at
            BEFORE INSERT OR UPDATE OF sent_timestamp ON emails
            FOR EACH ROW EXECUTE FUNCTION fn_set_email_sent_at();
    END IF;
END;
$$;


-- Index for date-range queries on sent_at.
CREATE INDEX IF NOT EXISTS idx_emails_sent_at
    ON emails(sent_at);

COMMENT ON INDEX idx_emails_sent_at IS
    'B-tree index on the computed sent_at column.  '
    'Enables efficient date-range queries without wrapping '
    'sent_timestamp in to_timestamp() at query time.';


-- ============================================================
--  BACKFILL NOTE
--
--  Existing rows have updated_at = DEFAULT (CURRENT_TIMESTAMP
--  at migration time) and sent_at = NULL.  A one-time backfill
--  is recommended but must be run as a separate data migration
--  to avoid long-running locks on the partitioned table:
--
--    -- Backfill sent_at from sent_timestamp (batch by partition):
--    UPDATE emails
--       SET sent_at = to_timestamp(sent_timestamp::double precision)
--     WHERE sent_timestamp IS NOT NULL
--       AND sent_at IS NULL;
--
--    -- Reset updated_at to created-at proxy (fetched_at):
--    UPDATE emails
--       SET updated_at = fetched_at
--     WHERE updated_at > fetched_at + INTERVAL '1 second';
-- ============================================================
