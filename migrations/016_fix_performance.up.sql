-- ============================================================
--  016_fix_performance.sql
--
--  Addresses five performance and operational gaps:
--
--  #38/#39  Denormalize current_verdict_label onto emails to
--           replace the expensive MV lateral join over current_verdicts.
--           A trigger keeps the column in sync on every verdicts INSERT.
--           The trigger requires email_fetched_at (added in 014) to
--           correctly target the right partition via the composite PK.
--
--  #40      Add per-job timeout to enrichment_jobs and a reaper
--           function to fail stale in-progress jobs.
--
--  #41      Add locked_by to enrichment_jobs for worker-level
--           optimistic locking.
--
--  #42      Add priority to enrichment_jobs and replace the pending
--           partial index to respect priority ordering.
--
--  #43      Break the monolithic refresh_all_materialized_views()
--           into one function per MV to allow independent pg_cron
--           scheduling.
--
--  All statements idempotent.
--  No CONCURRENTLY on index creation.
--  REFRESH MATERIALIZED VIEW CONCURRENTLY is used only inside
--  PL/pgSQL function bodies (invoked at call time, not migration time).
--
--  Depends on: 014_fix_polymorphic_email_key.sql
--              (email_fetched_at column exists on verdicts)
-- ============================================================


-- ============================================================
--  #38/#39 — Denormalize current_verdict_label onto emails
--
--  Background:
--    The mv_campaign_summary and mv_org_ingestion_summary MVs use a
--    LATERAL subquery over verdicts ordered by created_at DESC to find
--    the current verdict for each email.  For a partitioned emails table
--    with millions of rows this lateral join is expensive.
--
--  Strategy:
--    Add current_verdict_label TEXT to the emails parent table.
--    A trigger (trg_sync_email_verdict_label) fires AFTER INSERT on
--    verdicts and updates the correct emails row via the composite
--    partition key (internal_id, fetched_at).
--
--    The trigger REQUIRES email_fetched_at to be set on the incoming
--    verdicts row (added in migration 014).  When it is NULL the
--    trigger emits a WARNING and skips the update so that the column
--    stays consistent even during the backfill window.
--
--  NOTE: Once all verdicts have email_fetched_at backfilled,
--  remove the IS NULL guard.  The current_verdicts view remains for
--  non-email entity types.
-- ============================================================


-- 1a. Add the denormalized column to the partitioned parent.
--     The column propagates to all existing and future partitions.
ALTER TABLE emails
    ADD COLUMN IF NOT EXISTS current_verdict_label TEXT;

COMMENT ON COLUMN emails.current_verdict_label IS
    'Denormalized copy of the most-recent verdicts.label for this email '
    '(entity_type = ''email'').  Kept in sync by trg_sync_email_verdict_label '
    'which fires AFTER INSERT on verdicts.  NULL means no verdict has been '
    'issued yet, OR that the verdict row was inserted without a valid '
    'email_fetched_at (pre-backfill period). '
    'Used in place of the expensive LATERAL join over current_verdicts in the '
    'dashboard materialized views. '
    'Once all verdicts have email_fetched_at backfilled, remove the IS NULL '
    'guard in sync_email_verdict_label(). The current_verdicts view remains '
    'for non-email entity types.';


-- 1b. Trigger function: sync current_verdict_label on every new verdict.
CREATE OR REPLACE FUNCTION sync_email_verdict_label()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- Only act on email-type verdicts.
    IF NEW.entity_type <> 'email' THEN
        RETURN NEW;
    END IF;

    -- Guard for the pre-backfill window: email_fetched_at may be NULL on
    -- older rows that have not yet been backfilled.  Without it we cannot
    -- target the correct partition via the composite PK and any UPDATE
    -- would be a full-table scan that could silently hit the wrong row.
    --
    -- Once all verdicts have email_fetched_at backfilled, remove this
    -- guard block.  The current_verdicts view remains for non-email
    -- entity types.
    IF NEW.email_fetched_at IS NULL THEN
        RAISE WARNING
            'sync_email_verdict_label: skipping emails update for verdict id=% '
            '(entity_id=%) because email_fetched_at IS NULL. '
            'Backfill email_fetched_at on verdicts to enable the denorm sync.',
            NEW.id, NEW.entity_id;
        RETURN NEW;
    END IF;

    -- Update the correct partition row via both halves of the composite PK.
    UPDATE emails
       SET current_verdict_label = NEW.label::TEXT
     WHERE internal_id = NEW.entity_id
       AND fetched_at  = NEW.email_fetched_at;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION sync_email_verdict_label() IS
    'Trigger function that keeps emails.current_verdict_label in sync with '
    'the most-recently inserted verdict for each email.  Fires AFTER INSERT '
    'on verdicts.  For entity_type = ''email'' only; other entity types are '
    'ignored.  Skips the update and emits a WARNING when email_fetched_at IS '
    'NULL so the column stays consistent during the backfill window.';


-- 1c. Create the trigger (DROP first for idempotency — PG15 has no
--     CREATE TRIGGER IF NOT EXISTS or OR REPLACE).
DROP TRIGGER IF EXISTS trg_sync_email_verdict_label ON verdicts;

CREATE TRIGGER trg_sync_email_verdict_label
    AFTER INSERT ON verdicts
    FOR EACH ROW
    EXECUTE FUNCTION sync_email_verdict_label();


-- ============================================================
--  #40 — Per-job timeout and stale-job reaper
--
--  enrichment_jobs.timeout_seconds defines how long a job may
--  remain in_progress before it is considered hung.  The reaper
--  function is intended to be called by pg_cron periodically.
-- ============================================================


-- 2a. Add the timeout column.
ALTER TABLE enrichment_jobs
    ADD COLUMN IF NOT EXISTS timeout_seconds INT NOT NULL DEFAULT 600;

COMMENT ON COLUMN enrichment_jobs.timeout_seconds IS
    'Maximum number of seconds a job may remain in_progress before '
    'reap_stale_enrichment_jobs() marks it failed and increments attempts. '
    'Defaults to 600 (10 minutes). Override per job-type at insert time. '
    'Intended to be called by pg_cron, e.g.: '
    '  SELECT cron.schedule(''reap-stale-jobs'', ''* * * * *'', '
    '    ''SELECT reap_stale_enrichment_jobs()'');';


-- 2b. Reaper function.
CREATE OR REPLACE FUNCTION reap_stale_enrichment_jobs()
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_reaped BIGINT;
BEGIN
    -- Mark any in-progress job as failed when it has been running
    -- longer than its own timeout_seconds threshold.
    -- Increments attempts so the retry logic in the worker eventually
    -- gives up once max_attempts is reached.
    UPDATE enrichment_jobs
       SET status     = 'failed',
           attempts   = attempts + 1,
           last_error = format(
               'reaped by reap_stale_enrichment_jobs() at %s: '
               'job exceeded timeout of %s seconds',
               NOW()::TEXT,
               timeout_seconds
           )
     WHERE status      = 'in_progress'
       AND started_at  < NOW() - timeout_seconds * INTERVAL '1 second';

    GET DIAGNOSTICS v_reaped = ROW_COUNT;
    RETURN v_reaped;
END;
$$;

COMMENT ON FUNCTION reap_stale_enrichment_jobs() IS
    'Marks stale in_progress enrichment_jobs as failed and increments their '
    'attempt counter.  A job is stale when started_at < NOW() - timeout_seconds. '
    'Returns the number of rows reaped. '
    'Intended to be scheduled via pg_cron, e.g. every minute: '
    '  SELECT cron.schedule(''reap-stale-jobs'', ''* * * * *'', '
    '    ''SELECT reap_stale_enrichment_jobs()'');';


-- ============================================================
--  #41 — Worker-identity column for optimistic locking
--
--  Workers claim a pending job with:
--    UPDATE enrichment_jobs
--       SET status    = ''in_progress'',
--           locked_by = <hostname:pid>,
--           started_at = NOW()
--     WHERE id = (
--         SELECT id FROM enrichment_jobs
--          WHERE status = ''pending''
--          ORDER BY priority DESC, created_at ASC
--          LIMIT 1
--          FOR UPDATE SKIP LOCKED
--     )
--    RETURNING id;
--  A zero-rows-affected result means another worker claimed it first.
-- ============================================================


-- 3a. Add the locked_by column.
ALTER TABLE enrichment_jobs
    ADD COLUMN IF NOT EXISTS locked_by TEXT;

COMMENT ON COLUMN enrichment_jobs.locked_by IS
    'Identifies the worker that currently holds this job, '
    'stored as "<hostname>:<pid>" (e.g. "worker-1:42731"). '
    'Set atomically alongside status = ''in_progress'' via: '
    '  UPDATE enrichment_jobs '
    '     SET status = ''in_progress'', locked_by = $worker, started_at = NOW() '
    '   WHERE id = ( '
    '       SELECT id FROM enrichment_jobs '
    '        WHERE status = ''pending'' '
    '        ORDER BY priority DESC, created_at ASC '
    '        LIMIT 1 FOR UPDATE SKIP LOCKED '
    '   ) '
    '  RETURNING id; '
    'NULL when the job is pending, completed, failed, or skipped.';


-- ============================================================
--  #42 — Job priority and updated pending index
--
--  priority 1 = lowest, 10 = highest.  Default 5 = normal.
--  The existing idx_jobs_pending covers (created_at) and gives
--  FIFO ordering.  Replace it with (priority DESC, created_at ASC)
--  so the worker poll query picks up high-priority jobs first
--  within the same partial-index WHERE clause.
-- ============================================================


-- 4a. Add the priority column.
ALTER TABLE enrichment_jobs
    ADD COLUMN IF NOT EXISTS priority SMALLINT NOT NULL DEFAULT 5
        CHECK (priority BETWEEN 1 AND 10);

COMMENT ON COLUMN enrichment_jobs.priority IS
    'Job dispatch priority: 1 = lowest, 10 = highest, 5 = normal (default). '
    'The worker poll query ORDER BY priority DESC, created_at ASC ensures '
    'higher-priority jobs are dispatched first within the pending queue.';


-- 4b. Drop the old pending index and create the priority-aware replacement.
--     No CONCURRENTLY — acceptable since this is a migration-time operation.
DROP INDEX IF EXISTS idx_jobs_pending;

CREATE INDEX IF NOT EXISTS idx_jobs_pending
    ON enrichment_jobs(priority DESC, created_at ASC)
    WHERE status IN ('pending', 'failed')
      AND attempts < max_attempts;

COMMENT ON INDEX idx_jobs_pending IS
    'Partial index for the worker poll query.  Covers only actionable rows '
    '(pending or retryable-failed, not yet exhausted).  Sorted by priority '
    'DESC then created_at ASC so high-priority jobs are returned first and, '
    'within the same priority level, older jobs are preferred (FIFO).';


-- ============================================================
--  #43 — Individual MV refresh functions
--
--  The monolithic refresh_all_materialized_views() calls all five
--  MVs in sequence.  A slow or blocked REFRESH on one MV delays all
--  subsequent refreshes.  Breaking them out into individual functions
--  allows each MV to be scheduled independently via pg_cron based on
--  its acceptable staleness tolerance (documented in 004).
--
--  Recommended pg_cron schedule (adjust to your load profile):
--    mv_threat_summary         — every 15 minutes
--    mv_campaign_summary       — every 5  minutes
--    mv_feed_health            — every 10 minutes
--    mv_rule_performance       — every 30 minutes
--    mv_org_ingestion_summary  — every 5  minutes
--
--  The monolithic function is rewritten to delegate to these
--  individual functions so existing callers continue to work.
-- ============================================================


-- 5a. Individual refresh wrappers.

CREATE OR REPLACE FUNCTION refresh_mv_threat_summary()
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_threat_summary;
END;
$$;

COMMENT ON FUNCTION refresh_mv_threat_summary() IS
    'Refreshes mv_threat_summary concurrently.  Acceptable staleness: 15 min. '
    'Schedule independently via pg_cron: '
    '  SELECT cron.schedule(''refresh-mv-threat-summary'', ''*/15 * * * *'', '
    '    ''SELECT refresh_mv_threat_summary()'');';


CREATE OR REPLACE FUNCTION refresh_mv_campaign_summary()
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_campaign_summary;
END;
$$;

COMMENT ON FUNCTION refresh_mv_campaign_summary() IS
    'Refreshes mv_campaign_summary concurrently.  Acceptable staleness: 5 min. '
    'Schedule independently via pg_cron: '
    '  SELECT cron.schedule(''refresh-mv-campaign-summary'', ''*/5 * * * *'', '
    '    ''SELECT refresh_mv_campaign_summary()'');';


CREATE OR REPLACE FUNCTION refresh_mv_feed_health()
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_feed_health;
END;
$$;

COMMENT ON FUNCTION refresh_mv_feed_health() IS
    'Refreshes mv_feed_health concurrently.  Acceptable staleness: 10 min. '
    'Schedule independently via pg_cron: '
    '  SELECT cron.schedule(''refresh-mv-feed-health'', ''*/10 * * * *'', '
    '    ''SELECT refresh_mv_feed_health()'');';


CREATE OR REPLACE FUNCTION refresh_mv_rule_performance()
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_rule_performance;
END;
$$;

COMMENT ON FUNCTION refresh_mv_rule_performance() IS
    'Refreshes mv_rule_performance concurrently.  Acceptable staleness: 30 min. '
    'Schedule independently via pg_cron: '
    '  SELECT cron.schedule(''refresh-mv-rule-performance'', ''*/30 * * * *'', '
    '    ''SELECT refresh_mv_rule_performance()'');';


CREATE OR REPLACE FUNCTION refresh_mv_org_ingestion_summary()
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_org_ingestion_summary;
END;
$$;

COMMENT ON FUNCTION refresh_mv_org_ingestion_summary() IS
    'Refreshes mv_org_ingestion_summary concurrently.  Acceptable staleness: 5 min. '
    'Schedule independently via pg_cron: '
    '  SELECT cron.schedule(''refresh-mv-org-ingestion-summary'', ''*/5 * * * *'', '
    '    ''SELECT refresh_mv_org_ingestion_summary()'');';


-- 5b. Replace the monolithic function body to delegate to the
--     individual wrappers above.  Existing callers are unaffected.
--
--     NOTE: Each MV has a different acceptable staleness tolerance.
--     Consider replacing this single-schedule call with independent
--     pg_cron jobs per MV (see COMMENT ON FUNCTION blocks above) so
--     that a slow REFRESH on one MV cannot delay the others.
CREATE OR REPLACE FUNCTION refresh_all_materialized_views()
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM refresh_mv_threat_summary();
    PERFORM refresh_mv_campaign_summary();
    PERFORM refresh_mv_feed_health();
    PERFORM refresh_mv_rule_performance();
    PERFORM refresh_mv_org_ingestion_summary();
END;
$$;

COMMENT ON FUNCTION refresh_all_materialized_views() IS
    'Refreshes all five materialized views by delegating to the individual '
    'refresh_mv_<name>() functions introduced in migration 016. '
    'Retained for backwards compatibility with existing pg_cron jobs and '
    'Go scheduler calls. '
    'RECOMMENDATION: replace this single monolithic schedule with independent '
    'pg_cron jobs per MV based on each view''s staleness tolerance: '
    '  mv_threat_summary        → every 15 min '
    '  mv_campaign_summary      → every 5  min '
    '  mv_feed_health           → every 10 min '
    '  mv_rule_performance      → every 30 min '
    '  mv_org_ingestion_summary → every 5  min '
    'This prevents a slow or blocked REFRESH on one MV from delaying the rest.';
