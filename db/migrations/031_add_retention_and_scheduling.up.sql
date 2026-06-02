-- =============================================================================
-- 031_add_retention_and_scheduling.up.sql
--   #159 Privacy & retention sweep — soft-delete past each org's retention
--        window, purge bodies of deleted rows, drop stale enrichment_results.
--   #160 pg_cron schedule for the retention sweep + materialized-view refresh.
--
-- The sweep / refresh logic lives in SQL functions that are ALWAYS created, so
-- they can be invoked by any scheduler (or manually). pg_cron scheduling is
-- best-effort: wrapped in an exception block so this migration still applies on
-- a Postgres without the pg_cron extension (e.g. CI / local dev).
-- =============================================================================

-- ── Retention sweep ─────────────────────────────────────────────────────────
-- One callable that performs all three lifecycle actions and returns a summary.
CREATE OR REPLACE FUNCTION cs_run_retention_sweep()
RETURNS TABLE(soft_deleted BIGINT, bodies_purged BIGINT, enrichment_pruned BIGINT)
LANGUAGE plpgsql AS $$
DECLARE
    v_soft_deleted BIGINT;
    v_bodies       BIGINT;
    v_enrichment   BIGINT;
BEGIN
    -- 1. Soft-delete emails older than their owning org's retention window.
    UPDATE emails e
       SET deleted_at = NOW()
      FROM organisations o
     WHERE e.org_id = o.id
       AND e.deleted_at IS NULL
       AND e.fetched_at < NOW() - make_interval(days => COALESCE(o.retention_days, 30));
    GET DIAGNOSTICS v_soft_deleted = ROW_COUNT;

    -- 2. Privacy: drop raw content from soft-deleted emails (keep metadata for
    --    audit/aggregates). Idempotent — only touches rows still holding bodies.
    UPDATE emails
       SET body_plain = NULL, body_html = NULL, headers_json = NULL
     WHERE deleted_at IS NOT NULL
       AND (body_plain IS NOT NULL OR body_html IS NOT NULL OR headers_json IS NOT NULL);
    GET DIAGNOSTICS v_bodies = ROW_COUNT;

    -- 3. Drop expired enrichment results so they re-fetch on next observation.
    DELETE FROM enrichment_results
     WHERE expires_at IS NOT NULL AND expires_at < NOW();
    GET DIAGNOSTICS v_enrichment = ROW_COUNT;

    RETURN QUERY SELECT v_soft_deleted, v_bodies, v_enrichment;
END;
$$;

COMMENT ON FUNCTION cs_run_retention_sweep() IS
    'Privacy/retention sweep (#159): soft-delete past org.retention_days, purge bodies of deleted rows, prune expired enrichment_results.';

-- ── Materialized-view refresh ───────────────────────────────────────────────
-- Plain (non-concurrent) REFRESH so it can run inside this function; acceptable
-- for a background schedule. SVC-11 also refreshes in-app — this is belt-and-braces.
CREATE OR REPLACE FUNCTION cs_refresh_materialized_views()
RETURNS VOID
LANGUAGE plpgsql AS $$
BEGIN
    REFRESH MATERIALIZED VIEW mv_org_ingestion_summary;
    REFRESH MATERIALIZED VIEW mv_threat_summary;
    REFRESH MATERIALIZED VIEW mv_campaign_summary;
    REFRESH MATERIALIZED VIEW mv_feed_health;
    REFRESH MATERIALIZED VIEW mv_rule_performance;
END;
$$;

COMMENT ON FUNCTION cs_refresh_materialized_views() IS
    'Refreshes all dashboard materialized views (#160). Scheduled via pg_cron when available.';

-- ── Best-effort scheduling via pg_cron ──────────────────────────────────────
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS pg_cron;
    -- cron.schedule(job_name, schedule, command) — upsert by name on pg_cron >= 1.4.
    PERFORM cron.schedule('cybersiren-retention-sweep', '0 * * * *', 'SELECT cs_run_retention_sweep()');
    PERFORM cron.schedule('cybersiren-mv-refresh', '*/15 * * * *', 'SELECT cs_refresh_materialized_views()');
    RAISE NOTICE 'pg_cron schedules installed: retention sweep (hourly), MV refresh (every 15m).';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pg_cron unavailable (%): functions created but not scheduled. Invoke cs_run_retention_sweep() / cs_refresh_materialized_views() from your scheduler.', SQLERRM;
END;
$$;
