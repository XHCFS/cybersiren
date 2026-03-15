-- ============================================================
--  004_add_materialized_view.sql
--  Materialized views for dashboard and ops queries.
--  Refresh strategy noted per view — wire these into your
--  Go scheduler or pg_cron based on acceptable staleness.
-- ============================================================


-- ============================================================
--  THREAT SUMMARY
--
--  Aggregate threat intel stats grouped by type, country,
--  and ASN. Drives the global threat landscape dashboard.
--  Acceptable staleness: 15 minutes.
--
--  COALESCE sentinels on nullable group-by columns are required
--  for REFRESH CONCURRENTLY — NULL = NULL is false in Postgres,
--  so uncoalesced NULLs cause unique-violation errors on refresh.
-- ============================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_threat_summary AS
SELECT
    COALESCE(threat_type, '')  AS threat_type,
    COALESCE(country, '')      AS country,
    COALESCE(asn, -1)          AS asn,
    COALESCE(asn_name, '')     AS asn_name,
    COUNT(*)                                            AS total,
    COUNT(*) FILTER (WHERE online = TRUE)               AS online_count,
    COUNT(*) FILTER (WHERE online = FALSE)              AS offline_count,
    AVG(risk_score)                                     AS avg_risk_score,
    MAX(risk_score)                                     AS max_risk_score,
    MIN(first_seen)                                     AS earliest_seen,
    MAX(last_seen)                                      AS latest_seen
FROM enriched_threats
WHERE deleted_at IS NULL
GROUP BY COALESCE(threat_type, ''), COALESCE(country, ''), COALESCE(asn, -1), COALESCE(asn_name, '')
WITH DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_threat_summary
    ON mv_threat_summary(threat_type, country, asn, asn_name);


-- ============================================================
--  CAMPAIGN SUMMARY
--
--  Per-campaign rollup: member counts, verdict distribution,
--  latest activity. Drives campaign list and detail views.
--  Acceptable staleness: 5 minutes.
-- ============================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_campaign_summary AS
SELECT
    c.id                                                AS campaign_id,
    c.org_id,
    c.name,
    c.fingerprint,
    c.threat_type,
    c.target_brand,
    c.risk_score,
    c.first_seen,
    c.last_seen,

    COUNT(DISTINCT e.internal_id)                       AS email_count,
    AVG(e.risk_score)                                   AS avg_email_risk_score,

    -- Verdict breakdown across all member emails
    COUNT(v.id) FILTER (WHERE v.label = 'phishing')     AS verdict_phishing,
    COUNT(v.id) FILTER (WHERE v.label = 'malware')      AS verdict_malware,
    COUNT(v.id) FILTER (WHERE v.label = 'suspicious')   AS verdict_suspicious,
    COUNT(v.id) FILTER (WHERE v.label = 'benign')       AS verdict_benign,
    COUNT(v.id) FILTER (WHERE v.label = 'spam')         AS verdict_spam,
    COUNT(v.id) FILTER (WHERE v.label = 'unknown')      AS verdict_unknown

FROM campaigns c
LEFT JOIN emails e
    ON e.campaign_id = c.id
    AND e.deleted_at IS NULL
LEFT JOIN LATERAL (
    -- Current verdict only for each email
    SELECT label, id
    FROM verdicts
    WHERE entity_type = 'email'
      AND entity_id = e.internal_id
    ORDER BY created_at DESC
    LIMIT 1
) v ON TRUE
WHERE c.deleted_at IS NULL
GROUP BY c.id, c.org_id, c.name, c.fingerprint,
         c.threat_type, c.target_brand, c.risk_score,
         c.first_seen, c.last_seen
WITH DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_campaign_summary_id
    ON mv_campaign_summary(campaign_id);
CREATE INDEX IF NOT EXISTS idx_mv_campaign_summary_org
    ON mv_campaign_summary(org_id);


-- ============================================================
--  FEED HEALTH
--
--  Per-feed stats: contribution volume, freshness, staleness.
--  Drives ops/admin feed monitoring dashboard.
--  Acceptable staleness: 10 minutes.
-- ============================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_feed_health AS
SELECT
    f.id                                                AS feed_id,
    f.name,
    f.display_name,
    f.feed_type,
    f.reliability_weight,
    f.enabled,
    f.last_fetched_at,

    -- How long since last successful fetch
    EXTRACT(EPOCH FROM (NOW() - f.last_fetched_at))     AS seconds_since_fetch,

    COUNT(et.id)                                        AS total_threats_contributed,
    COUNT(et.id) FILTER (WHERE et.online = TRUE)        AS active_threats,
    AVG(et.risk_score)                                  AS avg_threat_risk_score,
    MAX(et.last_seen)                                   AS most_recent_threat

FROM feeds f
LEFT JOIN enriched_threats et
    ON et.feed_id = f.id
    AND et.deleted_at IS NULL
GROUP BY f.id, f.name, f.display_name, f.feed_type,
         f.reliability_weight, f.enabled, f.last_fetched_at
WITH DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_feed_health_id
    ON mv_feed_health(feed_id);


-- ============================================================
--  RULE PERFORMANCE
--
--  Per-rule firing frequency and score contribution totals.
--  Helps analysts tune rules — find noisy low-signal rules
--  and high-value rules worth promoting.
--  Acceptable staleness: 30 minutes.
-- ============================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_rule_performance AS
SELECT
    r.id                                                AS rule_id,
    r.org_id,
    r.name,
    r.version,
    r.status,
    r.target,
    r.score_impact,

    COUNT(rh.id)                                        AS total_hits,
    COUNT(rh.id) FILTER (
        WHERE rh.fired_at >= NOW() - INTERVAL '24 hours'
    )                                                   AS hits_last_24h,
    COUNT(rh.id) FILTER (
        WHERE rh.fired_at >= NOW() - INTERVAL '7 days'
    )                                                   AS hits_last_7d,

    SUM(rh.score_impact)                                AS total_score_contributed,
    MAX(rh.fired_at)                                    AS last_fired_at

FROM rules r
LEFT JOIN rule_hits rh ON rh.rule_id = r.id
GROUP BY r.id, r.org_id, r.name, r.version,
         r.status, r.target, r.score_impact
WITH DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_rule_performance_id
    ON mv_rule_performance(rule_id);
CREATE INDEX IF NOT EXISTS idx_mv_rule_performance_org
    ON mv_rule_performance(org_id);


-- ============================================================
--  ORG INGESTION SUMMARY
--
--  Per-org email volume and risk breakdown over time windows.
--  Drives every customer's home screen / overview panel.
--  Acceptable staleness: 5 minutes.
-- ============================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_org_ingestion_summary AS
SELECT
    e.org_id,

    COUNT(*)                                            AS total_emails,

    COUNT(*) FILTER (
        WHERE e.fetched_at >= NOW() - INTERVAL '24 hours'
    )                                                   AS emails_last_24h,
    COUNT(*) FILTER (
        WHERE e.fetched_at >= NOW() - INTERVAL '7 days'
    )                                                   AS emails_last_7d,
    COUNT(*) FILTER (
        WHERE e.fetched_at >= NOW() - INTERVAL '30 days'
    )                                                   AS emails_last_30d,

    AVG(e.risk_score)                                   AS avg_risk_score,
    MAX(e.risk_score)                                   AS max_risk_score,

    -- High risk = score >= 70
    COUNT(*) FILTER (WHERE e.risk_score >= 70)          AS high_risk_count,
    COUNT(*) FILTER (WHERE e.risk_score BETWEEN 40 AND 69) AS medium_risk_count,
    COUNT(*) FILTER (WHERE e.risk_score < 40)           AS low_risk_count,

    -- Verdict breakdown (current verdict per email via lateral)
    COUNT(v.label) FILTER (WHERE v.label = 'phishing')  AS confirmed_phishing,
    COUNT(v.label) FILTER (WHERE v.label = 'malware')   AS confirmed_malware,
    COUNT(v.label) FILTER (WHERE v.label = 'spam')      AS confirmed_spam,
    COUNT(v.label) FILTER (WHERE v.label = 'benign')    AS confirmed_benign,
    COUNT(v.label) FILTER (WHERE v.label IS NULL)       AS unclassified

FROM emails e
LEFT JOIN LATERAL (
    SELECT label
    FROM verdicts
    WHERE entity_type = 'email'
      AND entity_id = e.internal_id
    ORDER BY created_at DESC
    LIMIT 1
) v ON TRUE
WHERE e.deleted_at IS NULL
GROUP BY e.org_id
WITH DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_org_ingestion_org_id
    ON mv_org_ingestion_summary(org_id);


-- ============================================================
--  REFRESH HELPER FUNCTION
--
--  Call this from your Go scheduler or pg_cron.
--  Refreshes all views concurrently so reads are never blocked.
--
--  Example pg_cron job (every 5 minutes):
--    SELECT cron.schedule('refresh-mvs', '*/5 * * * *',
--      'SELECT refresh_all_materialized_views()');
-- ============================================================

CREATE OR REPLACE FUNCTION refresh_all_materialized_views()
RETURNS VOID AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_threat_summary;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_campaign_summary;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_feed_health;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_rule_performance;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_org_ingestion_summary;
END;
$$ LANGUAGE plpgsql;
