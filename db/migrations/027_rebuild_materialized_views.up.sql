-- ============================================================
--  027_rebuild_materialized_views.sql
--
--  Rebuilds materialized views dropped by 022_fix_data_types.sql
--  while reusing refresh helper functions defined in 016.
-- ============================================================

DROP MATERIALIZED VIEW IF EXISTS mv_threat_summary;
DROP MATERIALIZED VIEW IF EXISTS mv_campaign_summary;
DROP MATERIALIZED VIEW IF EXISTS mv_feed_health;
DROP MATERIALIZED VIEW IF EXISTS mv_rule_performance;
DROP MATERIALIZED VIEW IF EXISTS mv_org_ingestion_summary;

CREATE MATERIALIZED VIEW mv_threat_summary AS
SELECT
    COALESCE(threat_type, '')  AS threat_type,
    COALESCE(country, '')      AS country,
    COALESCE(asn, -1)          AS asn,
    COALESCE(asn_name, '')     AS asn_name,
    is_global,
    COALESCE(org_id, -1)       AS org_id,
    COUNT(*)                                            AS total,
    COUNT(*) FILTER (WHERE online = TRUE)               AS online_count,
    COUNT(*) FILTER (WHERE online = FALSE)              AS offline_count,
    AVG(risk_score)                                     AS avg_risk_score,
    MAX(risk_score)                                     AS max_risk_score,
    MIN(first_seen)                                     AS earliest_seen,
    MAX(last_seen)                                      AS latest_seen
FROM enriched_threats
WHERE deleted_at IS NULL
GROUP BY
    COALESCE(threat_type, ''),
    COALESCE(country, ''),
    COALESCE(asn, -1),
    COALESCE(asn_name, ''),
    is_global,
    COALESCE(org_id, -1)
WITH DATA;

CREATE UNIQUE INDEX idx_mv_threat_summary
    ON mv_threat_summary(threat_type, country, asn, asn_name, is_global, org_id);

CREATE INDEX idx_mv_threat_summary_org
    ON mv_threat_summary(is_global, org_id);

CREATE MATERIALIZED VIEW mv_campaign_summary AS
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
    COUNT(e.internal_id) FILTER (WHERE e.current_verdict_label = 'phishing')    AS verdict_phishing,
    COUNT(e.internal_id) FILTER (WHERE e.current_verdict_label = 'malware')     AS verdict_malware,
    COUNT(e.internal_id) FILTER (WHERE e.current_verdict_label = 'suspicious')  AS verdict_suspicious,
    COUNT(e.internal_id) FILTER (WHERE e.current_verdict_label = 'benign')      AS verdict_benign,
    COUNT(e.internal_id) FILTER (WHERE e.current_verdict_label = 'spam')        AS verdict_spam,
    COUNT(e.internal_id) FILTER (WHERE e.current_verdict_label = 'unknown')     AS verdict_unknown
FROM campaigns c
LEFT JOIN emails e
    ON  e.campaign_id = c.id
    AND e.org_id      = c.org_id
    AND e.deleted_at IS NULL
WHERE c.deleted_at IS NULL
GROUP BY c.id, c.org_id, c.name, c.fingerprint,
         c.threat_type, c.target_brand, c.risk_score,
         c.first_seen, c.last_seen
WITH DATA;

CREATE UNIQUE INDEX idx_mv_campaign_summary_id
    ON mv_campaign_summary(campaign_id);

CREATE INDEX idx_mv_campaign_summary_org
    ON mv_campaign_summary(org_id);

CREATE MATERIALIZED VIEW mv_feed_health AS
SELECT
    f.id                                                AS feed_id,
    f.name,
    f.display_name,
    f.feed_type,
    f.reliability_weight,
    f.enabled,
    f.last_fetched_at,
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

CREATE UNIQUE INDEX idx_mv_feed_health_id
    ON mv_feed_health(feed_id);

CREATE MATERIALIZED VIEW mv_rule_performance AS
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

CREATE UNIQUE INDEX idx_mv_rule_performance_id
    ON mv_rule_performance(rule_id);

CREATE INDEX idx_mv_rule_performance_org
    ON mv_rule_performance(org_id);

CREATE MATERIALIZED VIEW mv_org_ingestion_summary AS
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
    COUNT(*) FILTER (WHERE e.risk_score >= 70)          AS high_risk_count,
    COUNT(*) FILTER (WHERE e.risk_score BETWEEN 40 AND 69) AS medium_risk_count,
    COUNT(*) FILTER (WHERE e.risk_score < 40)           AS low_risk_count,
    COUNT(*) FILTER (WHERE e.current_verdict_label = 'phishing')  AS confirmed_phishing,
    COUNT(*) FILTER (WHERE e.current_verdict_label = 'malware')   AS confirmed_malware,
    COUNT(*) FILTER (WHERE e.current_verdict_label = 'spam')      AS confirmed_spam,
    COUNT(*) FILTER (WHERE e.current_verdict_label = 'benign')    AS confirmed_benign,
    COUNT(*) FILTER (WHERE e.current_verdict_label IS NULL)        AS unclassified
FROM emails e
WHERE e.deleted_at IS NULL
  AND e.org_id IS NOT NULL
GROUP BY e.org_id
WITH DATA;

CREATE UNIQUE INDEX idx_mv_org_ingestion_org_id
    ON mv_org_ingestion_summary(org_id);

-- Refresh helper functions are intentionally reused from 016_fix_performance.sql:
--   refresh_mv_threat_summary()
--   refresh_mv_campaign_summary()
--   refresh_mv_feed_health()
--   refresh_mv_rule_performance()
--   refresh_mv_org_ingestion_summary()
--   refresh_all_materialized_views()
