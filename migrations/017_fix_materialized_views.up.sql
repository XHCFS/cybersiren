-- ============================================================
--  017_fix_materialized_views.sql
--
--  Fixes three materialized-view correctness bugs introduced as
--  the schema grew after 004_add_materialized_view.sql:
--
--  #62  mv_threat_summary — does not group by is_global / org_id,
--       so it produces a single global aggregate across all tenants
--       regardless of who owns the threat record.
--
--  #63  mv_campaign_summary — joins emails on campaign_id only,
--       allowing cross-tenant email counts when a campaign_id is
--       reused across orgs or org_id is NULL.  Also replaces the
--       expensive LATERAL subquery with the denormalised
--       emails.current_verdict_label column added in 016.
--
--  #64  mv_org_ingestion_summary — groups by e.org_id which is
--       nullable, producing a misleading NULL-keyed summary row for
--       all pre-backfill emails.  Excludes those rows with
--       AND e.org_id IS NOT NULL.  Also removes the LATERAL subquery
--       in favour of emails.current_verdict_label (016).
--
--  All DROPs use IF EXISTS.
--  Indexes are created without CONCURRENTLY (migration transaction).
--  All MVs are populated immediately (WITH DATA).
--
--  Depends on:
--    013_fix_multitenancy.sql   — org_id on child tables
--    016_fix_performance.sql    — emails.current_verdict_label
-- ============================================================


-- ============================================================
--  #62 — mv_threat_summary: add is_global / org_id dimensions
--
--  The original MV (004) grouped only by threat_type, country, asn,
--  asn_name.  Migration 005 added is_global to enriched_threats but
--  the MV was never updated, so global TI and per-org TI are mixed
--  into the same aggregate rows.
--
--  Fix: add is_global and COALESCE(org_id, -1) to the GROUP BY.
--  COALESCE sentinel (-1) is required for REFRESH CONCURRENTLY —
--  NULL = NULL is false in Postgres, which causes unique-violation
--  errors on refresh when org_id is NULL.
--
--  Query guidance (add to application query):
--    global threats : WHERE is_global = TRUE
--    org-specific   : WHERE is_global = FALSE AND org_id = $1
-- ============================================================

DROP MATERIALIZED VIEW IF EXISTS mv_threat_summary;

CREATE MATERIALIZED VIEW mv_threat_summary AS
SELECT
    -- Existing dimensions
    COALESCE(threat_type, '')  AS threat_type,
    COALESCE(country, '')      AS country,
    COALESCE(asn, -1)          AS asn,
    COALESCE(asn_name, '')     AS asn_name,

    -- New tenant-aware dimensions (fixes #62)
    is_global,
    COALESCE(org_id, -1)       AS org_id,   -- -1 sentinel for REFRESH CONCURRENTLY

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

COMMENT ON MATERIALIZED VIEW mv_threat_summary IS
    'Per-type/country/ASN aggregate of enriched_threats, broken down by '
    'is_global and org_id.  '
    'Query guidance: '
    '  global threats  — WHERE is_global = TRUE; '
    '  org-specific    — WHERE is_global = FALSE AND org_id = $1. '
    'org_id = -1 means the original row had org_id IS NULL (pre-backfill). '
    'Refresh: every 15 minutes via refresh_mv_threat_summary().';

-- Unique index required for REFRESH CONCURRENTLY.
-- All columns are already COALESCE-safe in the MV projection;
-- is_global is NOT NULL (added in 005 with NOT NULL DEFAULT FALSE).
CREATE UNIQUE INDEX idx_mv_threat_summary
    ON mv_threat_summary(threat_type, country, asn, asn_name, is_global, org_id);

-- Lookup index for per-org dashboard queries.
CREATE INDEX idx_mv_threat_summary_org
    ON mv_threat_summary(is_global, org_id);


-- ============================================================
--  #63 — mv_campaign_summary: enforce org_id on email join and
--         replace LATERAL subquery with current_verdict_label
--
--  The original JOIN was:
--    LEFT JOIN emails e ON e.campaign_id = c.id AND e.deleted_at IS NULL
--  which allows emails belonging to a different org (or org_id IS NULL)
--  to be counted under campaign c when two orgs happen to share the
--  same campaign_id (e.g. a reused hash fingerprint).
--
--  Fix: add AND e.org_id = c.org_id to the JOIN condition.
--
--  The LATERAL subquery over verdicts (ORDER BY created_at DESC LIMIT 1)
--  was the most expensive part of this MV.  Migration 016 added
--  emails.current_verdict_label which is kept in sync by a trigger.
--  Replace the LATERAL with a direct column reference.
-- ============================================================

DROP MATERIALIZED VIEW IF EXISTS mv_campaign_summary;

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

    -- Verdict breakdown using the denormalised column from 016.
    -- Avoids the expensive LATERAL join over verdicts.
    COUNT(e.internal_id) FILTER (WHERE e.current_verdict_label = 'phishing')    AS verdict_phishing,
    COUNT(e.internal_id) FILTER (WHERE e.current_verdict_label = 'malware')     AS verdict_malware,
    COUNT(e.internal_id) FILTER (WHERE e.current_verdict_label = 'suspicious')  AS verdict_suspicious,
    COUNT(e.internal_id) FILTER (WHERE e.current_verdict_label = 'benign')      AS verdict_benign,
    COUNT(e.internal_id) FILTER (WHERE e.current_verdict_label = 'spam')        AS verdict_spam,
    COUNT(e.internal_id) FILTER (WHERE e.current_verdict_label = 'unknown')     AS verdict_unknown

FROM campaigns c
LEFT JOIN emails e
    ON  e.campaign_id = c.id
    -- Enforce tenant boundary: only count emails belonging to the same org.
    -- Also prevents cross-tenant leakage when campaign_id is reused (#63).
    AND e.org_id      = c.org_id
    AND e.deleted_at IS NULL
WHERE c.deleted_at IS NULL
GROUP BY c.id, c.org_id, c.name, c.fingerprint,
         c.threat_type, c.target_brand, c.risk_score,
         c.first_seen, c.last_seen
WITH DATA;

COMMENT ON MATERIALIZED VIEW mv_campaign_summary IS
    'Per-campaign email volume and verdict distribution.  '
    'The emails JOIN now includes AND e.org_id = c.org_id to prevent '
    'cross-tenant email counts.  Verdict breakdown uses '
    'emails.current_verdict_label (denormalised in 016) instead of the '
    'expensive LATERAL subquery over verdicts.  '
    'Refresh: every 5 minutes via refresh_mv_campaign_summary().';

-- Unique index required for REFRESH CONCURRENTLY.
CREATE UNIQUE INDEX idx_mv_campaign_summary_id
    ON mv_campaign_summary(campaign_id);

-- Lookup index for per-org campaign list queries.
CREATE INDEX idx_mv_campaign_summary_org
    ON mv_campaign_summary(org_id);


-- ============================================================
--  #64 — mv_org_ingestion_summary: exclude pre-backfill rows and
--         replace LATERAL subquery with current_verdict_label
--
--  The original MV grouped by e.org_id with no NULL guard.  Any email
--  ingested before the org_id backfill landed in a NULL-keyed row that
--  does not correspond to any real organisation and makes per-org counts
--  incorrect.
--
--  Fix: add AND e.org_id IS NOT NULL to the WHERE clause.
--  Note: this filter becomes a no-op after org_id is enforced
--  NOT NULL on the emails table.
--
--  The LATERAL subquery over verdicts is replaced by the denormalised
--  emails.current_verdict_label column (added in 016) for the same
--  performance reason as mv_campaign_summary (#63).
-- ============================================================

DROP MATERIALIZED VIEW IF EXISTS mv_org_ingestion_summary;

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

    -- High risk = score >= 70
    COUNT(*) FILTER (WHERE e.risk_score >= 70)          AS high_risk_count,
    COUNT(*) FILTER (WHERE e.risk_score BETWEEN 40 AND 69) AS medium_risk_count,
    COUNT(*) FILTER (WHERE e.risk_score < 40)           AS low_risk_count,

    -- Verdict breakdown using the denormalised column from 016.
    -- Replaces the expensive LATERAL join over verdicts.
    COUNT(*) FILTER (WHERE e.current_verdict_label = 'phishing')  AS confirmed_phishing,
    COUNT(*) FILTER (WHERE e.current_verdict_label = 'malware')   AS confirmed_malware,
    COUNT(*) FILTER (WHERE e.current_verdict_label = 'spam')      AS confirmed_spam,
    COUNT(*) FILTER (WHERE e.current_verdict_label = 'benign')    AS confirmed_benign,
    COUNT(*) FILTER (WHERE e.current_verdict_label IS NULL)        AS unclassified

FROM emails e
WHERE e.deleted_at IS NULL
  -- Exclude pre-backfill emails whose org_id has not yet been set (#64).
  -- This filter becomes a no-op after org_id is enforced NOT NULL on emails.
  AND e.org_id IS NOT NULL
GROUP BY e.org_id
WITH DATA;

COMMENT ON MATERIALIZED VIEW mv_org_ingestion_summary IS
    'Per-organisation email volume and risk/verdict breakdown.  '
    'Rows with org_id IS NULL (pre-backfill emails) are excluded via '
    'AND e.org_id IS NOT NULL — this filter becomes a no-op once org_id '
    'is enforced NOT NULL on the emails table.  '
    'Verdict breakdown uses emails.current_verdict_label (016) instead of '
    'the expensive LATERAL subquery over verdicts.  '
    'Refresh: every 5 minutes via refresh_mv_org_ingestion_summary().';

-- Unique index required for REFRESH CONCURRENTLY.
-- org_id is guaranteed non-NULL by the WHERE filter above,
-- so no COALESCE sentinel is needed here.
CREATE UNIQUE INDEX idx_mv_org_ingestion_org_id
    ON mv_org_ingestion_summary(org_id);
