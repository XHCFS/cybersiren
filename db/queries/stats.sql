-- =============================================================================
-- stats.sql — the 5 dashboard materialized-view reads for the svc-10 console
-- (MVP-7 /stats). The MVs (mv_threat_summary, mv_campaign_summary,
-- mv_feed_health, mv_rule_performance, mv_org_ingestion_summary) are rebuilt in
-- migration 027. Materialized views are NOT RLS-forced — RLS does not propagate
-- through a MV — so org scoping here is enforced by EXPLICIT org_id predicates in
-- the SQL, NOT by the app.current_org_id GUC. The console passes the authenticated
-- JWT claim OrgID as @org_id.
-- =============================================================================

-- name: GetThreatSummary :many
-- mv_threat_summary grouped rows for the org's threat landscape. The MV stores
-- org_id as COALESCE(org_id, -1) and a separate is_global flag; we return both
-- the org's own rows AND globally-shared TI rows (is_global = TRUE), which is the
-- intended cross-tenant TI corpus the analyst should see.
SELECT
    threat_type,
    country,
    asn,
    asn_name,
    is_global,
    org_id,
    total,
    online_count,
    offline_count,
    avg_risk_score,
    max_risk_score,
    earliest_seen,
    latest_seen
FROM mv_threat_summary
WHERE org_id = @org_id OR is_global = TRUE
ORDER BY total DESC, threat_type;

-- name: GetCampaignSummary :many
-- mv_campaign_summary rows for the org's detected campaigns, newest activity
-- first. org_id is nullable in the MV (COALESCE not applied); the explicit
-- predicate is the tenant boundary.
SELECT
    campaign_id,
    org_id,
    name,
    fingerprint,
    threat_type,
    target_brand,
    risk_score,
    first_seen,
    last_seen,
    email_count,
    avg_email_risk_score,
    verdict_phishing,
    verdict_malware,
    verdict_suspicious,
    verdict_benign,
    verdict_spam,
    verdict_unknown
FROM mv_campaign_summary
WHERE org_id = @org_id
ORDER BY last_seen DESC NULLS LAST, campaign_id;

-- name: GetFeedHealth :many
-- mv_feed_health rows. Feeds are a PLATFORM-global resource (the MV has no org_id
-- column), so this returns all feeds; ordering surfaces the freshest first.
SELECT
    feed_id,
    name,
    display_name,
    feed_type,
    reliability_weight,
    enabled,
    last_fetched_at,
    seconds_since_fetch,
    total_threats_contributed,
    active_threats,
    avg_threat_risk_score,
    most_recent_threat
FROM mv_feed_health
ORDER BY last_fetched_at DESC NULLS LAST, feed_id;

-- name: GetRulePerformance :many
-- mv_rule_performance rows for the org's rules PLUS platform-global rules
-- (org_id IS NULL). org_id is nullable in the MV.
SELECT
    rule_id,
    org_id,
    name,
    version,
    status,
    target,
    score_impact,
    total_hits,
    hits_last_24h,
    hits_last_7d,
    total_score_contributed,
    last_fired_at
FROM mv_rule_performance
WHERE org_id = @org_id OR org_id IS NULL
ORDER BY total_hits DESC, rule_id;

-- name: GetOrgIngestionSummary :one
-- mv_org_ingestion_summary single row for the org's ingestion volumes + verdict
-- breakdown. org_id is nullable in the MV. Returns no row when the org has
-- ingested nothing yet (the console renders zeroes in that case).
SELECT
    org_id,
    total_emails,
    emails_last_24h,
    emails_last_7d,
    emails_last_30d,
    avg_risk_score,
    max_risk_score,
    high_risk_count,
    medium_risk_count,
    low_risk_count,
    confirmed_phishing,
    confirmed_malware,
    confirmed_spam,
    confirmed_benign,
    unclassified
FROM mv_org_ingestion_summary
WHERE org_id = @org_id;
