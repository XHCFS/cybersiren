-- ============================================================
--  009_fix_indexes.sql
--  Removes redundant and low-value indexes; adds composite
--  org-scoped indexes on the emails partitioned table.
--
--  All DROPs use IF EXISTS.
--  No CONCURRENTLY — assumes a transactional migrator.
--  No index that backs a UNIQUE or PRIMARY KEY constraint is touched.
-- ============================================================


-- ============================================================
--  #27  attachment_library — drop idx_attachments_sha256
--
--  sha256 is declared UNIQUE NOT NULL on attachment_library,
--  so Postgres already maintains an implicit unique B-tree index
--  on that column. idx_attachments_sha256 is an exact duplicate
--  and wastes ~one index-page-set per row written.
-- ============================================================

DROP INDEX IF EXISTS idx_attachments_sha256;


-- ============================================================
--  #28  campaigns — drop idx_campaigns_fingerprint
--
--  fingerprint is declared UNIQUE NOT NULL on campaigns.
--  The UNIQUE constraint's implicit index covers all lookups
--  that idx_campaigns_fingerprint would serve.
-- ============================================================

DROP INDEX IF EXISTS idx_campaigns_fingerprint;


-- ============================================================
--  #29  feeds — drop idx_feeds_name
--
--  name is declared UNIQUE NOT NULL on feeds.
--  The constraint's implicit index makes idx_feeds_name redundant.
-- ============================================================

DROP INDEX IF EXISTS idx_feeds_name;


-- ============================================================
--  #30  enriched_threats — drop three low-selectivity indexes
--
--  idx_enriched_online  : BOOLEAN column — only 2 distinct values
--  (TRUE / FALSE / NULL counts as a third but collapses the
--  selectivity further). The planner will prefer a seq-scan for
--  any predicate on this column because even the "minority" value
--  typically matches ~30-50 % of rows.
--
--  idx_enriched_country : TEXT column but country codes cluster
--  into dozens of values across potentially millions of rows.
--  Standalone selectivity is too low; country is better served
--  as the second column of a composite (threat_type, country)
--  index if a specific query pattern demands it.
--
--  idx_enriched_tld     : TLD distributes across a few hundred
--  values (.com, .net, .xyz dominate), giving poor selectivity
--  for point lookups. Like country, it is more useful as part
--  of a composite index targeting a concrete query pattern.
--
--  These three indexes are net-negative on write-heavy ingestion
--  workloads: they add WAL, checkpoint pressure, and autovacuum
--  work without meaningfully improving read plans.
-- ============================================================

DROP INDEX IF EXISTS idx_enriched_online;
DROP INDEX IF EXISTS idx_enriched_country;
DROP INDEX IF EXISTS idx_enriched_tld;


-- ============================================================
--  #31  emails — add composite org-scoped indexes
--
--  The emails table is range-partitioned by fetched_at.
--  Indexes created on the parent are automatically propagated
--  to all existing and future child partitions by Postgres 11+.
--
--  Three patterns cover the vast majority of tenant-facing list
--  and search queries:
--
--  1. (org_id, fetched_at DESC)
--     Time-ordered inbox view: "show me my org's emails newest-first."
--     No partial predicate — also serves soft-deleted row counts.
--
--  2. (org_id, risk_score DESC) WHERE deleted_at IS NULL
--     Risk triage queue: "show my org's highest-risk live emails."
--     Partial predicate excludes deleted rows from the index,
--     keeping it small and matching the query filter exactly.
--
--  3. (org_id, sender_domain) WHERE deleted_at IS NULL
--     Domain drill-down: "all live emails from phishing-domain.xyz
--     in my org." Also accelerates GROUP BY sender_domain analytics.
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_emails_org_fetched_at
    ON emails (org_id, fetched_at DESC);

CREATE INDEX IF NOT EXISTS idx_emails_org_risk_score
    ON emails (org_id, risk_score DESC)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_emails_org_sender_domain
    ON emails (org_id, sender_domain)
    WHERE deleted_at IS NULL;


-- ============================================================
--  #33  feeds — drop idx_feeds_enabled
--
--  feeds is a small, rarely-written reference table. In
--  practice it will hold tens to low-hundreds of rows at most.
--  For tables this small Postgres's sequential scan is cheaper
--  than an index scan: the planner pays the per-page overhead
--  to walk the index, then fetches the heap page anyway, all
--  for a table that likely fits in a single heap page.
--  The planner will already ignore this index once statistics
--  show the table is small, making the index pure write overhead.
-- ============================================================

DROP INDEX IF EXISTS idx_feeds_enabled;


-- ============================================================
--  #34  verdicts — drop idx_verdicts_label and idx_verdicts_source
--
--  verdict_label has 6 distinct values; verdict_source has 4.
--  Standalone B-tree indexes on these enums have very poor
--  selectivity — a "phishing" label query still touches a large
--  fraction of the table and the planner routinely chooses a
--  seq-scan over them.
--
--  More importantly, the covering index idx_verdicts_entity_time
--  ON verdicts(entity_type, entity_id, created_at DESC)
--  already satisfies every query that resolves the current
--  verdict for an entity. Any further filtering on label or
--  source is a cheap post-filter on the small result set that
--  the covering index returns. Keeping idx_verdicts_label and
--  idx_verdicts_source adds WAL and maintenance cost on every
--  verdict insert with no measurable query benefit.
-- ============================================================

DROP INDEX IF EXISTS idx_verdicts_label;
DROP INDEX IF EXISTS idx_verdicts_source;
