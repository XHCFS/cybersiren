-- ============================================================
--  003_add_enrichments.sql
--  Adds feeds, enrichment pipeline tracking, rule engine,
--  and external provider results.
-- ============================================================


-- ============================================================
--  FEEDS
--
--  Tracks external threat intelligence sources.
--  Replaces the raw source_feed TEXT on enriched_threats.
-- ============================================================

CREATE TABLE IF NOT EXISTS feeds (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    display_name TEXT,
    feed_type    TEXT NOT NULL CHECK (feed_type IN ('threat_intel', 'reputation', 'blocklist', 'sandbox')),
    url          TEXT,
    last_fetched_at TIMESTAMPTZ,
    enabled      BOOLEAN DEFAULT TRUE,
    -- Weight applied when aggregating scores from multiple feeds.
    -- Higher = more trusted source. Defaults to equal weighting.
    reliability_weight DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    created_at   TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_feeds_name    ON feeds(name);
CREATE INDEX IF NOT EXISTS idx_feeds_enabled ON feeds(enabled) WHERE enabled = TRUE;


-- ============================================================
--  PATCH enriched_threats: add feed FK, drop NOT NULL on source_feed
--
--  source_feed is kept for backwards compatibility.
--  New inserts should populate feed_id instead.
-- ============================================================

ALTER TABLE enriched_threats
    ADD COLUMN IF NOT EXISTS feed_id BIGINT REFERENCES feeds(id) ON DELETE SET NULL;

-- source_feed has no NOT NULL constraint in 001 so this ALTER is a no-op.
-- Kept here for documentation: source_feed is now deprecated in favour of feed_id.
-- New inserts should populate feed_id. source_feed is retained for backwards compatibility
-- with any records that pre-date the feeds table.
-- ALTER TABLE enriched_threats
--     ALTER COLUMN source_feed DROP NOT NULL;

CREATE INDEX IF NOT EXISTS idx_enriched_feed_id ON enriched_threats(feed_id);


-- ============================================================
--  ENRICHMENT JOBS
--
--  DB-backed job queue for the Go enrichment worker pool.
--  Gives idempotency, retry tracking, and failure history.
-- ============================================================

CREATE TYPE job_status AS ENUM (
    'pending',
    'in_progress',
    'completed',
    'failed',
    'skipped'
);

CREATE TYPE job_type AS ENUM (
    'whois',
    'dns',
    'asn',
    'ip_geo',
    'ssl_cert',
    'url_scan',
    'virustotal',
    'feed_ingest',
    'rule_eval'
);

CREATE TABLE IF NOT EXISTS enrichment_jobs (
    id           BIGSERIAL PRIMARY KEY,
    job_type     job_type NOT NULL,
    status       job_status NOT NULL DEFAULT 'pending',
    entity_type  TEXT NOT NULL CHECK (entity_type IN ('email', 'threat', 'attachment')),
    entity_id    BIGINT NOT NULL,
    attempts     INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    last_error   TEXT,
    started_at   TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_jobs_status     ON enrichment_jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_entity     ON enrichment_jobs(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_jobs_type       ON enrichment_jobs(job_type);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON enrichment_jobs(created_at);
-- Partial index for the Go worker poll query.
-- Excludes exhausted jobs (attempts >= max_attempts) to avoid scanning permanently-failed rows.
CREATE INDEX IF NOT EXISTS idx_jobs_pending ON enrichment_jobs(created_at)
    WHERE status IN ('pending', 'failed')
      AND attempts < max_attempts;


-- ============================================================
--  ENRICHMENT RESULTS
--
--  Raw responses from external providers, one row per provider
--  per entity. Upsert on conflict so re-enrichment is clean.
--  Keeps raw responses so you can re-score without re-fetching.
-- ============================================================

CREATE TABLE IF NOT EXISTS enrichment_results (
    id           BIGSERIAL PRIMARY KEY,
    entity_type  TEXT NOT NULL CHECK (entity_type IN ('email', 'threat', 'attachment')),
    entity_id    BIGINT NOT NULL,
    provider     TEXT NOT NULL,
    raw_response JSONB NOT NULL,

    -- Parsed summary fields — avoids re-parsing raw_response during scoring
    malicious_votes  INT,
    harmless_votes   INT,
    suspicious_votes INT,
    reputation_score DOUBLE PRECISION,

    fetched_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (entity_type, entity_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_enrichment_results_entity     ON enrichment_results(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_enrichment_results_provider   ON enrichment_results(provider);
CREATE INDEX IF NOT EXISTS idx_enrichment_results_fetched_at ON enrichment_results(fetched_at);


-- ============================================================
--  RULES
--
--  Versioned detection rules. Each edit is a new row so verdict
--  history can always trace back to the exact logic that fired.
-- ============================================================

CREATE TYPE rule_status AS ENUM (
    'draft',
    'active',
    'disabled',
    'archived'
);

CREATE TABLE IF NOT EXISTS rules (
    id          BIGSERIAL PRIMARY KEY,
    org_id      BIGINT REFERENCES organisations(id) ON DELETE CASCADE, -- NULL = global rule

    name        TEXT NOT NULL,
    description TEXT,
    version     TEXT NOT NULL DEFAULT '1.0.0',
    status      rule_status NOT NULL DEFAULT 'draft',

    -- JSONB rule logic your Go engine evaluates:
    -- conditions, field targets, thresholds, logical operators.
    logic       JSONB NOT NULL,

    score_impact INT NOT NULL DEFAULT 0 CHECK (score_impact BETWEEN -100 AND 100),
    target       TEXT NOT NULL CHECK (target IN ('email', 'url', 'attachment', 'header', 'campaign')),

    created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_rules_org_id ON rules(org_id);
CREATE INDEX IF NOT EXISTS idx_rules_status ON rules(status);
CREATE INDEX IF NOT EXISTS idx_rules_target ON rules(target);
CREATE INDEX IF NOT EXISTS idx_rules_active ON rules(status) WHERE status = 'active';

-- Enforces (org_id, name, version) uniqueness, treating two global
-- rules (org_id IS NULL) with the same name/version as duplicates.
-- PG15+: NULLS NOT DISTINCT handles the NULL org_id case correctly.
ALTER TABLE rules
    ADD CONSTRAINT uq_rules_org_name_version
    UNIQUE NULLS NOT DISTINCT (org_id, name, version);

-- PG14 fallback (comment out the above and use these instead):
-- CREATE UNIQUE INDEX uq_rules_global_name_version
--     ON rules(name, version) WHERE org_id IS NULL;
-- CREATE UNIQUE INDEX uq_rules_org_name_version
--     ON rules(org_id, name, version) WHERE org_id IS NOT NULL;


-- ============================================================
--  RULE HITS
--
--  Every time a rule fires, record it here.
--  Links entity → rule version → score contribution.
--  This is what lets you explain why an email scored the way it did.
-- ============================================================

CREATE TABLE IF NOT EXISTS rule_hits (
    id           BIGSERIAL PRIMARY KEY,
    rule_id      BIGINT NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    rule_version TEXT NOT NULL,
    entity_type  TEXT NOT NULL CHECK (entity_type IN ('email', 'threat', 'attachment', 'campaign')),
    entity_id    BIGINT NOT NULL,
    score_impact INT NOT NULL,
    match_detail JSONB,
    fired_at     TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_rule_hits_rule_id  ON rule_hits(rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_hits_entity   ON rule_hits(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_rule_hits_fired_at ON rule_hits(fired_at);


-- ============================================================
--  UPDATED_AT TRIGGERS (003 tables)
-- ============================================================

CREATE TRIGGER trg_feeds_updated_at
    BEFORE UPDATE ON feeds
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
