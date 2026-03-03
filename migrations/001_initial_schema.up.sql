-- ============================================================
--  001_initial_schema.sql
-- ============================================================


-- ============================================================
--  ENRICHED THREATS
-- ============================================================

CREATE TABLE IF NOT EXISTS enriched_threats (
    id BIGSERIAL PRIMARY KEY,
    url TEXT NOT NULL UNIQUE,
    domain TEXT,

    online BOOLEAN,
    http_status_code INT,

    ip_address INET,
    cidr_block TEXT,
    asn INT,
    asn_name TEXT,
    isp TEXT,

    country TEXT,
    country_name TEXT,
    region TEXT,
    city TEXT,
    latitude  DOUBLE PRECISION,
    longitude DOUBLE PRECISION,

    ssl_enabled    BOOLEAN,
    cert_issuer    TEXT,
    cert_subject   TEXT,
    cert_valid_from TIMESTAMPTZ,
    cert_valid_to   TIMESTAMPTZ,
    cert_serial    TEXT,

    tld          TEXT,
    registrar    TEXT,
    creation_date DATE,
    expiry_date   DATE,
    updated_date  DATE,
    name_servers  TEXT[],

    page_language TEXT,
    page_title    TEXT,

    threat_type  TEXT,
    target_brand TEXT,
    threat_tags  TEXT[],

    source_feed  TEXT,
    source_id    TEXT,
    first_seen   TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_seen    TIMESTAMPTZ,
    last_checked TIMESTAMPTZ,

    notes             TEXT,
    analysis_metadata JSONB,
    risk_score        INT DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),

    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_enriched_domain      ON enriched_threats(domain);
CREATE INDEX IF NOT EXISTS idx_enriched_ip          ON enriched_threats(ip_address);
CREATE INDEX IF NOT EXISTS idx_enriched_asn         ON enriched_threats(asn);
CREATE INDEX IF NOT EXISTS idx_enriched_country     ON enriched_threats(country);
CREATE INDEX IF NOT EXISTS idx_enriched_online      ON enriched_threats(online);
CREATE INDEX IF NOT EXISTS idx_enriched_tld         ON enriched_threats(tld);
CREATE INDEX IF NOT EXISTS idx_enriched_threat_type ON enriched_threats(threat_type);
CREATE INDEX IF NOT EXISTS idx_enriched_first_seen  ON enriched_threats(first_seen);
CREATE INDEX IF NOT EXISTS idx_enriched_last_seen   ON enriched_threats(last_seen);
CREATE INDEX IF NOT EXISTS idx_enriched_risk_score  ON enriched_threats(risk_score);
CREATE INDEX IF NOT EXISTS idx_enriched_threat_tags ON enriched_threats USING GIN (threat_tags);
CREATE INDEX IF NOT EXISTS idx_enriched_active      ON enriched_threats(deleted_at) WHERE deleted_at IS NULL;


-- ============================================================
--  CAMPAIGNS
-- ============================================================

CREATE TABLE IF NOT EXISTS campaigns (
    id BIGSERIAL PRIMARY KEY,

    name        TEXT,
    description TEXT,

    -- Deterministic fingerprint derived from shared campaign signals.
    -- Used by the ingestion pipeline for idempotent upserts.
    -- NOTE: Currently globally unique. If campaigns should be per-org,
    -- change to UNIQUE (org_id, fingerprint) after org_id is added in 002.
    fingerprint TEXT UNIQUE NOT NULL,

    threat_type  TEXT,
    target_brand TEXT,
    tags         TEXT[],

    first_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_seen  TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    risk_score INT DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),

    analysis_metadata JSONB,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_campaigns_fingerprint  ON campaigns(fingerprint);
CREATE INDEX IF NOT EXISTS idx_campaigns_threat_type  ON campaigns(threat_type);
CREATE INDEX IF NOT EXISTS idx_campaigns_target_brand ON campaigns(target_brand);
CREATE INDEX IF NOT EXISTS idx_campaigns_first_seen   ON campaigns(first_seen);
CREATE INDEX IF NOT EXISTS idx_campaigns_tags         ON campaigns USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_campaigns_active       ON campaigns(deleted_at) WHERE deleted_at IS NULL;


-- ============================================================
--  EMAILS  (partitioned by fetched_at, monthly)
--
--  Composite PK (internal_id, fetched_at) is required by
--  Postgres when child tables reference a partitioned parent.
-- ============================================================

CREATE TABLE IF NOT EXISTS emails (
    internal_id BIGSERIAL,
    fetched_at  TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    message_id  TEXT,
    campaign_id BIGINT REFERENCES campaigns(id) ON DELETE SET NULL,

    sender_name    TEXT,
    sender_email   TEXT,
    sender_domain  TEXT,
    reply_to_email TEXT,
    return_path    TEXT,

    originating_ip   INET,
    auth_spf         TEXT,
    auth_dkim        TEXT,
    auth_dmarc       TEXT,
    auth_arc         TEXT,
    x_originating_ip INET,
    mailer_agent     TEXT,
    in_reply_to      TEXT,
    references_list  TEXT[],
    content_charset  TEXT,
    precedence       TEXT,
    list_id          TEXT,
    vendor_security_tags JSONB,

    subject        TEXT,
    sent_timestamp BIGINT, -- raw Unix epoch from email headers; kept as-is to preserve malformed values
    headers_json   JSONB,
    body_plain     TEXT,
    body_html      TEXT,

    header_risk_score     INT DEFAULT 0 CHECK (header_risk_score BETWEEN 0 AND 100),
    content_risk_score    INT DEFAULT 0 CHECK (content_risk_score BETWEEN 0 AND 100),
    attachment_risk_score INT DEFAULT 0 CHECK (attachment_risk_score BETWEEN 0 AND 100),
    url_risk_score        INT DEFAULT 0 CHECK (url_risk_score BETWEEN 0 AND 100),
    analysis_metadata     JSONB,

    risk_score INT DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),

    deleted_at TIMESTAMPTZ,

    PRIMARY KEY (internal_id, fetched_at)

) PARTITION BY RANGE (fetched_at);

CREATE TABLE IF NOT EXISTS emails_2025_01 PARTITION OF emails FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE IF NOT EXISTS emails_2025_02 PARTITION OF emails FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
CREATE TABLE IF NOT EXISTS emails_2025_03 PARTITION OF emails FOR VALUES FROM ('2025-03-01') TO ('2025-04-01');
CREATE TABLE IF NOT EXISTS emails_2025_04 PARTITION OF emails FOR VALUES FROM ('2025-04-01') TO ('2025-05-01');
CREATE TABLE IF NOT EXISTS emails_2025_05 PARTITION OF emails FOR VALUES FROM ('2025-05-01') TO ('2025-06-01');
CREATE TABLE IF NOT EXISTS emails_2025_06 PARTITION OF emails FOR VALUES FROM ('2025-06-01') TO ('2025-07-01');
CREATE TABLE IF NOT EXISTS emails_2025_07 PARTITION OF emails FOR VALUES FROM ('2025-07-01') TO ('2025-08-01');
CREATE TABLE IF NOT EXISTS emails_2025_08 PARTITION OF emails FOR VALUES FROM ('2025-08-01') TO ('2025-09-01');
CREATE TABLE IF NOT EXISTS emails_2025_09 PARTITION OF emails FOR VALUES FROM ('2025-09-01') TO ('2025-10-01');
CREATE TABLE IF NOT EXISTS emails_2025_10 PARTITION OF emails FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');
CREATE TABLE IF NOT EXISTS emails_2025_11 PARTITION OF emails FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');
CREATE TABLE IF NOT EXISTS emails_2025_12 PARTITION OF emails FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');
CREATE TABLE IF NOT EXISTS emails_2026_01 PARTITION OF emails FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE IF NOT EXISTS emails_2026_02 PARTITION OF emails FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE IF NOT EXISTS emails_2026_03 PARTITION OF emails FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE IF NOT EXISTS emails_2026_04 PARTITION OF emails FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE IF NOT EXISTS emails_2026_05 PARTITION OF emails FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE IF NOT EXISTS emails_2026_06 PARTITION OF emails FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE IF NOT EXISTS emails_2026_07 PARTITION OF emails FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE IF NOT EXISTS emails_2026_08 PARTITION OF emails FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE IF NOT EXISTS emails_2026_09 PARTITION OF emails FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE IF NOT EXISTS emails_2026_10 PARTITION OF emails FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE IF NOT EXISTS emails_2026_11 PARTITION OF emails FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE IF NOT EXISTS emails_2026_12 PARTITION OF emails FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE TABLE IF NOT EXISTS emails_default  PARTITION OF emails DEFAULT;

CREATE INDEX IF NOT EXISTS idx_emails_fetched_at   ON emails(fetched_at);
CREATE INDEX IF NOT EXISTS idx_sender_domain       ON emails(sender_domain);
CREATE INDEX IF NOT EXISTS idx_originating_ip      ON emails(originating_ip);
CREATE INDEX IF NOT EXISTS idx_message_id          ON emails(message_id);
CREATE INDEX IF NOT EXISTS idx_sent_timestamp      ON emails(sent_timestamp);
CREATE INDEX IF NOT EXISTS idx_emails_risk_score   ON emails(risk_score);
CREATE INDEX IF NOT EXISTS idx_in_reply_to         ON emails(in_reply_to);
CREATE INDEX IF NOT EXISTS idx_mailer_agent        ON emails(mailer_agent);
CREATE INDEX IF NOT EXISTS idx_emails_campaign_id  ON emails(campaign_id);
CREATE INDEX IF NOT EXISTS idx_emails_headers_json ON emails USING GIN (headers_json);
CREATE INDEX IF NOT EXISTS idx_emails_active       ON emails(deleted_at) WHERE deleted_at IS NULL;


-- ============================================================
--  VERDICTS
--
--  Append-only — never update a row, always insert a new one.
--  Current verdict = latest by created_at for a given entity.
-- ============================================================

CREATE TYPE verdict_label AS ENUM (
    'benign',
    'suspicious',
    'phishing',
    'malware',
    'spam',
    'unknown'
);

CREATE TYPE verdict_source AS ENUM (
    'model',    -- ML pipeline
    'analyst',  -- Human reviewer
    'feed',     -- Authoritative external feed
    'rule'      -- Deterministic rule engine
);

CREATE TABLE IF NOT EXISTS verdicts (
    id          BIGSERIAL PRIMARY KEY,
    entity_type TEXT NOT NULL CHECK (entity_type IN ('email', 'threat', 'attachment', 'campaign')),
    entity_id   BIGINT NOT NULL,
    label       verdict_label NOT NULL,
    confidence  DOUBLE PRECISION CHECK (confidence BETWEEN 0.0 AND 1.0),
    source      verdict_source NOT NULL,
    model_version TEXT, -- populated for source = 'model'
    notes         TEXT, -- populated for source = 'analyst'
    created_at  TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_verdicts_label      ON verdicts(label);
CREATE INDEX IF NOT EXISTS idx_verdicts_source     ON verdicts(source);
CREATE INDEX IF NOT EXISTS idx_verdicts_created_at ON verdicts(created_at);
-- Covering index: lets current_verdicts view resolve without a full table sort.
CREATE INDEX IF NOT EXISTS idx_verdicts_entity_time
    ON verdicts(entity_type, entity_id, created_at DESC);

CREATE OR REPLACE VIEW current_verdicts AS
SELECT DISTINCT ON (entity_type, entity_id)
    entity_type,
    entity_id,
    label,
    confidence,
    source,
    model_version,
    notes,
    created_at
FROM verdicts
ORDER BY entity_type, entity_id, created_at DESC;


-- ============================================================
--  EMAIL URLS
-- ============================================================

CREATE TABLE IF NOT EXISTS email_urls (
    id               BIGSERIAL PRIMARY KEY,
    email_id         BIGINT NOT NULL,
    email_fetched_at TIMESTAMPTZ NOT NULL,
    threat_id        BIGINT NOT NULL,
    visible_text     TEXT,   -- anchor text shown to recipient, e.g. "Click Here"
    created_at       TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (email_id, email_fetched_at) REFERENCES emails(internal_id, fetched_at) ON DELETE CASCADE,
    FOREIGN KEY (threat_id) REFERENCES enriched_threats(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_email_urls_email_id  ON email_urls(email_id);
CREATE INDEX IF NOT EXISTS idx_email_urls_threat_id ON email_urls(threat_id);


-- ============================================================
--  ATTACHMENT LIBRARY  (global dedup by SHA256)
--
--  Global dedup corpus. SHA256 uniqueness is intentionally cross-tenant.
--  An attachment that appears across multiple orgs is a stronger malware signal.
--  Tenant isolation is NOT a goal here.
-- ============================================================

CREATE TABLE IF NOT EXISTS attachment_library (
    id               BIGSERIAL PRIMARY KEY,
    actual_extension TEXT,
    size_bytes       BIGINT,
    entropy          DOUBLE PRECISION,
    md5              TEXT,
    sha1             TEXT,
    sha256           TEXT UNIQUE NOT NULL,
    is_malicious     BOOLEAN DEFAULT FALSE,
    risk_score       INT DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    threat_tags      TEXT[],
    created_at       TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_attachments_sha256      ON attachment_library(sha256);
CREATE INDEX IF NOT EXISTS idx_attachments_entropy     ON attachment_library(entropy);
CREATE INDEX IF NOT EXISTS idx_attachments_threat_tags ON attachment_library USING GIN (threat_tags);


-- ============================================================
--  EMAIL ATTACHMENTS
-- ============================================================

CREATE TABLE IF NOT EXISTS email_attachments (
    email_id          BIGINT NOT NULL,
    email_fetched_at  TIMESTAMPTZ NOT NULL,
    attachment_id     BIGINT NOT NULL,
    filename          TEXT,
    content_type      TEXT,
    analysis_metadata JSONB,
    content_id        TEXT,
    disposition       TEXT,
    risk_score        INT DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),

    PRIMARY KEY (email_id, email_fetched_at, attachment_id),
    FOREIGN KEY (email_id, email_fetched_at) REFERENCES emails(internal_id, fetched_at) ON DELETE CASCADE,
    FOREIGN KEY (attachment_id) REFERENCES attachment_library(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_email_attachments_email_id      ON email_attachments(email_id);
CREATE INDEX IF NOT EXISTS idx_email_attachments_attachment_id ON email_attachments(attachment_id);


-- ============================================================
--  UPDATED_AT TRIGGER
--
--  Keeps updated_at accurate even on direct SQL updates.
--  Attach to every table that has an updated_at column.
-- ============================================================

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_enriched_threats_updated_at
    BEFORE UPDATE ON enriched_threats
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_campaigns_updated_at
    BEFORE UPDATE ON campaigns
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
