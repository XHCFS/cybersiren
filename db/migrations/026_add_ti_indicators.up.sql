-- ============================================================
--  026_add_ti_indicators.sql
--
--  Separates TI feed indicators from enriched email-observed
--  threats.  Until now enriched_threats has served two roles:
--
--    (A) Email-observed threats — URLs / domains / IPs extracted
--        from emails and later enriched with WHOIS, cert, geo,
--        VT, etc.  These are expensive to produce and are the
--        primary output of the enrichment pipeline.
--
--    (B) Global TI feed indicators — raw indicators ingested
--        from external feeds (PhishTank, MISP, etc.) that exist
--        only for matching purposes and carry no enrichment data.
--        These are cheap to store and must not block the expensive
--        enrichment pipeline.
--
--  This migration introduces:
--    A.  ti_indicators — lightweight, normalised table for
--        feed-origin indicators (role B above).
--    B.  email_url_ti_matches — junction table linking email_urls
--        to matching ti_indicators (explainability / auditability).
--    C.  Data migration — moves feed-only rows out of
--        enriched_threats into ti_indicators.
--    D.  Clarifying comments on enriched_threats columns that
--        are now conceptually reserved for email-observed threats.
--
--  Invariants preserved:
--    • email_urls.threat_id → enriched_threats(id) is untouched.
--    • Rows referenced by email_urls are never moved.
--    • enriched_threats is not physically altered beyond a new
--      deprecation comment on is_global.
--
--  All statements are idempotent / safe to re-run.
--  No CONCURRENTLY index builds (to keep the migration transactional).
-- ============================================================


-- ============================================================
--  A.1  CREATE ti_indicator_type ENUM
--
--  Naming: 'ti_indicator_type' — distinct from entity_type_enum
--  to avoid confusion.  entity_type_enum refers to the kind of
--  entity stored in a polymorphic reference; this enum describes
--  the kind of network / file indicator in a TI feed record.
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = current_schema()
          AND t.typname = 'ti_indicator_type'
    ) THEN
        CREATE TYPE ti_indicator_type AS ENUM (
            'url',            -- full URL, e.g. https://evil.example.com/phish
            'domain',         -- bare hostname or FQDN, e.g. evil.example.com
            'ip',             -- single IPv4/IPv6 address
            'cidr',           -- IP range / network block
            'hash',           -- file hash (MD5 / SHA1 / SHA256 / SSDEEP)
            'email_address'   -- known malicious sender address
        );
    END IF;
END;
$$;

COMMENT ON TYPE ti_indicator_type IS
    'Canonical set of indicator kinds stored in ti_indicators.  '
    'Not to be confused with entity_type_enum, which describes artefact '
    'types in the polymorphic verdict / enrichment tables.  '
    'To add a new kind: ALTER TYPE ti_indicator_type ADD VALUE ''new_kind'';';


-- ============================================================
--  A.2  CREATE ti_indicators
--
--  Uniqueness: (feed_id, indicator_type, indicator_value).
--    • Two different feeds may carry the same indicator —
--      allowed, desirable for corroboration.
--    • The same feed must not carry two rows for the same
--      indicator/type pair (idempotent ingest).
--
--  brand_id / target_brand: mirrors the enriched_threats pattern.
--    brand_id is the canonical FK (brands table, migration 020).
--    target_brand is a deprecated free-text fallback.
--
--  confidence: feed-assigned confidence score in [0.0, 1.0].
--    Aligns with the confidence column type on verdicts.
--
--  risk_score: feed-assigned severity [0, 100].
--    Used only for feed-side matching / prioritisation.
--    Does NOT feed into the main enrichment risk scoring model.
-- ============================================================

CREATE TABLE IF NOT EXISTS ti_indicators (
    id              BIGSERIAL PRIMARY KEY,

    -- Feed provenance (required — every TI indicator must have a source).
    feed_id         BIGINT          NOT NULL
                        REFERENCES feeds(id) ON DELETE CASCADE,

    -- What kind of indicator this is.
    indicator_type  ti_indicator_type NOT NULL,

    -- Canonical normalised value.
    --   url          → lowercased, scheme-normalised full URL
    --   domain       → lowercased FQDN without trailing dot
    --   ip           → canonical text representation of the address
    --   cidr         → canonical CIDR notation, e.g. 192.168.0.0/24
    --   hash         → lowercase hex string, prefixed with algo:
    --                   e.g. sha256:abc123…  or md5:abc123…
    --   email_address → lowercase address, e.g. phisher@evil.com
    indicator_value TEXT            NOT NULL,

    -- Classification (validated via threat_type_values reference table).
    -- The trg_normalise_threat_type trigger function (migration 020)
    -- is reused here to ensure consistency.
    threat_type     TEXT,

    -- Brand targeting.  brand_id is canonical; target_brand is legacy.
    brand_id        BIGINT
                        REFERENCES brands(id) ON DELETE SET NULL,
    target_brand    TEXT,  -- legacy fallback; populate brand_id on new inserts

    -- Taxonomy tags from the feed (e.g. '{"ransomware","emotet"}').
    threat_tags     TEXT[]  NOT NULL DEFAULT '{}',

    -- Original identifier in the source feed (e.g. PhishTank phish_id).
    source_id       TEXT,

    -- Temporal range during which this indicator was considered active.
    first_seen      TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen       TIMESTAMPTZ,

    -- Feed-assigned confidence [0.0, 1.0].  NULL = not provided by feed.
    confidence      DOUBLE PRECISION
                        CHECK (confidence IS NULL OR confidence BETWEEN 0.0 AND 1.0),

    -- Feed-assigned severity [0, 100].  For matching/prioritisation only.
    risk_score      INT             NOT NULL DEFAULT 0
                        CHECK (risk_score BETWEEN 0 AND 100),

    -- Soft-delete / staleness: FALSE when feed signals the indicator is
    -- no longer active (e.g. removed from a blocklist).
    is_active       BOOLEAN         NOT NULL DEFAULT TRUE,

    -- Free-form extra fields from the feed response (kept unparsed).
    raw_metadata    JSONB,

    created_at      TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- One row per indicator per feed.  Same indicator across different
    -- feeds is allowed (and expected — corroboration is a signal).
    CONSTRAINT uq_ti_indicators_feed_type_value
        UNIQUE (feed_id, indicator_type, indicator_value)
);

COMMENT ON TABLE ti_indicators IS
    'Normalised store for raw threat-intelligence feed indicators.  '
    'These rows are ingested cheaply from external TI feeds and are used '
    'only for matching against email-extracted URLs / domains / IPs / hashes.  '
    'They carry no enrichment data (no WHOIS, geo, ASN, cert, VT results, etc.). '
    'Enrichment happens only in enriched_threats, which is reserved for '
    'URL/domain/IP artefacts actually observed through the email pipeline.  '
    'Relationship: email_urls → enriched_threats (email observation + enrichment); '
    '              email_urls → ti_indicators via email_url_ti_matches (TI matching).';

COMMENT ON COLUMN ti_indicators.indicator_value IS
    'Canonical normalised representation of the indicator.  '
    'For urls: lowercased, scheme-normalised.  '
    'For domains: lowercased FQDN, no trailing dot.  '
    'For ip: canonical address text (inet_norm form).  '
    'For cidr: standard CIDR notation.  '
    'For hash: lowercase hex prefixed with algorithm, e.g. sha256:abc123….  '
    'For email_address: lower(address).';

COMMENT ON COLUMN ti_indicators.target_brand IS
    'DEPRECATED in favour of brand_id (brands table, migration 020).  '
    'Populated only when migrating legacy enriched_threats rows that '
    'carried a target_brand value.  New ingest must populate brand_id.';

COMMENT ON COLUMN ti_indicators.risk_score IS
    'Feed-assigned severity score [0, 100].  Used for TI-side matching '
    'and prioritisation only.  Not aggregated into the main email/threat '
    'enrichment risk scoring model.';


-- ============================================================
--  A.3  INDEXES ON ti_indicators
--
--  Primary matching workflow:
--    1. Incoming URL → lookup by indicator_value WHERE indicator_type = 'url'
--    2. Extracted domain → lookup by indicator_value WHERE indicator_type = 'domain'
--    3. Resolved IP → lookup by indicator_value WHERE indicator_type = 'ip'
--    4. Attachment hash → lookup by indicator_value WHERE indicator_type = 'hash'
--
--  B-tree is the right choice for all of these (equality lookups,
--  range scans on indicator_value prefix not expected).
-- ============================================================

-- Fast lookup by indicator value regardless of type (the most common query
-- is "does this URL/domain/IP/hash exist in any active TI indicator?").
CREATE INDEX IF NOT EXISTS idx_ti_indicators_value
    ON ti_indicators(indicator_value);

-- Narrow lookup by type + value (used when the caller already knows
-- the indicator kind, e.g. the URL classification step).
CREATE INDEX IF NOT EXISTS idx_ti_indicators_type_value
    ON ti_indicators(indicator_type, indicator_value);

-- Feed-scoped lookup (covering index for the feed ingest upsert path:
-- ON CONFLICT (feed_id, indicator_type, indicator_value) DO UPDATE).
CREATE INDEX IF NOT EXISTS idx_ti_indicators_feed_type_value
    ON ti_indicators(feed_id, indicator_type, indicator_value);

-- Active-only partial index: the matching query always filters is_active = TRUE.
CREATE INDEX IF NOT EXISTS idx_ti_indicators_active_value
    ON ti_indicators(indicator_type, indicator_value)
    WHERE is_active = TRUE;

-- Temporal lookups (feed health dashboards, staleness sweeps).
CREATE INDEX IF NOT EXISTS idx_ti_indicators_first_seen
    ON ti_indicators(first_seen);
CREATE INDEX IF NOT EXISTS idx_ti_indicators_last_seen
    ON ti_indicators(last_seen);

-- Feed FK (used by ON DELETE CASCADE and JOIN to feeds).
CREATE INDEX IF NOT EXISTS idx_ti_indicators_feed_id
    ON ti_indicators(feed_id);

-- Brand FK.
CREATE INDEX IF NOT EXISTS idx_ti_indicators_brand_id
    ON ti_indicators(brand_id)
    WHERE brand_id IS NOT NULL;

-- GIN index on threat_tags (same pattern as enriched_threats).
CREATE INDEX IF NOT EXISTS idx_ti_indicators_threat_tags
    ON ti_indicators USING GIN (threat_tags);


-- ============================================================
--  A.4  updated_at TRIGGER
--
--  Reuses the set_updated_at() function from migration 001.
-- ============================================================

DROP TRIGGER IF EXISTS trg_ti_indicators_updated_at ON ti_indicators;
CREATE TRIGGER trg_ti_indicators_updated_at
    BEFORE UPDATE ON ti_indicators
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();


-- ============================================================
--  A.5  THREAT TYPE NORMALISATION TRIGGER
--
--  Reuses fn_normalise_threat_type() from migration 020.
--  Ensures ti_indicators.threat_type values are lowercased and
--  validated against the threat_type_values reference table,
--  the same way enriched_threats.threat_type is enforced.
-- ============================================================

DROP TRIGGER IF EXISTS trg_normalise_threat_type ON ti_indicators;
CREATE TRIGGER trg_normalise_threat_type
    BEFORE INSERT OR UPDATE OF threat_type
    ON ti_indicators
    FOR EACH ROW
    EXECUTE FUNCTION fn_normalise_threat_type();


-- ============================================================
--  B.  email_url_ti_matches — JUNCTION TABLE
--
--  Rationale: When the matching pipeline checks an email URL
--  against TI feed indicators, we want an auditable record of:
--    • which email URL triggered a match
--    • which ti_indicator it matched
--    • how the match was made (exact URL, domain, IP, CIDR, hash)
--    • when the match was recorded
--
--  This is deliberately separate from email_urls.threat_id,
--  which remains the FK to enriched_threats (the full enrichment
--  record for that URL) and is not replaced by this table.
--
--  The two relationships are orthogonal:
--    email_urls.threat_id  → "here is the enrichment data for this URL"
--    email_url_ti_matches  → "here is which TI feed recognised this URL"
--
--  Uniqueness: one row per (email_url, ti_indicator) pair.
--  Duplicate matches (e.g. two ingest runs) are rejected.
-- ============================================================

CREATE TABLE IF NOT EXISTS email_url_ti_matches (
    id               BIGSERIAL PRIMARY KEY,
    email_url_id     BIGINT      NOT NULL
                         REFERENCES email_urls(id) ON DELETE CASCADE,
    ti_indicator_id  BIGINT      NOT NULL
                         REFERENCES ti_indicators(id) ON DELETE CASCADE,

    -- How the match was determined.
    --   exact   → indicator_value == the full URL
    --   domain  → indicator domain == extracted domain from the URL
    --   ip      → indicator IP == resolved IP of the URL's host
    --   cidr    → indicator CIDR block contains the resolved IP
    --   hash    → indicator hash matches attachment or page body hash
    match_type       TEXT        NOT NULL
                         CHECK (match_type IN ('exact', 'domain', 'ip', 'cidr', 'hash')),

    matched_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_email_url_ti_matches
        UNIQUE (email_url_id, ti_indicator_id)
);

COMMENT ON TABLE email_url_ti_matches IS
    'Audit trail of TI feed matches against email URLs.  '
    'Records which ti_indicator was matched for each email_url, '
    'how the match was determined, and when.  '
    'Does not replace email_urls.threat_id → enriched_threats, which '
    'remains the link to the full enrichment record.';

CREATE INDEX IF NOT EXISTS idx_eu_ti_matches_email_url_id
    ON email_url_ti_matches(email_url_id);
CREATE INDEX IF NOT EXISTS idx_eu_ti_matches_ti_indicator_id
    ON email_url_ti_matches(ti_indicator_id);
CREATE INDEX IF NOT EXISTS idx_eu_ti_matches_matched_at
    ON email_url_ti_matches(matched_at);


-- ============================================================
--  C.  DATA MIGRATION
--
--  Moves feed-only rows from enriched_threats into ti_indicators.
--
--  Heuristic for "feed-only" rows:
--    1. enriched_threats.is_global = TRUE
--         (set in migration 005 for records ingested from public feeds)
--    2. NOT referenced by any email_urls row
--         (email_urls.threat_id → enriched_threats.id)
--    3. feed_id IS NOT NULL
--         (must have a traceable feed source)
--
--  Rows that satisfy all three conditions have:
--    • Never been observed through an email (no email_urls link).
--    • Originated from a global/public TI feed (is_global).
--    • A known feed source (feed_id).
--  These are pure TI feed indicators with no enrichment data, and
--  exactly the kind of record ti_indicators is designed for.
--
--  Rows that are referenced by email_urls are kept in enriched_threats
--  unchanged — they were observed through the email pipeline and have
--  enrichment value.
--
--  indicator_type inference:
--    • URL scheme present (starts with http:// or https://) → 'url'
--    • ip_address IS NOT NULL and url = ip_address::TEXT     → 'ip'
--    • Otherwise                                             → 'domain'
--  (The url column in enriched_threats is the primary indicator value;
--  domain and ip_address are derived/enriched fields added later.)
--
--  Idempotency:
--    ON CONFLICT (feed_id, indicator_type, indicator_value) DO NOTHING
--    makes this safe to re-run if the migration is interrupted and
--    retried.  Source rows in enriched_threats are NOT deleted here —
--    a supervised cleanup step is recommended after verifying the data.
-- ============================================================

INSERT INTO ti_indicators (
    feed_id,
    indicator_type,
    indicator_value,
    threat_type,
    brand_id,
    target_brand,
    threat_tags,
    source_id,
    first_seen,
    last_seen,
    risk_score,
    is_active,
    raw_metadata,
    created_at,
    updated_at
)
SELECT
    et.feed_id,

    -- Infer indicator_type from the url column value.
    CASE
        WHEN et.url ~* '^https?://'
            THEN 'url'::ti_indicator_type
        WHEN et.ip_address IS NOT NULL
         AND et.url = et.ip_address::TEXT
            THEN 'ip'::ti_indicator_type
        ELSE
            'domain'::ti_indicator_type
    END                                     AS indicator_type,

    -- Normalise indicator_value: lowercase for domains/IPs, keep URL as-is.
    CASE
        WHEN et.url ~* '^https?://'
            THEN lower(et.url)
        ELSE
            lower(et.url)
    END                                     AS indicator_value,

    et.threat_type,
    et.brand_id,
    et.target_brand,
    COALESCE(et.threat_tags, '{}')          AS threat_tags,
    et.source_id,
    COALESCE(et.first_seen, et.created_at)  AS first_seen,
    et.last_seen,
    COALESCE(et.risk_score, 0)              AS risk_score,

    -- is_active: treat soft-deleted enriched_threats rows as inactive.
    (et.deleted_at IS NULL)                 AS is_active,

    -- Preserve any analysis metadata as raw_metadata.
    et.analysis_metadata                    AS raw_metadata,

    et.created_at,
    et.updated_at

FROM enriched_threats et

WHERE
    -- Condition 1: globally-shared feed record.
    et.is_global = TRUE

    -- Condition 2: has a structured feed reference.
AND et.feed_id IS NOT NULL

    -- Condition 3: not referenced by any email_urls row.
    -- These rows have email-observation value and must stay in enriched_threats.
AND NOT EXISTS (
        SELECT 1
        FROM   email_urls eu
        WHERE  eu.threat_id = et.id
    )

ON CONFLICT (feed_id, indicator_type, indicator_value)
    DO NOTHING;  -- idempotent: skip rows already migrated


-- ============================================================
--  D.  CLARIFYING COMMENTS ON enriched_threats
--
--  enrich_threats is now conceptually reserved for email-observed
--  URL/domain/IP artefacts that have been (or will be) enriched.
--  The following columns are called out explicitly:
--
--  is_global:  Was the discriminator for "global TI record vs
--              org-specific email observation".  After this migration,
--              new feed indicators go into ti_indicators; is_global
--              on enriched_threats rows should always be FALSE for
--              newly created email-email-observed threats.  Existing
--              TRUE rows that were not migrated (because they are
--              already referenced by email_urls) remain valid —
--              they are email-observed AND happened to be a known TI
--              indicator.
--
--  feed_id / source_feed:  Retained.  An email-observed threat may
--              legitimately reference the feed that confirmed it (e.g.
--              "this URL was seen in email AND is in feed X").  These
--              columns are not misleading in that context.  They should
--              NOT be the heuristic used to route new inserts; use
--              "does this threat come from an email extraction?" instead.
-- ============================================================

COMMENT ON COLUMN enriched_threats.is_global IS
    'TRUE = this record was originally ingested as a global TI feed record, '
    'shared across all tenants.  FALSE = attributed to org_id only.  '
    'AFTER MIGRATION 026: new TI feed indicators must be stored in '
    'ti_indicators, not here.  enriched_threats is now reserved for '
    'URL/domain/IP artefacts observed through the email pipeline and '
    'subsequently enriched.  Existing is_global = TRUE rows that are '
    'already referenced by email_urls are legitimate (email-observed AND '
    'feed-confirmed) and should not be moved.  '
    'See also: 005_fix_current_verdicts.sql (original column), '
    '          013_fix_multitenancy.sql (invariant CHECK).';

COMMENT ON COLUMN enriched_threats.feed_id IS
    'FK to feeds(id).  On an email-observed threat, this may point to a '
    'TI feed that independently confirmed the indicator — i.e. the URL '
    'was both extracted from an email AND found in a feed.  '
    'This column does NOT make a row a "feed indicator row"; that concept '
    'now belongs exclusively to ti_indicators.  '
    'Deprecated free-text counterpart: source_feed (see below).  '
    'Originally added in migration 003.';

COMMENT ON COLUMN enriched_threats.source_feed IS
    'DEPRECATED free-text feed label, retained for backwards compatibility '
    'with records ingested before the feeds table (migration 003).  '
    'New code must populate feed_id instead.  '
    'Will be dropped after all legacy rows have been backfilled.  '
    'Originally added in 001_initial_schema.sql.';

