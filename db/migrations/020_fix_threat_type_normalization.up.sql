-- ============================================================
--  020_fix_threat_type_normalization.sql
--
--  Normalises threat_type and target_brand on enriched_threats
--  and campaigns to eliminate case-variant fragmentation in
--  GROUP BY aggregations and materialized views.
--
--  Changes:
--    #53  threat_type_values reference table + BEFORE INSERT OR
--         UPDATE trigger on enriched_threats and campaigns that
--         lowercases threat_type and rejects unknown values.
--    #54  brands reference table + brand_id FK on enriched_threats
--         and campaigns. target_brand is deprecated but retained.
--    Refresh mv_threat_summary and mv_campaign_summary so the
--    MVs reflect any normalised data.
--
--  Existing rows with non-canonical threat_type values are NOT
--  modified.  A one-time UPDATE to normalise historical data is
--  recommended but must be run as a separate data migration to
--  avoid long-running locks.
--
--  Depends on: 013_fix_multitenancy.sql (org_id on core tables)
--  All statements idempotent.  No CONCURRENTLY.
-- ============================================================


-- ============================================================
--  #53  THREAT TYPE REFERENCE TABLE
-- ============================================================

CREATE TABLE IF NOT EXISTS threat_type_values (
    value TEXT PRIMARY KEY  -- canonical lowercase value
);

COMMENT ON TABLE threat_type_values IS
    'Canonical set of lowercase threat_type values.  '
    'The trg_normalise_threat_type triggers on enriched_threats and '
    'campaigns reject any value not present in this table.  '
    'To add a new threat type, INSERT INTO threat_type_values(value) '
    'VALUES (''my_new_type'') before inserting rows that use it.';

-- Seed canonical values (idempotent via ON CONFLICT DO NOTHING).
INSERT INTO threat_type_values (value) VALUES
    ('phishing'),
    ('malware'),
    ('ransomware'),
    ('spam'),
    ('bec'),
    ('credential_harvesting'),
    ('tech_support_scam'),
    ('advance_fee_fraud'),
    ('unknown')
ON CONFLICT (value) DO NOTHING;


-- ============================================================
--  #53  NORMALISATION TRIGGER FUNCTION
--
--  Lowercases NEW.threat_type and validates it against
--  threat_type_values.  Shared by both enriched_threats and
--  campaigns triggers.
-- ============================================================

CREATE OR REPLACE FUNCTION fn_normalise_threat_type()
RETURNS TRIGGER AS $$
BEGIN
    -- Allow NULLs — threat_type is nullable on both tables.
    IF NEW.threat_type IS NULL THEN
        RETURN NEW;
    END IF;

    -- Normalise to lowercase.
    NEW.threat_type := lower(NEW.threat_type);

    -- Validate against the reference table.
    IF NOT EXISTS (
        SELECT 1 FROM threat_type_values WHERE value = NEW.threat_type
    ) THEN
        RAISE EXCEPTION
            'Invalid threat_type "%" on %.  '
            'INSERT INTO threat_type_values(value) VALUES (''%'') first.',
            NEW.threat_type, TG_TABLE_NAME, NEW.threat_type;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION fn_normalise_threat_type() IS
    'BEFORE INSERT OR UPDATE trigger function that lowercases threat_type '
    'and rejects values not present in the threat_type_values reference '
    'table.  Shared by enriched_threats and campaigns.';


-- ============================================================
--  #53  ATTACH TRIGGERS (idempotent via DROP IF EXISTS + CREATE)
-- ============================================================

-- enriched_threats
DROP TRIGGER IF EXISTS trg_normalise_threat_type ON enriched_threats;
CREATE TRIGGER trg_normalise_threat_type
    BEFORE INSERT OR UPDATE OF threat_type
    ON enriched_threats
    FOR EACH ROW
    EXECUTE FUNCTION fn_normalise_threat_type();

-- campaigns
DROP TRIGGER IF EXISTS trg_normalise_threat_type ON campaigns;
CREATE TRIGGER trg_normalise_threat_type
    BEFORE INSERT OR UPDATE OF threat_type
    ON campaigns
    FOR EACH ROW
    EXECUTE FUNCTION fn_normalise_threat_type();


-- ============================================================
--  #54  BRANDS REFERENCE TABLE
-- ============================================================

CREATE TABLE IF NOT EXISTS brands (
    id   BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,  -- canonical display name, e.g. 'PayPal'
    aliases TEXT[] NOT NULL DEFAULT '{}'  -- known variants, e.g. '{"paypal","PAYPAL Inc."}'
);

COMMENT ON TABLE brands IS
    'Canonical brand directory for target_brand normalisation.  '
    'name is the single display form; aliases lists known alternative '
    'spellings / casings.  Application code should resolve a raw '
    'target_brand string to a brands.id before persisting.';


-- ============================================================
--  #54  ADD brand_id FK TO enriched_threats AND campaigns
-- ============================================================

-- enriched_threats
ALTER TABLE enriched_threats
    ADD COLUMN IF NOT EXISTS brand_id BIGINT
        REFERENCES brands(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_enriched_brand_id
    ON enriched_threats(brand_id);

-- campaigns
ALTER TABLE campaigns
    ADD COLUMN IF NOT EXISTS brand_id BIGINT
        REFERENCES brands(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_campaigns_brand_id
    ON campaigns(brand_id);


-- ============================================================
--  #54  DEPRECATION COMMENTS ON target_brand
-- ============================================================

COMMENT ON COLUMN enriched_threats.target_brand IS
    'DEPRECATED in favour of brand_id (see brands table, migration 020).  '
    'Retained for backwards compatibility — new code should populate '
    'brand_id instead.  Will be dropped in a future migration once all '
    'consumers have been migrated.';

COMMENT ON COLUMN campaigns.target_brand IS
    'DEPRECATED in favour of brand_id (see brands table, migration 020).  '
    'Retained for backwards compatibility — new code should populate '
    'brand_id instead.  Will be dropped in a future migration once all '
    'consumers have been migrated.';


-- ============================================================
--  REFRESH MATERIALIZED VIEWS
--
--  Invoke the per-view refresh helpers created in 016 so that
--  mv_threat_summary and mv_campaign_summary reflect the
--  normalised data immediately after this migration runs.
-- ============================================================

DO $$
BEGIN
    PERFORM refresh_mv_threat_summary();
    PERFORM refresh_mv_campaign_summary();
END;
$$;
