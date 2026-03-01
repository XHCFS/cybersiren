-- ============================================================
--  023_fix_constraint_gaps.sql
--
--  Adds missing CHECK constraints and validation to columns
--  that currently accept arbitrary / malformed input.
--
--  Changes:
--    #19  emails.sent_timestamp    — range CHECK (NOT VALID)
--    #20  api_keys.scopes          — reference table + trigger
--    #23  organisations.slug       — URL-safe format CHECK
--    #24  api_keys.key_prefix      — length CHECK
--    #25  feeds.reliability_weight — upper-bound CHECK
--    #26  campaigns.name           — NOT NULL
--
--  All statements idempotent.  No CONCURRENTLY.
-- ============================================================


-- ============================================================
--  #19  emails.sent_timestamp — range CHECK
--
--  sent_timestamp is a raw Unix epoch from email headers.
--  Without a range guard, negative values, impossibly large
--  values, and epoch-zero (1970-01-01 00:00 UTC) are all
--  silently accepted.
--
--  The CHECK allows NULL (header missing / unparseable) and
--  non-negative values up to 4102444800 (2100-01-01 00:00 UTC).
--  Zero is permitted — it represents a legitimate (if unlikely)
--  header value of "Thu, 01 Jan 1970 00:00:00 +0000".
--
--  NOT VALID: existing rows are not scanned.  Once historical
--  data has been audited, run:
--    ALTER TABLE emails
--        VALIDATE CONSTRAINT chk_emails_sent_timestamp_range;
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_constraint  c
        JOIN   pg_class       rel ON rel.oid = c.conrelid
        JOIN   pg_namespace   nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = current_schema()
           AND rel.relname = 'emails'
           AND c.contype   = 'c'
           AND c.conname   = 'chk_emails_sent_timestamp_range'
    ) THEN
        ALTER TABLE emails
            ADD CONSTRAINT chk_emails_sent_timestamp_range
            CHECK (
                sent_timestamp IS NULL
                OR sent_timestamp BETWEEN 0 AND 4102444800
            )
            NOT VALID;
    END IF;
END;
$$;

COMMENT ON COLUMN emails.sent_timestamp IS
    'Raw Unix epoch extracted from the email Date header. '
    'Kept as BIGINT (not TIMESTAMPTZ) to preserve the original value '
    'verbatim, including edge-case headers that carry epoch-zero. '
    'Semantics: '
    '  NULL  — header missing or unparseable. '
    '  0     — epoch-zero (1970-01-01 00:00 UTC). '
    '  > 0   — normal timestamp. '
    'Constraint chk_emails_sent_timestamp_range rejects negative values '
    'and values beyond 2100-01-01 00:00 UTC (4102444800). '
    'Use emails.sent_at (added in 024) for TIMESTAMPTZ queries.';


-- ============================================================
--  #20  api_keys.scopes — reference table + validation trigger
--
--  scopes TEXT[] accepts arbitrary strings with no allowlist.
--  A typo like 'emal:read' silently grants nothing (or silently
--  passes a permissive check).
--
--  Fix: a valid_api_scopes reference table (same pattern as
--  threat_type_values in 020) and a BEFORE INSERT OR UPDATE
--  trigger that rejects unknown scope strings.
-- ============================================================

CREATE TABLE IF NOT EXISTS valid_api_scopes (
    value TEXT PRIMARY KEY
);

COMMENT ON TABLE valid_api_scopes IS
    'Canonical set of allowed API key scope strings.  '
    'The trg_validate_api_key_scopes trigger on api_keys rejects any '
    'scope value not present in this table.  '
    'To add a new scope, INSERT INTO valid_api_scopes(value) VALUES '
    '(''resource:action'') before creating keys that use it.';

-- Seed canonical scopes (idempotent via ON CONFLICT DO NOTHING).
INSERT INTO valid_api_scopes (value) VALUES
    ('email:read'),
    ('email:write'),
    ('verdict:read'),
    ('verdict:write'),
    ('threat:read'),
    ('threat:write'),
    ('campaign:read'),
    ('campaign:write'),
    ('rule:read'),
    ('rule:write'),
    ('feed:read'),
    ('feed:write'),
    ('attachment:read'),
    ('attachment:write'),
    ('admin:org'),
    ('admin:users'),
    ('admin:api_keys')
ON CONFLICT (value) DO NOTHING;


-- Trigger function: validates every element in scopes[].
CREATE OR REPLACE FUNCTION fn_validate_api_key_scopes()
RETURNS TRIGGER AS $$
DECLARE
    v_invalid TEXT[];
BEGIN
    -- Allow empty scopes array (key with no permissions).
    IF NEW.scopes IS NULL OR array_length(NEW.scopes, 1) IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT array_agg(s ORDER BY s)
      INTO v_invalid
      FROM unnest(NEW.scopes) AS s
     WHERE s NOT IN (SELECT value FROM valid_api_scopes);

    IF v_invalid IS NOT NULL THEN
        RAISE EXCEPTION
            'Invalid API key scope(s): %.  '
            'INSERT INTO valid_api_scopes(value) VALUES (''...'') first.',
            array_to_string(v_invalid, ', ');
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION fn_validate_api_key_scopes() IS
    'BEFORE INSERT OR UPDATE trigger function that validates every element '
    'in api_keys.scopes[] against the valid_api_scopes reference table.  '
    'Rejects the operation with a descriptive error if any unknown scope '
    'is found.';

DROP TRIGGER IF EXISTS trg_validate_api_key_scopes ON api_keys;
CREATE TRIGGER trg_validate_api_key_scopes
    BEFORE INSERT OR UPDATE OF scopes ON api_keys
    FOR EACH ROW
    EXECUTE FUNCTION fn_validate_api_key_scopes();


-- ============================================================
--  #23  organisations.slug — URL-safe format CHECK
--
--  slug is described as "URL-safe identifier, e.g. acme-corp",
--  but nothing enforces that format.  Spaces, unicode, and
--  special characters that would break URLs are all accepted.
--
--  The CHECK enforces: lowercase ASCII alphanumerics and hyphens,
--  no leading/trailing hyphens, minimum 1 character.
--  Examples:  'acme-corp' ✓   'a1' ✓   '-bad' ✗   'Bad' ✗
--
--  NOT VALID: existing rows may violate the format and must be
--  corrected before running VALIDATE CONSTRAINT.
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_constraint  c
        JOIN   pg_class       rel ON rel.oid = c.conrelid
        JOIN   pg_namespace   nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = current_schema()
           AND rel.relname = 'organisations'
           AND c.contype   = 'c'
           AND c.conname   = 'chk_organisations_slug_format'
    ) THEN
        ALTER TABLE organisations
            ADD CONSTRAINT chk_organisations_slug_format
            CHECK (slug ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$')
            NOT VALID;
    END IF;
END;
$$;

COMMENT ON COLUMN organisations.slug IS
    'URL-safe identifier used in API paths, e.g. "acme-corp".  '
    'Format: lowercase ASCII alphanumerics and hyphens only, no '
    'leading or trailing hyphens, at least 1 character.  '
    'Constraint chk_organisations_slug_format enforces this on new rows.  '
    'TODO: After auditing existing data, run: '
    '  ALTER TABLE organisations '
    '      VALIDATE CONSTRAINT chk_organisations_slug_format;';


-- ============================================================
--  #24  api_keys.key_prefix — length CHECK
--
--  Comment in 002 says "First 8 chars of raw key" but nothing
--  enforces that the stored prefix is exactly 8 characters.
--
--  NOT VALID: any existing rows with non-8-char prefixes must be
--  corrected before VALIDATE CONSTRAINT.
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_constraint  c
        JOIN   pg_class       rel ON rel.oid = c.conrelid
        JOIN   pg_namespace   nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = current_schema()
           AND rel.relname = 'api_keys'
           AND c.contype   = 'c'
           AND c.conname   = 'chk_api_keys_key_prefix_length'
    ) THEN
        ALTER TABLE api_keys
            ADD CONSTRAINT chk_api_keys_key_prefix_length
            CHECK (length(key_prefix) = 8)
            NOT VALID;
    END IF;
END;
$$;

COMMENT ON COLUMN api_keys.key_prefix IS
    'First 8 characters of the raw API key, stored for identification '
    'purposes (e.g. "cs_live_ab12").  The full key is never stored — '
    'only key_hash is persisted for authentication.  '
    'Constraint chk_api_keys_key_prefix_length enforces exactly 8 characters.';


-- ============================================================
--  #25  feeds.reliability_weight — upper-bound CHECK
--
--  reliability_weight defaults to 1.0 and has no upper bound.
--  An absurdly large value (e.g. 999999) would dominate all
--  other feeds in score aggregation.
--
--  The CHECK constrains the range to [0.0, 10.0], allowing a
--  10× weight multiplier over the default — well beyond any
--  legitimate tuning need.
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_constraint  c
        JOIN   pg_class       rel ON rel.oid = c.conrelid
        JOIN   pg_namespace   nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = current_schema()
           AND rel.relname = 'feeds'
           AND c.contype   = 'c'
           AND c.conname   = 'chk_feeds_reliability_weight_range'
    ) THEN
        ALTER TABLE feeds
            ADD CONSTRAINT chk_feeds_reliability_weight_range
            CHECK (reliability_weight BETWEEN 0.0 AND 10.0);
    END IF;
END;
$$;

COMMENT ON COLUMN feeds.reliability_weight IS
    'Weight applied when aggregating scores from multiple feeds. '
    'Higher = more trusted source.  Default 1.0; maximum 10.0.  '
    'Constraint chk_feeds_reliability_weight_range prevents values '
    'outside [0.0, 10.0] from dominating the aggregation.';


-- ============================================================
--  #26  campaigns.name — NOT NULL
--
--  campaigns.name was nullable with no documented reason.
--  Every campaign should have a human-readable name for
--  analyst-facing UIs and reports.
--
--  Existing NULLs are back-filled to 'Unnamed Campaign #<id>'
--  before the NOT NULL constraint is applied.
-- ============================================================

UPDATE campaigns
   SET name = 'Unnamed Campaign #' || id
 WHERE name IS NULL;

ALTER TABLE campaigns ALTER COLUMN name SET NOT NULL;

COMMENT ON COLUMN campaigns.name IS
    'Human-readable campaign name displayed in dashboards and reports.  '
    'NOT NULL since migration 023.  Pre-existing NULL values were '
    'back-filled to ''Unnamed Campaign #<id>''.';
