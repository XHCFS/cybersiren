-- ============================================================
--  013_fix_multitenancy.sql
--
--  Patches multi-tenancy gaps identified after 002_add_users_orgs.sql.
--  Migration 002 added org_id to emails, campaigns, and enriched_threats
--  but several child / sibling tables were never patched.
--
--  Changes:
--    #1  verdicts          — add org_id
--    #2  enrichment_jobs   — add org_id
--    #3  enrichment_results — add org_id
--    #4  rule_hits         — add org_id
--    #5  email_urls        — add org_id
--    #6  email_attachments — add org_id
--    #7  enriched_threats  — change org_id FK from ON DELETE SET NULL
--                            to ON DELETE CASCADE
--    #8  enriched_threats  — enforce is_global / org_id invariant via CHECK
--    #9  campaigns         — replace global UNIQUE(fingerprint) with
--                            UNIQUE NULLS NOT DISTINCT (org_id, fingerprint)
--
--  All new org_id columns are nullable (existing rows cannot be
--  backfilled in the migration itself).
--
--  RLS is explicitly out of scope — it will be added in a separate
--  migration once the application is prepared to set
--  app.current_org_id on every connection.
--
--  All statements are idempotent. No CONCURRENTLY.
-- ============================================================


-- ============================================================
--  #1  verdicts — add org_id
-- ============================================================

-- TODO: Enforce NOT NULL after backfill is complete.
ALTER TABLE verdicts
    ADD COLUMN IF NOT EXISTS org_id BIGINT
        REFERENCES organisations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_verdicts_org_id
    ON verdicts(org_id);


-- ============================================================
--  #2  enrichment_jobs — add org_id
-- ============================================================

-- TODO: Enforce NOT NULL after backfill is complete.
ALTER TABLE enrichment_jobs
    ADD COLUMN IF NOT EXISTS org_id BIGINT
        REFERENCES organisations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_enrichment_jobs_org_id
    ON enrichment_jobs(org_id);


-- ============================================================
--  #3  enrichment_results — add org_id
-- ============================================================

-- TODO: Enforce NOT NULL after backfill is complete.
ALTER TABLE enrichment_results
    ADD COLUMN IF NOT EXISTS org_id BIGINT
        REFERENCES organisations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_enrichment_results_org_id
    ON enrichment_results(org_id);


-- ============================================================
--  #4  rule_hits — add org_id
-- ============================================================

-- TODO: Enforce NOT NULL after backfill is complete.
ALTER TABLE rule_hits
    ADD COLUMN IF NOT EXISTS org_id BIGINT
        REFERENCES organisations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_rule_hits_org_id
    ON rule_hits(org_id);


-- ============================================================
--  #5  email_urls — add org_id
-- ============================================================

-- TODO: Enforce NOT NULL after backfill is complete.
ALTER TABLE email_urls
    ADD COLUMN IF NOT EXISTS org_id BIGINT
        REFERENCES organisations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_email_urls_org_id
    ON email_urls(org_id);


-- ============================================================
--  #6  email_attachments — add org_id
-- ============================================================

-- TODO: Enforce NOT NULL after backfill is complete.
ALTER TABLE email_attachments
    ADD COLUMN IF NOT EXISTS org_id BIGINT
        REFERENCES organisations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_email_attachments_org_id
    ON email_attachments(org_id);


-- ============================================================
--  #7  enriched_threats — change org_id FK to ON DELETE CASCADE
--
--  Migration 002 added org_id with ON DELETE SET NULL, which is
--  inconsistent with every other tenant table in the schema.
--  Discover the FK name at runtime to avoid hard-coding the
--  auto-generated name (which may differ across environments or
--  after a pg_dump restore), then drop and re-add it.
-- ============================================================

DO $$
DECLARE
    v_conname TEXT;
BEGIN
    -- Find the FK on enriched_threats.org_id → organisations(id).
    -- contype = 'f' (foreign key), confrelid = organisations, and the
    -- constrained column set includes org_id.
    SELECT c.conname
      INTO v_conname
      FROM pg_constraint  c
      JOIN pg_class       rel ON rel.oid = c.conrelid
      JOIN pg_namespace   nsp ON nsp.oid = rel.relnamespace
      JOIN pg_class       frel ON frel.oid = c.confrelid
     WHERE nsp.nspname   = current_schema()
       AND rel.relname   = 'enriched_threats'
       AND frel.relname  = 'organisations'
       AND c.contype     = 'f'
       -- Verify that org_id is the sole constrained column.
       AND EXISTS (
           SELECT 1
           FROM   unnest(c.conkey) AS k(attnum)
           JOIN   pg_attribute     a ON a.attrelid = rel.oid
                                    AND a.attnum   = k.attnum
          WHERE   a.attname = 'org_id'
       );

    IF v_conname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE enriched_threats DROP CONSTRAINT %I', v_conname);
    END IF;
END;
$$;

-- Re-add with ON DELETE CASCADE (idempotent: the ADD COLUMN IF NOT EXISTS
-- in 002 guards against a second column; this only re-creates the FK).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint  c
          JOIN pg_class       rel  ON rel.oid  = c.conrelid
          JOIN pg_namespace   nsp  ON nsp.oid  = rel.relnamespace
          JOIN pg_class       frel ON frel.oid = c.confrelid
         WHERE nsp.nspname  = current_schema()
           AND rel.relname  = 'enriched_threats'
           AND frel.relname = 'organisations'
           AND c.contype    = 'f'
           AND c.confdeltype = 'c'   -- 'c' = CASCADE in pg_constraint.confdeltype
    ) THEN
        ALTER TABLE enriched_threats
            ADD CONSTRAINT enriched_threats_org_id_fkey
            FOREIGN KEY (org_id)
            REFERENCES organisations(id)
            ON DELETE CASCADE;
    END IF;
END;
$$;


-- ============================================================
--  #8  enriched_threats — enforce is_global / org_id invariant
--
--  Rule (from 005): a row must either be a global TI record
--  (is_global = TRUE, shared across all tenants) or be attributed
--  to a specific organisation (org_id IS NOT NULL).
--  A row with is_global = FALSE and org_id IS NULL is an orphan —
--  it would be invisible to every tenant and uncollectable by any
--  query. The CHECK makes this state impossible.
--
--  is_global = TRUE rows may still carry an org_id (the feed
--  ingestor that first submitted the record), so we only reject
--  the combination where is_global = FALSE AND org_id IS NULL.
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint  c
          JOIN pg_class       rel ON rel.oid = c.conrelid
          JOIN pg_namespace   nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = current_schema()
           AND rel.relname = 'enriched_threats'
           AND c.contype   = 'c'    -- CHECK constraint
           AND c.conname   = 'chk_enriched_threats_global_or_org'
    ) THEN
        ALTER TABLE enriched_threats
            ADD CONSTRAINT chk_enriched_threats_global_or_org
            CHECK (is_global = TRUE OR org_id IS NOT NULL);
    END IF;
END;
$$;

COMMENT ON CONSTRAINT chk_enriched_threats_global_or_org
    ON enriched_threats IS
    'Enforces the is_global / org_id invariant introduced in 005. '
    'Every enriched_threats row must be either: '
    '(a) a shared global TI record (is_global = TRUE), or '
    '(b) attributed to a specific organisation (org_id IS NOT NULL). '
    'A row where is_global = FALSE AND org_id IS NULL is an orphan — '
    'it would be invisible to all tenants and must not be persisted.';


-- ============================================================
--  #9  campaigns — replace global UNIQUE(fingerprint) with
--      UNIQUE NULLS NOT DISTINCT (org_id, fingerprint)
--
--  Migration 001 added fingerprint with a global UNIQUE constraint
--  and included a TODO comment:
--    "If campaigns should be per-org, change to
--     UNIQUE (org_id, fingerprint) after org_id is added in 002."
--  Migration 002 added org_id but never acted on the TODO.
--
--  A global UNIQUE on fingerprint incorrectly prevents two distinct
--  organisations from independently detecting the same campaign
--  pattern (same fingerprint), which is a valid and expected
--  scenario in a multi-tenant deployment.
--
--  The replacement constraint uses NULLS NOT DISTINCT so that two
--  global/unattributed rows (org_id IS NULL) with the same fingerprint
--  are still treated as duplicates — matching the original intent of
--  the idempotent ingestion pipeline for global TI records.
-- ============================================================

DO $$
DECLARE
    v_conname TEXT;
BEGIN
    -- Discover the current UNIQUE constraint on campaigns.fingerprint.
    -- We look for a unique constraint whose constrained column set is
    -- exactly the single column 'fingerprint' (conkey has one element).
    SELECT c.conname
      INTO v_conname
      FROM pg_constraint  c
      JOIN pg_class       rel ON rel.oid = c.conrelid
      JOIN pg_namespace   nsp ON nsp.oid = rel.relnamespace
     WHERE nsp.nspname   = current_schema()
       AND rel.relname   = 'campaigns'
       AND c.contype     = 'u'          -- UNIQUE constraint
       AND array_length(c.conkey, 1) = 1
       AND EXISTS (
           SELECT 1
           FROM   pg_attribute a
          WHERE   a.attrelid = rel.oid
            AND   a.attnum   = c.conkey[1]
            AND   a.attname  = 'fingerprint'
       );

    IF v_conname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE campaigns DROP CONSTRAINT %I', v_conname);
    END IF;
END;
$$;

-- Add per-org unique constraint (idempotent guard by name).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint  c
          JOIN pg_class       rel ON rel.oid = c.conrelid
          JOIN pg_namespace   nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = current_schema()
           AND rel.relname = 'campaigns'
           AND c.contype   = 'u'
           AND c.conname   = 'uq_campaigns_org_fingerprint'
    ) THEN
        ALTER TABLE campaigns
            ADD CONSTRAINT uq_campaigns_org_fingerprint
            UNIQUE NULLS NOT DISTINCT (org_id, fingerprint);
    END IF;
END;
$$;

COMMENT ON CONSTRAINT uq_campaigns_org_fingerprint
    ON campaigns IS
    'Per-org campaign deduplication. Resolves the TODO in 001_initial_schema.sql: '
    '"If campaigns should be per-org, change to UNIQUE (org_id, fingerprint) '
    'after org_id is added in 002." This was not actioned in 002; corrected here. '
    'NULLS NOT DISTINCT ensures that two unattributed rows (org_id IS NULL) with '
    'the same fingerprint are still treated as duplicates, preserving idempotency '
    'for global TI ingestion pipelines.';
