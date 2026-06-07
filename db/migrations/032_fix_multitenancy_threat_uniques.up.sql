-- ============================================================
--  032_fix_multitenancy_threat_uniques.sql
--  Per-org UNIQUE constraints for enriched_threats + enrichment_results.
--
--  Depends on: 001 (enriched_threats.url global UNIQUE,
--  enrichment_results UNIQUE(entity_type,entity_id,provider)),
--  013 (#3 enrichment_results.org_id, #8 enriched_threats org_id
--  invariant CHECK, #9 the SAME fix applied to campaigns), and 018
--  (FORCE ROW LEVEL SECURITY on both tables).
--
--  Why: both tables carry a GLOBAL UNIQUE (enriched_threats.url;
--  enrichment_results(entity_type,entity_id,provider)) while being
--  per-org RLS-forced (migration 018, tenant_isolation). That is the
--  exact contradiction migration 013 #9 already fixed for campaigns:
--  a global UNIQUE prevents two tenants from independently recording
--  the same artefact, and — once the app connects as the non-bypass
--  cybersiren_app role (031) — an INSERT … ON CONFLICT from org B that
--  conflicts with org A's row tries to UPDATE a row org B's RLS policy
--  hides, so the statement errors and the whole parse/enrich tx rolls
--  back. The per-org UPSERTs in db/queries/{enriched_threats,
--  enrichment_results}.sql cannot work against a global UNIQUE.
--
--  Fix (mirrors 013 #9 for campaigns): drop the global UNIQUE and add
--  a per-org UNIQUE NULLS NOT DISTINCT, so each org gets its own row
--  for the same url / entity and global (org_id IS NULL) rows still
--  dedupe. The queries' ON CONFLICT targets move to the org-scoped key.
--
--  All statements are idempotent (dynamic constraint discovery for the
--  drop, name guard for the add — same pattern as 013).
-- ============================================================


-- ── enriched_threats: global UNIQUE(url) → per-org UNIQUE(org_id, url) ──
DO $$
DECLARE
    v_conname TEXT;
BEGIN
    -- Discover the global UNIQUE whose constrained column set is exactly
    -- the single column 'url' (the auto-named enriched_threats_url_key).
    SELECT c.conname
      INTO v_conname
      FROM pg_constraint  c
      JOIN pg_class       rel ON rel.oid = c.conrelid
      JOIN pg_namespace   nsp ON nsp.oid = rel.relnamespace
     WHERE nsp.nspname = current_schema()
       AND rel.relname = 'enriched_threats'
       AND c.contype   = 'u'
       AND array_length(c.conkey, 1) = 1
       AND EXISTS (
           SELECT 1
           FROM   pg_attribute a
          WHERE   a.attrelid = rel.oid
            AND   a.attnum   = c.conkey[1]
            AND   a.attname  = 'url'
       );

    IF v_conname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE enriched_threats DROP CONSTRAINT %I', v_conname);
    END IF;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint  c
          JOIN pg_class       rel ON rel.oid = c.conrelid
          JOIN pg_namespace   nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = current_schema()
           AND rel.relname = 'enriched_threats'
           AND c.contype   = 'u'
           AND c.conname   = 'uq_enriched_threats_org_url'
    ) THEN
        ALTER TABLE enriched_threats
            ADD CONSTRAINT uq_enriched_threats_org_url
            UNIQUE NULLS NOT DISTINCT (org_id, url);
    END IF;
END;
$$;

COMMENT ON CONSTRAINT uq_enriched_threats_org_url ON enriched_threats IS
    'Per-org uniqueness for email-observed URL artefacts (replaces the global '
    'UNIQUE(url) from 001, which is incompatible with the per-org RLS policy in '
    '018 — see 032 / 013 #9). NULLS NOT DISTINCT keeps global (org_id IS NULL) '
    'rows deduped. SVC-02''s bare UPSERT conflicts on (org_id, url).';


-- ── enrichment_results: global UNIQUE(entity_type,entity_id,provider)
--    → per-org UNIQUE(org_id, entity_type, entity_id, provider) ──
DO $$
DECLARE
    v_conname TEXT;
BEGIN
    -- Discover the global UNIQUE on (entity_type, entity_id, provider).
    SELECT c.conname
      INTO v_conname
      FROM pg_constraint c
     WHERE c.conrelid = 'enrichment_results'::regclass
       AND c.contype  = 'u'
       AND pg_get_constraintdef(c.oid) ILIKE '%entity_type%'
       AND pg_get_constraintdef(c.oid) ILIKE '%provider%'
       AND array_length(c.conkey, 1) = 3;

    IF v_conname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE enrichment_results DROP CONSTRAINT %I', v_conname);
    END IF;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint c
         WHERE c.conrelid = 'enrichment_results'::regclass
           AND c.contype  = 'u'
           AND c.conname   = 'uq_enrichment_results_org_entity_provider'
    ) THEN
        ALTER TABLE enrichment_results
            ADD CONSTRAINT uq_enrichment_results_org_entity_provider
            UNIQUE NULLS NOT DISTINCT (org_id, entity_type, entity_id, provider);
    END IF;
END;
$$;

COMMENT ON CONSTRAINT uq_enrichment_results_org_entity_provider ON enrichment_results IS
    'Per-org uniqueness for the third-party enrichment cache (replaces the global '
    'UNIQUE(entity_type,entity_id,provider) from 001, incompatible with the per-org '
    'RLS policy in 018 — see 032). Each org caches its own provider lookups; the '
    'UPSERT conflicts on (org_id, entity_type, entity_id, provider).';
