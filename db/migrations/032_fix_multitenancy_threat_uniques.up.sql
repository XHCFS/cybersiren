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

-- Pre-flight guard: ADD CONSTRAINT ... UNIQUE NULLS NOT DISTINCT aborts the
-- whole migration mid-apply if the table already holds two rows colliding on
-- (org_id, url). On the normal upgrade path that is impossible — the global
-- UNIQUE(url) just dropped above made every url unique table-wide, so the
-- per-org key cannot collide. This guard exists so a DB whose 001 constraint
-- was dropped out-of-band fails LOUDLY with an actionable message instead of a
-- raw 23505 from the ADD. GROUP BY folds NULL org_id rows into one group,
-- matching the NULLS NOT DISTINCT semantics of the new constraint.
DO $$
DECLARE
    v_dupes BIGINT;
BEGIN
    SELECT count(*) INTO v_dupes
      FROM (
          SELECT 1
            FROM enriched_threats
        GROUP BY org_id, url
          HAVING count(*) > 1
      ) d;
    IF v_dupes > 0 THEN
        RAISE EXCEPTION
            'cannot add uq_enriched_threats_org_url: % (org_id, url) group(s) already '
            'violate per-org uniqueness; dedupe enriched_threats before applying 032',
            v_dupes;
    END IF;
END;
$$;

-- Note on soft-deletes: this is a table constraint over LIVE + soft-deleted
-- (deleted_at IS NOT NULL) rows, NOT a partial index. So a soft-deleted row for
-- (org_id, url) still participates: the bare UPSERT's ON CONFLICT (org_id, url)
-- refreshes/resurrects it rather than inserting a fresh row. That is intentional
-- and mirrors the campaigns fix (013 #9). A partial UNIQUE ... WHERE deleted_at
-- IS NULL is deliberately NOT used: the ON CONFLICT in db/queries does not carry
-- the predicate, so inference would break.
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

-- No pre-flight dupe guard here (unlike enriched_threats): the new key
-- (org_id, entity_type, entity_id, provider) PREPENDS a column to the old global
-- UNIQUE(entity_type, entity_id, provider), so it is strictly LOOSER — any data
-- that satisfied the old constraint trivially satisfies the new one. The ADD
-- cannot fail on existing rows. Soft-delete semantics match enriched_threats above.
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
