-- ============================================================
--  033_rls_email_url_ti_matches.sql
--  Make email_url_ti_matches a first-class tenant table (org_id + RLS).
--
--  Depends on: 026 (email_url_ti_matches table), 018 (RLS pattern +
--  migration_role / migration_bypass), 002 (organisations).
--
--  Why: 026 created email_url_ti_matches as a junction/audit table with
--  NO org_id column and NO row-level security. The Go data layer
--  (shared/postgres/repository.URLRepository.RecordTIMatch) nonetheless
--  wraps its writes in WithOrgTx, which sets app.current_org_id — but a
--  GUC is a no-op on a table that has no policy, so the wrapper implied a
--  tenant isolation it never enforced. email_url_id is an enumerable
--  BIGSERIAL, so a caller (or a future bug) handed a foreign tenant's
--  email_url_id could read/write that tenant's TI-match rows.
--
--  Fix: give the table its own org_id (backfilled from the parent
--  email_urls row), FORCE RLS, and a tenant_isolation policy mirroring
--  email_urls (018 #7) — but with an explicit WITH CHECK so a write whose
--  org_id disagrees with the GUC is rejected at insert time, not merely
--  filtered on read. The query (db/queries/email_url_ti_matches.sql)
--  derives org_id from the parent email_urls row under RLS, so it is
--  structurally impossible to attach a match to a URL the caller's org
--  cannot see.
--
--  All statements are idempotent.
-- ============================================================

-- ── COLUMN ──────────────────────────────────────────────────
-- Nullable first so the backfill can run; tightened to NOT NULL below.
ALTER TABLE email_url_ti_matches
    ADD COLUMN IF NOT EXISTS org_id BIGINT
        REFERENCES organisations(id) ON DELETE CASCADE;

-- ── BACKFILL ────────────────────────────────────────────────
-- Every match row belongs to exactly the org of its parent email_urls row.
UPDATE email_url_ti_matches m
   SET org_id = eu.org_id
  FROM email_urls eu
 WHERE eu.id = m.email_url_id
   AND m.org_id IS DISTINCT FROM eu.org_id;

-- Tighten to NOT NULL. If any row still has a NULL org_id (an orphan whose
-- parent email_urls.org_id is itself NULL), this fails loudly — which is the
-- correct outcome: such a row is unattributable and must be fixed by hand.
ALTER TABLE email_url_ti_matches
    ALTER COLUMN org_id SET NOT NULL;

-- Index the RLS predicate column (point lookups already use email_url_id).
CREATE INDEX IF NOT EXISTS idx_eu_ti_matches_org_id
    ON email_url_ti_matches(org_id);

COMMENT ON COLUMN email_url_ti_matches.org_id IS
    'Owning tenant, mirrored from the parent email_urls row. Drives the '
    'tenant_isolation RLS policy (033). NOT NULL: every match is org-scoped.';

-- ── RLS ─────────────────────────────────────────────────────
ALTER TABLE email_url_ti_matches ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_url_ti_matches FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename  = 'email_url_ti_matches'
          AND policyname = 'tenant_isolation'
    ) THEN
        -- USING gates reads/updates/deletes; WITH CHECK gates the org_id of
        -- rows being written, so an INSERT/UPDATE cannot smuggle in another
        -- tenant's org_id even though the same GUC is set.
        CREATE POLICY tenant_isolation ON email_url_ti_matches
            USING (
                current_setting('app.current_org_id', TRUE) IS NOT NULL
                AND org_id IS NOT NULL
                AND org_id = current_setting('app.current_org_id', TRUE)::BIGINT
            )
            WITH CHECK (
                current_setting('app.current_org_id', TRUE) IS NOT NULL
                AND org_id IS NOT NULL
                AND org_id = current_setting('app.current_org_id', TRUE)::BIGINT
            );
    END IF;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename  = 'email_url_ti_matches'
          AND policyname = 'migration_bypass'
    ) THEN
        CREATE POLICY migration_bypass ON email_url_ti_matches
            TO migration_role
            USING (TRUE)
            WITH CHECK (TRUE);
    END IF;
END;
$$;
