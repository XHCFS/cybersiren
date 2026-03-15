-- ============================================================
--  018_add_rls.sql
--  Row-Level Security for tenant isolation.
--
--  Depends on: 013_fix_multitenancy.sql (all tables have org_id).
-- ============================================================
--
--  ╔══════════════════════════════════════════════════════════╗
--  ║  WARNING — READ BEFORE APPLYING                         ║
--  ║                                                         ║
--  ║  DO NOT APPLY this migration until the application      ║
--  ║  unconditionally sets app.current_org_id on every       ║
--  ║  connection.  Applying it prematurely will lock out     ║
--  ║  all application queries.                               ║
--  ║                                                         ║
--  ║  The Go layer must execute:                             ║
--  ║    SET LOCAL app.current_org_id = $1                    ║
--  ║  at the start of every transaction / connection before  ║
--  ║  any tenant-scoped query.                               ║
--  ╚══════════════════════════════════════════════════════════╝
--
--  All statements are idempotent (guarded by DO blocks).
-- ============================================================


-- ============================================================
--  HELPER: reusable DO-block template
--
--  For each table we:
--    1. ALTER TABLE … ENABLE ROW LEVEL SECURITY;
--    2. ALTER TABLE … FORCE ROW LEVEL SECURITY;
--       (so the table owner is also subject to policies during
--        testing.  Relax this for migrations and maintenance
--        scripts that run as the table-owner role by either
--        removing the FORCE or connecting as a superuser.)
--    3. CREATE POLICY tenant_isolation … USING (…);
--    4. CREATE POLICY migration_bypass … TO migration_role
--       USING (TRUE);
--       (The DBA must "CREATE ROLE migration_role" and grant it
--        to whatever role runs migrations / maintenance.)
-- ============================================================


-- ============================================================
--  ROLE: migration_role
--
--  Used by the bypass policy on every table.
--  The DBA must grant this role to the actual migration /
--  maintenance user, e.g.:
--    GRANT migration_role TO my_migration_user;
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'migration_role'
    ) THEN
        CREATE ROLE migration_role NOLOGIN;
    END IF;
END;
$$;


-- ============================================================
--  1. emails
-- ============================================================

ALTER TABLE emails ENABLE ROW LEVEL SECURITY;

-- FORCE RLS so the table owner is also subject to policies
-- during testing.  May need to be relaxed for migrations and
-- maintenance scripts running as the owner role.
ALTER TABLE emails FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename  = 'emails'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON emails
            USING (
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
          AND tablename  = 'emails'
          AND policyname = 'migration_bypass'
    ) THEN
        CREATE POLICY migration_bypass ON emails
            TO migration_role
            USING (TRUE);
    END IF;
END;
$$;


-- ============================================================
--  2. verdicts
-- ============================================================

ALTER TABLE verdicts ENABLE ROW LEVEL SECURITY;
ALTER TABLE verdicts FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename  = 'verdicts'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON verdicts
            USING (
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
          AND tablename  = 'verdicts'
          AND policyname = 'migration_bypass'
    ) THEN
        CREATE POLICY migration_bypass ON verdicts
            TO migration_role
            USING (TRUE);
    END IF;
END;
$$;


-- ============================================================
--  3. campaigns
-- ============================================================

ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaigns FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename  = 'campaigns'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON campaigns
            USING (
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
          AND tablename  = 'campaigns'
          AND policyname = 'migration_bypass'
    ) THEN
        CREATE POLICY migration_bypass ON campaigns
            TO migration_role
            USING (TRUE);
    END IF;
END;
$$;


-- ============================================================
--  4. enrichment_jobs
-- ============================================================

ALTER TABLE enrichment_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrichment_jobs FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename  = 'enrichment_jobs'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON enrichment_jobs
            USING (
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
          AND tablename  = 'enrichment_jobs'
          AND policyname = 'migration_bypass'
    ) THEN
        CREATE POLICY migration_bypass ON enrichment_jobs
            TO migration_role
            USING (TRUE);
    END IF;
END;
$$;


-- ============================================================
--  5. enrichment_results
-- ============================================================

ALTER TABLE enrichment_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrichment_results FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename  = 'enrichment_results'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON enrichment_results
            USING (
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
          AND tablename  = 'enrichment_results'
          AND policyname = 'migration_bypass'
    ) THEN
        CREATE POLICY migration_bypass ON enrichment_results
            TO migration_role
            USING (TRUE);
    END IF;
END;
$$;


-- ============================================================
--  6. rule_hits
-- ============================================================

ALTER TABLE rule_hits ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_hits FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename  = 'rule_hits'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON rule_hits
            USING (
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
          AND tablename  = 'rule_hits'
          AND policyname = 'migration_bypass'
    ) THEN
        CREATE POLICY migration_bypass ON rule_hits
            TO migration_role
            USING (TRUE);
    END IF;
END;
$$;


-- ============================================================
--  7. email_urls
-- ============================================================

ALTER TABLE email_urls ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_urls FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename  = 'email_urls'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON email_urls
            USING (
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
          AND tablename  = 'email_urls'
          AND policyname = 'migration_bypass'
    ) THEN
        CREATE POLICY migration_bypass ON email_urls
            TO migration_role
            USING (TRUE);
    END IF;
END;
$$;


-- ============================================================
--  8. email_attachments
-- ============================================================

ALTER TABLE email_attachments ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_attachments FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename  = 'email_attachments'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON email_attachments
            USING (
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
          AND tablename  = 'email_attachments'
          AND policyname = 'migration_bypass'
    ) THEN
        CREATE POLICY migration_bypass ON email_attachments
            TO migration_role
            USING (TRUE);
    END IF;
END;
$$;


-- ============================================================
--  9. rules
-- ============================================================

ALTER TABLE rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE rules FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename  = 'rules'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON rules
            USING (
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
          AND tablename  = 'rules'
          AND policyname = 'migration_bypass'
    ) THEN
        CREATE POLICY migration_bypass ON rules
            TO migration_role
            USING (TRUE);
    END IF;
END;
$$;


-- ============================================================
--  10. audit_log
-- ============================================================

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename  = 'audit_log'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON audit_log
            USING (
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
          AND tablename  = 'audit_log'
          AND policyname = 'migration_bypass'
    ) THEN
        CREATE POLICY migration_bypass ON audit_log
            TO migration_role
            USING (TRUE);
    END IF;
END;
$$;


-- ============================================================
--  11. email_recipients  (added in 008)
-- ============================================================

ALTER TABLE email_recipients ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_recipients FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename  = 'email_recipients'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON email_recipients
            USING (
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
          AND tablename  = 'email_recipients'
          AND policyname = 'migration_bypass'
    ) THEN
        CREATE POLICY migration_bypass ON email_recipients
            TO migration_role
            USING (TRUE);
    END IF;
END;
$$;


-- ============================================================
--  12. enriched_threats  (special: global rows visible to all)
--
--  enriched_threats has both org-scoped and global rows
--  (is_global = TRUE).  Global rows should be visible to all
--  authenticated tenants.  The policy allows access when:
--    - The GUC is set (deny everything if not), AND
--    - Either the row is global, OR the org_id matches.
-- ============================================================

ALTER TABLE enriched_threats ENABLE ROW LEVEL SECURITY;
ALTER TABLE enriched_threats FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename  = 'enriched_threats'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON enriched_threats
            USING (
                current_setting('app.current_org_id', TRUE) IS NOT NULL
                AND (
                    is_global = TRUE
                    OR org_id = current_setting('app.current_org_id', TRUE)::BIGINT
                )
            );
    END IF;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename  = 'enriched_threats'
          AND policyname = 'migration_bypass'
    ) THEN
        CREATE POLICY migration_bypass ON enriched_threats
            TO migration_role
            USING (TRUE);
    END IF;
END;
$$;
