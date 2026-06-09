-- ============================================================
--  031_add_app_role.sql
--  Non-bypass application login role for real RLS enforcement.
--
--  Depends on: 018_add_rls.sql (FORCE RLS + tenant_isolation /
--  migration_bypass policies on every tenant table).
--
--  Why: migration 018 forces RLS, but every service still connects
--  as the superuser `postgres`, which BYPASSes RLS entirely — so the
--  tenant_isolation policies were never actually enforced at runtime.
--  This role is a NON-superuser, NOBYPASSRLS login that IS subject to
--  the policies, so a connection that does not first
--  `SET LOCAL app.current_org_id` sees zero tenant rows. The Go data
--  layer (shared/postgres/repository: WithOrgTx / SetOrgGUC) sets the
--  GUC on every tenant-scoped tx; this role makes that mandatory
--  instead of optional.
--
--  Migrations and maintenance keep running as `postgres` (superuser,
--  bypasses RLS). This role is NOT granted migration_role, so it does
--  NOT get the migration_bypass policy — it is a pure tenant client.
--
--  DEV CREDENTIAL: the password below is a local/compose development
--  secret only (mirrors POSTGRES_PASSWORD=postgres in deploy/compose).
--  Production secret handling is tracked with the compose JWT-secret
--  removal in the P8 hardening pass.
--
--  All statements are idempotent.
-- ============================================================

-- ── ROLE ────────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cybersiren_app') THEN
        CREATE ROLE cybersiren_app LOGIN NOBYPASSRLS PASSWORD 'cybersiren_app';
    ELSE
        -- Ensure an existing role has the security-relevant attributes.
        ALTER ROLE cybersiren_app LOGIN NOBYPASSRLS;
    END IF;
END;
$$;

-- ── GRANTS ──────────────────────────────────────────────────
-- CONNECT is granted to PUBLIC by default; grant it explicitly against
-- whatever database this migration runs in (do NOT hardcode the name, so a
-- renamed dev/demo DB still applies cleanly).
DO $$
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO cybersiren_app', current_database());
END;
$$;
GRANT USAGE ON SCHEMA public TO cybersiren_app;

-- DML on all current tables (incl. non-RLS organisations, which the
-- app role inserts/reads directly), plus sequence access for the
-- BIGSERIAL surrogate keys (emails.internal_id, etc.).
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO cybersiren_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO cybersiren_app;

-- Same DML on objects created by future migrations. Default privileges are
-- keyed to the role that CREATES the object — i.e. whoever runs the migrations.
-- That is `postgres` in compose, but a differently-named superuser in CI
-- (POSTGRES_USER=cybersiren) and in managed Postgres. Bind to current_user (the
-- migrating role) instead of a hardcoded 'postgres', so the grants attach to
-- future tables regardless of the migration role's name. Hardcoding 'postgres'
-- makes this migration fail with `role "postgres" does not exist` anywhere the
-- superuser is named otherwise. Same do-not-hardcode rationale as the CONNECT
-- grant above; the format()/%I pattern guarantees the keyword resolves.
DO $$
BEGIN
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
        'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO cybersiren_app',
        current_user);
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
        'GRANT USAGE, SELECT ON SEQUENCES TO cybersiren_app',
        current_user);
END;
$$;
