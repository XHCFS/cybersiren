-- ============================================================
--  002_add_users_orgs.sql
--  Adds multi-tenancy, user accounts, roles, and API keys.
--  Patches tenant_id onto core tables from 001.
-- ============================================================


-- ============================================================
--  ORGANISATIONS
-- ============================================================

CREATE TABLE IF NOT EXISTS organisations (
    id BIGSERIAL PRIMARY KEY,

    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,  -- URL-safe identifier, e.g. "acme-corp"

    -- Soft cap on monthly email ingestion. NULL = unlimited.
    -- TODO: once all rows are backfilled, enforce NOT NULL on org_id.
    monthly_ingestion_limit INT,

    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_orgs_slug ON organisations(slug);
CREATE INDEX IF NOT EXISTS idx_orgs_active ON organisations(deleted_at) WHERE deleted_at IS NULL;


-- ============================================================
--  USERS
-- ============================================================

CREATE TYPE user_role AS ENUM (
    'admin',    -- Full org access, manages users and API keys
    'analyst',  -- Can review emails and submit verdicts
    'viewer'    -- Read-only
);

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    org_id BIGINT NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,

    email TEXT NOT NULL,
    display_name TEXT,
    role user_role NOT NULL DEFAULT 'viewer',

    -- Hashed with bcrypt/argon2 in the Go layer. NULL if SSO-only.
    password_hash TEXT,

    last_login_at TIMESTAMPTZ,

    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (org_id, email)
);

CREATE INDEX IF NOT EXISTS idx_users_org_id ON users(org_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(deleted_at) WHERE deleted_at IS NULL;


-- ============================================================
--  API KEYS
--
--  Used by the Go service for programmatic access.
--  The raw key is shown once at creation and never stored.
--  key_hash is what gets persisted and checked at auth time.
-- ============================================================

CREATE TABLE IF NOT EXISTS api_keys (
    id BIGSERIAL PRIMARY KEY,
    org_id BIGINT NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,

    -- NULL = org-level key not tied to a specific user
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,

    name TEXT NOT NULL,         -- Human label, e.g. "Go ingestion service"
    key_prefix TEXT NOT NULL,   -- First 8 chars of raw key, for identification (e.g. "cs_live_ab12")
    key_hash TEXT NOT NULL UNIQUE,

    -- Comma-separated or use TEXT[] — defines what this key can do
    scopes TEXT[] NOT NULL DEFAULT '{}',

    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,     -- NULL = never expires

    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_api_keys_org_id ON api_keys(org_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(revoked_at) WHERE revoked_at IS NULL;


-- ============================================================
--  PATCH 001 TABLES WITH tenant_id
--
--  All core tables get org_id so rows are strictly isolated
--  per tenant. Existing rows (if any) are left with NULL and
--  should be backfilled before adding NOT NULL constraints.
--
--  TODO: Once backfill is complete, enforce NOT NULL:
--    ALTER TABLE emails ALTER COLUMN org_id SET NOT NULL;
--    ALTER TABLE campaigns ALTER COLUMN org_id SET NOT NULL;
-- ============================================================

ALTER TABLE emails
    ADD COLUMN IF NOT EXISTS org_id BIGINT REFERENCES organisations(id) ON DELETE CASCADE;

ALTER TABLE campaigns
    ADD COLUMN IF NOT EXISTS org_id BIGINT REFERENCES organisations(id) ON DELETE CASCADE;

-- enriched_threats is global threat intel shared across tenants,
-- but source attribution is still per-org.
ALTER TABLE enriched_threats
    ADD COLUMN IF NOT EXISTS org_id BIGINT REFERENCES organisations(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_emails_org_id ON emails(org_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_org_id ON campaigns(org_id);
CREATE INDEX IF NOT EXISTS idx_enriched_org_id ON enriched_threats(org_id);


-- ============================================================
--  PATCH verdicts TO TRACK ANALYST IDENTITY
--
--  created_by is NULL for model/rule/feed verdicts.
-- ============================================================

ALTER TABLE verdicts
    ADD COLUMN IF NOT EXISTS created_by BIGINT REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_verdicts_created_by ON verdicts(created_by);


-- ============================================================
--  MESSAGE_ID UNIQUENESS
--
--  Prevents duplicate ingestion (retries, duplicate delivery)
--  from silently creating duplicate email rows.
--  Scoped per org because Message-IDs are not globally unique.
-- ============================================================

ALTER TABLE emails
    ADD CONSTRAINT uq_emails_org_message_id UNIQUE (org_id, message_id, fetched_at);


-- ============================================================
--  UPDATED_AT TRIGGERS (002 tables)
-- ============================================================

CREATE TRIGGER trg_organisations_updated_at
    BEFORE UPDATE ON organisations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();


-- ============================================================
--  AUDIT LOG
--
--  Immutable record of analyst actions across the platform.
--  Append-only — no updates, no deletes.
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    org_id BIGINT NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    api_key_id BIGINT REFERENCES api_keys(id) ON DELETE SET NULL,

    action TEXT NOT NULL,           -- e.g. 'verdict.create', 'email.delete', 'rule.update'
    entity_type TEXT,
    entity_id BIGINT,

    -- Full before/after snapshot for sensitive changes
    diff JSONB,

    ip_address INET,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_org_id ON audit_log(org_id);
CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log(created_at);
