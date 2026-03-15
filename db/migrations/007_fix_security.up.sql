-- ============================================================
--  007_fix_security.sql
--  Fix: api_keys expiry indexes (#65), users email format
--       constraint (#66), trigger to revoke api_keys on user
--       deletion or soft-deletion (#67).
--
--  All statements are idempotent. No CONCURRENTLY.
-- ============================================================


-- ============================================================
--  #65  PARTIAL INDEXES ON api_keys(expires_at)
-- ============================================================

-- Covers all rows that have an expiry date set.
-- Avoids a full table scan for the common
--   WHERE expires_at < NOW()
-- query pattern.
CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at
    ON api_keys(expires_at)
    WHERE expires_at IS NOT NULL;

-- Scoped to non-revoked rows with an expiry date.
-- Directly supports the cleanup / sweep query pattern:
--   WHERE expires_at < NOW() AND revoked_at IS NULL
CREATE INDEX IF NOT EXISTS idx_api_keys_expires_active
    ON api_keys(expires_at)
    WHERE expires_at IS NOT NULL
      AND revoked_at IS NULL;


-- ============================================================
--  #66  BASIC EMAIL FORMAT CHECK CONSTRAINT ON users
-- ============================================================

-- NOTE: Full RFC-5321/5322 validation (MX lookup, disposable-address
-- detection, international domain handling, etc.) is the application
-- layer's responsibility. This constraint is a minimal structural
-- sanity check only: local-part @ domain DOT tld, no whitespace.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_constraint
        WHERE  conname  = 'chk_users_email_format'
          AND  conrelid = 'users'::regclass
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT chk_users_email_format
            CHECK (email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$');
    END IF;
END;
$$;

COMMENT ON COLUMN users.email IS
    'User e-mail address. '
    'The constraint chk_users_email_format enforces a minimal structural format only '
    '(local-part@domain.tld, no whitespace). '
    'Full RFC-5321/5322 validation, MX lookup, and disposable-address detection '
    'are the application layer''s responsibility.';


-- ============================================================
--  #67  TRIGGER: REVOKE api_keys WHEN A USER IS DELETED
--               (hard delete) OR SOFT-DELETED (deleted_at SET)
-- ============================================================

-- Trigger function.
-- Called for both DELETE and UPDATE OF deleted_at on users.
--   DELETE      → revoke all non-revoked keys for OLD.id.
--   UPDATE path → revoke when deleted_at transitions NULL → non-NULL
--                 (soft-delete). No-ops on un-delete or on updates
--                 that only change an already-set deleted_at value.
CREATE OR REPLACE FUNCTION fn_revoke_user_api_keys()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        UPDATE api_keys
        SET    revoked_at = NOW()
        WHERE  user_id    = OLD.id
          AND  revoked_at IS NULL;
        RETURN OLD;
    END IF;

    -- UPDATE path: act only on a NULL → non-NULL transition.
    IF NEW.deleted_at IS NOT NULL AND OLD.deleted_at IS NULL THEN
        UPDATE api_keys
        SET    revoked_at = NOW()
        WHERE  user_id    = NEW.id
          AND  revoked_at IS NULL;
    END IF;

    RETURN NEW;
END;
$$;

-- CREATE OR REPLACE TRIGGER is idempotent (PostgreSQL 14+).
-- Fires AFTER so that the users row is fully committed / removed
-- before the api_keys UPDATE runs, keeping FK lookups consistent.
CREATE OR REPLACE TRIGGER trg_revoke_keys_on_user_delete
    AFTER DELETE OR UPDATE OF deleted_at ON users
    FOR EACH ROW
    EXECUTE FUNCTION fn_revoke_user_api_keys();
