-- ============================================================
--  019_fix_lifecycle.sql
--
--  Standardises soft-delete and lifecycle semantics across the
--  schema.  Depends on 013_fix_multitenancy.sql.
--
--  Changes:
--    #57-a  feeds              — add deleted_at + active-rows index
--    #57-b  attachment_library — add deleted_at + active-rows index
--    #57-c  enrichment_jobs    — add deleted_at + active-rows index
--    #57-d  enrichment_results — add deleted_at + active-rows index
--    #57-e  verdicts / rule_hits — COMMENT: append-only, no deleted_at
--    #57-f  api_keys.revoked_at — COMMENT: soft-delete equivalent
--
--    #58-a  organisations — BEFORE DELETE warning trigger
--    #58-b  users         — BEFORE DELETE warning trigger
--    #58-c  verdicts.created_by — COMMENT documenting SET NULL risk
--
--  All statements are idempotent.  No CONCURRENTLY.
--  No FK delete-behaviour changes.
-- ============================================================


-- ============================================================
--  #57-a  feeds — add deleted_at
-- ============================================================

ALTER TABLE feeds
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_feeds_active
    ON feeds(deleted_at) WHERE deleted_at IS NULL;


-- ============================================================
--  #57-b  attachment_library — add deleted_at
-- ============================================================

ALTER TABLE attachment_library
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_attachment_library_active
    ON attachment_library(deleted_at) WHERE deleted_at IS NULL;


-- ============================================================
--  #57-c  enrichment_jobs — add deleted_at
-- ============================================================

ALTER TABLE enrichment_jobs
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_enrichment_jobs_active
    ON enrichment_jobs(deleted_at) WHERE deleted_at IS NULL;


-- ============================================================
--  #57-d  enrichment_results — add deleted_at
-- ============================================================

ALTER TABLE enrichment_results
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_enrichment_results_active
    ON enrichment_results(deleted_at) WHERE deleted_at IS NULL;


-- ============================================================
--  #57-e  verdicts & rule_hits — append-only event logs
--
--  These tables are intentionally append-only.  Rows are never
--  updated or logically deleted; they form an immutable audit
--  trail.  No deleted_at column is added.
-- ============================================================

COMMENT ON TABLE verdicts IS
    'Append-only event log of entity verdicts. '
    'Rows are never updated or soft-deleted. '
    'The current verdict for an entity is derived by selecting the '
    'latest row by created_at (see the current_verdicts view). '
    'Do NOT add a deleted_at column — historical verdicts must be '
    'retained for auditability.';

COMMENT ON TABLE rule_hits IS
    'Append-only event log of rule firings. '
    'Each row records a single rule evaluation that contributed to '
    'an entity''s risk score at a specific point in time. '
    'Rows are never updated or soft-deleted. '
    'Do NOT add a deleted_at column — the full firing history is '
    'required for score explainability and rule tuning.';


-- ============================================================
--  #57-f  api_keys.revoked_at — document as soft-delete equivalent
-- ============================================================

COMMENT ON COLUMN api_keys.revoked_at IS
    'Soft-delete equivalent for API keys. '
    'A non-NULL value means the key has been revoked and must not '
    'be accepted during authentication. '
    'Unlike other tables that use deleted_at, api_keys uses '
    'revoked_at because revocation is a domain-specific concept '
    'with additional semantics (the key may still appear in audit '
    'logs and should remain queryable).';


-- ============================================================
--  #58-a  organisations — BEFORE DELETE warning trigger
--
--  Raises a WARNING (not an EXCEPTION) when a hard delete is
--  attempted on a row that was never soft-deleted first.
--  The trigger does NOT block the delete — it emits a log-level
--  warning so accidental hard deletes are visible in server logs
--  while automated cleanup scripts continue to function.
-- ============================================================

CREATE OR REPLACE FUNCTION warn_hard_delete_without_soft_delete()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.deleted_at IS NULL THEN
        RAISE WARNING
            '% id=% is being hard-deleted without a prior soft-delete '
            '(deleted_at IS NULL). Consider setting deleted_at before '
            'hard-deleting to preserve an audit trail.',
            TG_TABLE_NAME, OLD.id;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

-- Idempotent: DROP + CREATE avoids "trigger already exists" errors
-- while ensuring the function binding is always up to date.
DROP TRIGGER IF EXISTS trg_warn_hard_delete_organisation ON organisations;
CREATE TRIGGER trg_warn_hard_delete_organisation
    BEFORE DELETE ON organisations
    FOR EACH ROW
    EXECUTE FUNCTION warn_hard_delete_without_soft_delete();

-- ============================================================
--  #58-b  users — BEFORE DELETE warning trigger
-- ============================================================

DROP TRIGGER IF EXISTS trg_warn_hard_delete_user ON users;
CREATE TRIGGER trg_warn_hard_delete_user
    BEFORE DELETE ON users
    FOR EACH ROW
    EXECUTE FUNCTION warn_hard_delete_without_soft_delete();


-- ============================================================
--  #58-c  verdicts.created_by — document SET NULL attribution risk
-- ============================================================

COMMENT ON COLUMN verdicts.created_by IS
    'References users(id) with ON DELETE SET NULL. '
    'If a user row is hard-deleted, this column is set to NULL and '
    'analyst attribution for the verdict is permanently lost. '
    'To preserve attribution, always soft-delete users '
    '(SET deleted_at = NOW()) instead of hard-deleting them. '
    'The BEFORE DELETE trigger on users emits a WARNING when a '
    'hard delete is attempted on a non-soft-deleted row.';
