-- ============================================================
--  021_fix_cascade_deletes.sql
--
--  Changes unsafe ON DELETE CASCADE foreign keys to safer
--  alternatives on tables that serve as audit trails or
--  explainability records, and adds trigger-based CASCADE
--  for the polymorphic pattern.
--
--  Changes:
--    #13  audit_log.org_id        — CASCADE → RESTRICT
--    #14  rule_hits.rule_id       — CASCADE → SET NULL
--    #15  email_urls.threat_id    — CASCADE → SET NULL
--    #58  users.org_id            — CASCADE → RESTRICT
--    #11  Polymorphic orphan prevention triggers on source tables
--
--  All statements are idempotent.  No CONCURRENTLY.
-- ============================================================


-- ============================================================
--  #13  audit_log.org_id — ON DELETE CASCADE → RESTRICT
--
--  The audit_log comment in 002 says "Immutable record …
--  Append-only — no updates, no deletes."  But ON DELETE CASCADE
--  on org_id means deleting an organisation wipes its entire
--  audit trail, directly contradicting that stated intent.
--
--  Fix: ON DELETE RESTRICT.  An organisation cannot be hard-
--  deleted while it has audit records.  The operator must either
--  archive/export the audit rows first, or soft-delete the org
--  (the recommended path per 019).
-- ============================================================

DO $$
DECLARE
    v_conname TEXT;
BEGIN
    SELECT c.conname
      INTO v_conname
      FROM pg_constraint  c
      JOIN pg_class       rel  ON rel.oid  = c.conrelid
      JOIN pg_namespace   nsp  ON nsp.oid  = rel.relnamespace
      JOIN pg_class       frel ON frel.oid = c.confrelid
     WHERE nsp.nspname   = current_schema()
       AND rel.relname   = 'audit_log'
       AND frel.relname  = 'organisations'
       AND c.contype     = 'f'
       AND EXISTS (
           SELECT 1
           FROM   unnest(c.conkey) AS k(attnum)
           JOIN   pg_attribute     a ON a.attrelid = rel.oid
                                    AND a.attnum   = k.attnum
           WHERE  a.attname = 'org_id'
       );

    IF v_conname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE audit_log DROP CONSTRAINT %I', v_conname);
    END IF;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint  c
          JOIN pg_class       rel  ON rel.oid  = c.conrelid
          JOIN pg_namespace   nsp  ON nsp.oid  = rel.relnamespace
          JOIN pg_class       frel ON frel.oid = c.confrelid
         WHERE nsp.nspname  = current_schema()
           AND rel.relname  = 'audit_log'
           AND frel.relname = 'organisations'
           AND c.contype    = 'f'
           AND c.confdeltype = 'r'   -- 'r' = RESTRICT
    ) THEN
        ALTER TABLE audit_log
            ADD CONSTRAINT audit_log_org_id_fkey
            FOREIGN KEY (org_id)
            REFERENCES organisations(id)
            ON DELETE RESTRICT;
    END IF;
END;
$$;

COMMENT ON COLUMN audit_log.org_id IS
    'Organisation that performed the audited action. '
    'ON DELETE RESTRICT prevents accidental destruction of audit history '
    'when an organisation is removed.  Soft-delete the org (set deleted_at) '
    'instead of hard-deleting.  If the org must be hard-deleted, export or '
    'archive audit_log rows first.';


-- ============================================================
--  #14  rule_hits.rule_id — ON DELETE CASCADE → SET NULL
--
--  rule_hits is an explainability table: it records which rule
--  fired and what score contribution it made.  ON DELETE CASCADE
--  erases all evidence that a rule ever fired when the rule row
--  is deleted.
--
--  Fix: ON DELETE SET NULL.  The rule_hits row survives with
--  rule_id = NULL, and the denormalized rule_version and
--  score_impact columns (documented in 012 as point-in-time
--  snapshots) still explain the historical firing.
-- ============================================================

DO $$
DECLARE
    v_conname TEXT;
BEGIN
    SELECT c.conname
      INTO v_conname
      FROM pg_constraint  c
      JOIN pg_class       rel  ON rel.oid  = c.conrelid
      JOIN pg_namespace   nsp  ON nsp.oid  = rel.relnamespace
      JOIN pg_class       frel ON frel.oid = c.confrelid
     WHERE nsp.nspname   = current_schema()
       AND rel.relname   = 'rule_hits'
       AND frel.relname  = 'rules'
       AND c.contype     = 'f'
       AND EXISTS (
           SELECT 1
           FROM   unnest(c.conkey) AS k(attnum)
           JOIN   pg_attribute     a ON a.attrelid = rel.oid
                                    AND a.attnum   = k.attnum
           WHERE  a.attname = 'rule_id'
       );

    IF v_conname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE rule_hits DROP CONSTRAINT %I', v_conname);
    END IF;
END;
$$;

-- rule_id must be nullable for SET NULL to work.
-- DROP NOT NULL is a no-op if the column is already nullable.
ALTER TABLE rule_hits ALTER COLUMN rule_id DROP NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint  c
          JOIN pg_class       rel  ON rel.oid  = c.conrelid
          JOIN pg_namespace   nsp  ON nsp.oid  = rel.relnamespace
          JOIN pg_class       frel ON frel.oid = c.confrelid
         WHERE nsp.nspname  = current_schema()
           AND rel.relname  = 'rule_hits'
           AND frel.relname = 'rules'
           AND c.contype    = 'f'
           AND c.confdeltype = 'n'   -- 'n' = SET NULL
    ) THEN
        ALTER TABLE rule_hits
            ADD CONSTRAINT rule_hits_rule_id_fkey
            FOREIGN KEY (rule_id)
            REFERENCES rules(id)
            ON DELETE SET NULL;
    END IF;
END;
$$;

COMMENT ON COLUMN rule_hits.rule_id IS
    'References the rule that fired.  ON DELETE SET NULL preserves the '
    'hit row (and its denormalized rule_version / score_impact snapshots) '
    'even after the parent rule is archived or deleted.  A NULL rule_id '
    'indicates that the original rule row no longer exists.';


-- ============================================================
--  #15  email_urls.threat_id — ON DELETE CASCADE → SET NULL
--
--  email_urls links an email to a URL (enriched_threats row).
--  ON DELETE CASCADE means removing a threat intel entry silently
--  severs the link, and analysts lose visibility into which URLs
--  appeared in an email.
--
--  Fix: ON DELETE SET NULL.  The email↔URL row survives with
--  threat_id = NULL.  The visible_text column still records what
--  the recipient saw.
-- ============================================================

DO $$
DECLARE
    v_conname TEXT;
BEGIN
    SELECT c.conname
      INTO v_conname
      FROM pg_constraint  c
      JOIN pg_class       rel  ON rel.oid  = c.conrelid
      JOIN pg_namespace   nsp  ON nsp.oid  = rel.relnamespace
      JOIN pg_class       frel ON frel.oid = c.confrelid
     WHERE nsp.nspname   = current_schema()
       AND rel.relname   = 'email_urls'
       AND frel.relname  = 'enriched_threats'
       AND c.contype     = 'f'
       AND EXISTS (
           SELECT 1
           FROM   unnest(c.conkey) AS k(attnum)
           JOIN   pg_attribute     a ON a.attrelid = rel.oid
                                    AND a.attnum   = k.attnum
           WHERE  a.attname = 'threat_id'
       );

    IF v_conname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE email_urls DROP CONSTRAINT %I', v_conname);
    END IF;
END;
$$;

-- threat_id must be nullable for SET NULL to work.
ALTER TABLE email_urls ALTER COLUMN threat_id DROP NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint  c
          JOIN pg_class       rel  ON rel.oid  = c.conrelid
          JOIN pg_namespace   nsp  ON nsp.oid  = rel.relnamespace
          JOIN pg_class       frel ON frel.oid = c.confrelid
         WHERE nsp.nspname  = current_schema()
           AND rel.relname  = 'email_urls'
           AND frel.relname = 'enriched_threats'
           AND c.contype    = 'f'
           AND c.confdeltype = 'n'   -- 'n' = SET NULL
    ) THEN
        ALTER TABLE email_urls
            ADD CONSTRAINT email_urls_threat_id_fkey
            FOREIGN KEY (threat_id)
            REFERENCES enriched_threats(id)
            ON DELETE SET NULL;
    END IF;
END;
$$;

COMMENT ON COLUMN email_urls.threat_id IS
    'References the enriched_threats row for this URL.  ON DELETE SET NULL '
    'preserves the email↔URL link (and the visible_text anchor text) even '
    'if the threat intel entry is purged.  A NULL threat_id means the TI '
    'record no longer exists; the URL itself is still reconstructable from '
    'the email body.';


-- ============================================================
--  #58  users.org_id — ON DELETE CASCADE → RESTRICT
--
--  Hard-deleting an organisation cascades to users, which in
--  turn SETs NULL on verdicts.created_by — silently erasing
--  analyst attribution across every verdict the user issued.
--
--  Fix: ON DELETE RESTRICT on users.org_id.  An organisation
--  with active users cannot be hard-deleted.  Combined with the
--  soft-delete workflow enforced by the BEFORE DELETE warning
--  trigger added in 019, this ensures no accidental data loss.
--
--  Recommended org removal workflow:
--    1. Soft-delete all users  (SET deleted_at = NOW()).
--    2. Hard-delete the users  (the 007 trigger revokes their keys).
--    3. Archive / export audit_log rows for the org.
--    4. Hard-delete audit_log rows (now RESTRICT-safe).
--    5. Soft-delete the org    (SET deleted_at = NOW()).
--    6. Hard-delete the org    (nothing references it any more).
-- ============================================================

DO $$
DECLARE
    v_conname TEXT;
BEGIN
    SELECT c.conname
      INTO v_conname
      FROM pg_constraint  c
      JOIN pg_class       rel  ON rel.oid  = c.conrelid
      JOIN pg_namespace   nsp  ON nsp.oid  = rel.relnamespace
      JOIN pg_class       frel ON frel.oid = c.confrelid
     WHERE nsp.nspname   = current_schema()
       AND rel.relname   = 'users'
       AND frel.relname  = 'organisations'
       AND c.contype     = 'f'
       AND EXISTS (
           SELECT 1
           FROM   unnest(c.conkey) AS k(attnum)
           JOIN   pg_attribute     a ON a.attrelid = rel.oid
                                    AND a.attnum   = k.attnum
           WHERE  a.attname = 'org_id'
       );

    IF v_conname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE users DROP CONSTRAINT %I', v_conname);
    END IF;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint  c
          JOIN pg_class       rel  ON rel.oid  = c.conrelid
          JOIN pg_namespace   nsp  ON nsp.oid  = rel.relnamespace
          JOIN pg_class       frel ON frel.oid = c.confrelid
         WHERE nsp.nspname  = current_schema()
           AND rel.relname  = 'users'
           AND frel.relname = 'organisations'
           AND c.contype    = 'f'
           AND c.confdeltype = 'r'   -- 'r' = RESTRICT
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT users_org_id_fkey
            FOREIGN KEY (org_id)
            REFERENCES organisations(id)
            ON DELETE RESTRICT;
    END IF;
END;
$$;

COMMENT ON COLUMN users.org_id IS
    'Organisation the user belongs to.  ON DELETE RESTRICT prevents '
    'accidental cascading deletion of user rows (and the downstream '
    'SET NULL on verdicts.created_by) when an org is removed.  '
    'Always soft-delete organisations; the application retention reaper '
    'handles the eventual hard-delete after all child rows are cleaned up.';


-- ============================================================
--  #11  Polymorphic orphan prevention — BEFORE DELETE triggers
--
--  The five polymorphic tables (verdicts, enrichment_jobs,
--  enrichment_results, rule_hits, audit_log) use
--  (entity_type, entity_id) without foreign keys.  Deleting a
--  source entity leaves orphans.  purge_polymorphic_orphans()
--  (014) cleans them up on a schedule, but orphans can still
--  accumulate between runs.
--
--  Fix: BEFORE DELETE triggers on the three non-email source
--  tables (enriched_threats, attachment_library, campaigns) that
--  immediately delete referencing rows from all five polymorphic
--  tables.  This gives CASCADE-like behaviour at the DB level.
--
--  Emails are excluded because the polymorphic references require
--  both entity_id AND email_fetched_at for a correct join, and
--  the emails table is partitioned — per-partition triggers are
--  complex to maintain.  Email orphan cleanup continues to rely
--  on purge_polymorphic_orphans().
-- ============================================================

CREATE OR REPLACE FUNCTION fn_cascade_polymorphic_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_entity_type entity_type_enum;
BEGIN
    -- Map the source table name to the entity_type_enum value.
    CASE TG_TABLE_NAME
        WHEN 'enriched_threats'   THEN v_entity_type := 'threat';
        WHEN 'attachment_library' THEN v_entity_type := 'attachment';
        WHEN 'campaigns'          THEN v_entity_type := 'campaign';
        ELSE
            RAISE EXCEPTION
                'fn_cascade_polymorphic_delete: unexpected table %',
                TG_TABLE_NAME;
    END CASE;

    DELETE FROM verdicts            WHERE entity_type = v_entity_type AND entity_id = OLD.id;
    DELETE FROM enrichment_jobs     WHERE entity_type = v_entity_type AND entity_id = OLD.id;
    DELETE FROM enrichment_results  WHERE entity_type = v_entity_type AND entity_id = OLD.id;
    DELETE FROM rule_hits           WHERE entity_type = v_entity_type AND entity_id = OLD.id;
    DELETE FROM audit_log           WHERE entity_type = v_entity_type AND entity_id = OLD.id;

    RETURN OLD;
END;
$$;

COMMENT ON FUNCTION fn_cascade_polymorphic_delete() IS
    'BEFORE DELETE trigger function that cascades deletes from source '
    'entity tables (enriched_threats, attachment_library, campaigns) to '
    'the five polymorphic tables that reference them via (entity_type, '
    'entity_id).  Provides FK-like CASCADE behaviour for the polymorphic '
    'pattern that Postgres cannot enforce natively.  '
    'Email entities are not covered — they rely on '
    'purge_polymorphic_orphans() due to partitioning complexity.';

-- enriched_threats
DROP TRIGGER IF EXISTS trg_cascade_polymorphic_delete ON enriched_threats;
CREATE TRIGGER trg_cascade_polymorphic_delete
    BEFORE DELETE ON enriched_threats
    FOR EACH ROW
    EXECUTE FUNCTION fn_cascade_polymorphic_delete();

-- attachment_library
DROP TRIGGER IF EXISTS trg_cascade_polymorphic_delete ON attachment_library;
CREATE TRIGGER trg_cascade_polymorphic_delete
    BEFORE DELETE ON attachment_library
    FOR EACH ROW
    EXECUTE FUNCTION fn_cascade_polymorphic_delete();

-- campaigns
DROP TRIGGER IF EXISTS trg_cascade_polymorphic_delete ON campaigns;
CREATE TRIGGER trg_cascade_polymorphic_delete
    BEFORE DELETE ON campaigns
    FOR EACH ROW
    EXECUTE FUNCTION fn_cascade_polymorphic_delete();
