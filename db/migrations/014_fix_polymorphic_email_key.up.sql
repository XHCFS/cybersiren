-- ============================================================
--  014_fix_polymorphic_email_key.sql
--
--  The emails table has a composite PK of (internal_id, fetched_at)
--  due to its monthly partitioning by fetched_at.  Five tables use a
--  polymorphic (entity_type, entity_id) pattern where entity_id stores
--  only internal_id when entity_type = 'email'.  Without the fetched_at
--  half of the key it is impossible to join back to the partitioned
--  parent or to identify which partition holds the referenced row.
--
--  Postgres does not support polymorphic foreign keys; FK enforcement
--  is therefore not achievable.  The goals of this migration are:
--    (a) Store the missing half of the composite key (email_fetched_at).
--    (b) Provide purge_polymorphic_orphans() that uses both halves to
--        delete dangling rows.
--
--  Changes
--  -------
--  #12  Add email_fetched_at TIMESTAMPTZ (nullable, NOT VALID check) to:
--         verdicts, enrichment_jobs, enrichment_results, rule_hits,
--         audit_log.
--
--  #11  Create function purge_polymorphic_orphans().
--
--  All statements idempotent.  No CONCURRENTLY.
--  Do NOT backfill email_fetched_at here — resolving the correct
--  partition timestamp requires application-layer logic.
-- ============================================================


-- ============================================================
--  #12 — ADD email_fetched_at TO POLYMORPHIC TABLES
--
--  The CHECK constraint is added NOT VALID so that it fires on
--  new inserts and updates without scanning the (potentially large)
--  existing dataset, which has not yet been backfilled.
--
--  TODO: After the application has backfilled email_fetched_at on
--  all existing rows, run the following on each table to promote
--  the constraint to fully enforced:
--
--    ALTER TABLE verdicts
--        VALIDATE CONSTRAINT chk_verdicts_email_fetched_at;
--    ALTER TABLE enrichment_jobs
--        VALIDATE CONSTRAINT chk_enrichment_jobs_email_fetched_at;
--    ALTER TABLE enrichment_results
--        VALIDATE CONSTRAINT chk_enrichment_results_email_fetched_at;
--    ALTER TABLE rule_hits
--        VALIDATE CONSTRAINT chk_rule_hits_email_fetched_at;
--    ALTER TABLE audit_log
--        VALIDATE CONSTRAINT chk_audit_log_email_fetched_at;
-- ============================================================


-- ------------------------------------------------------------
--  verdicts
-- ------------------------------------------------------------

ALTER TABLE verdicts
    ADD COLUMN IF NOT EXISTS email_fetched_at TIMESTAMPTZ;

COMMENT ON COLUMN verdicts.email_fetched_at IS
    'The fetched_at timestamp from the emails table when entity_type = ''email''. '
    'Required to reconstruct the full composite PK (internal_id, fetched_at) of '
    'the partitioned emails table. NULL until backfilled from the application layer. '
    'Must be populated by all new inserts where entity_type = ''email''.';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint  c
          JOIN pg_class       rel ON rel.oid = c.conrelid
          JOIN pg_namespace   nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = current_schema()
           AND rel.relname = 'verdicts'
           AND c.contype   = 'c'
           AND c.conname   = 'chk_verdicts_email_fetched_at'
    ) THEN
        ALTER TABLE verdicts
            ADD CONSTRAINT chk_verdicts_email_fetched_at
            CHECK (entity_type != 'email' OR email_fetched_at IS NOT NULL)
            NOT VALID;
    END IF;
END;
$$;

COMMENT ON CONSTRAINT chk_verdicts_email_fetched_at
    ON verdicts IS
    'Requires email_fetched_at to be set whenever entity_type = ''email''. '
    'Added NOT VALID — not yet enforced on pre-existing rows. '
    'Run VALIDATE CONSTRAINT after the application backfill is complete.';


-- ------------------------------------------------------------
--  enrichment_jobs
-- ------------------------------------------------------------

ALTER TABLE enrichment_jobs
    ADD COLUMN IF NOT EXISTS email_fetched_at TIMESTAMPTZ;

COMMENT ON COLUMN enrichment_jobs.email_fetched_at IS
    'The fetched_at timestamp from the emails table when entity_type = ''email''. '
    'Required to reconstruct the full composite PK (internal_id, fetched_at) of '
    'the partitioned emails table. NULL until backfilled from the application layer. '
    'Must be populated by all new inserts where entity_type = ''email''.';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint  c
          JOIN pg_class       rel ON rel.oid = c.conrelid
          JOIN pg_namespace   nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = current_schema()
           AND rel.relname = 'enrichment_jobs'
           AND c.contype   = 'c'
           AND c.conname   = 'chk_enrichment_jobs_email_fetched_at'
    ) THEN
        ALTER TABLE enrichment_jobs
            ADD CONSTRAINT chk_enrichment_jobs_email_fetched_at
            CHECK (entity_type != 'email' OR email_fetched_at IS NOT NULL)
            NOT VALID;
    END IF;
END;
$$;

COMMENT ON CONSTRAINT chk_enrichment_jobs_email_fetched_at
    ON enrichment_jobs IS
    'Requires email_fetched_at to be set whenever entity_type = ''email''. '
    'Added NOT VALID — not yet enforced on pre-existing rows. '
    'Run VALIDATE CONSTRAINT after the application backfill is complete.';


-- ------------------------------------------------------------
--  enrichment_results
-- ------------------------------------------------------------

ALTER TABLE enrichment_results
    ADD COLUMN IF NOT EXISTS email_fetched_at TIMESTAMPTZ;

COMMENT ON COLUMN enrichment_results.email_fetched_at IS
    'The fetched_at timestamp from the emails table when entity_type = ''email''. '
    'Required to reconstruct the full composite PK (internal_id, fetched_at) of '
    'the partitioned emails table. NULL until backfilled from the application layer. '
    'Must be populated by all new inserts where entity_type = ''email''.';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint  c
          JOIN pg_class       rel ON rel.oid = c.conrelid
          JOIN pg_namespace   nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = current_schema()
           AND rel.relname = 'enrichment_results'
           AND c.contype   = 'c'
           AND c.conname   = 'chk_enrichment_results_email_fetched_at'
    ) THEN
        ALTER TABLE enrichment_results
            ADD CONSTRAINT chk_enrichment_results_email_fetched_at
            CHECK (entity_type != 'email' OR email_fetched_at IS NOT NULL)
            NOT VALID;
    END IF;
END;
$$;

COMMENT ON CONSTRAINT chk_enrichment_results_email_fetched_at
    ON enrichment_results IS
    'Requires email_fetched_at to be set whenever entity_type = ''email''. '
    'Added NOT VALID — not yet enforced on pre-existing rows. '
    'Run VALIDATE CONSTRAINT after the application backfill is complete.';


-- ------------------------------------------------------------
--  rule_hits
-- ------------------------------------------------------------

ALTER TABLE rule_hits
    ADD COLUMN IF NOT EXISTS email_fetched_at TIMESTAMPTZ;

COMMENT ON COLUMN rule_hits.email_fetched_at IS
    'The fetched_at timestamp from the emails table when entity_type = ''email''. '
    'Required to reconstruct the full composite PK (internal_id, fetched_at) of '
    'the partitioned emails table. NULL until backfilled from the application layer. '
    'Must be populated by all new inserts where entity_type = ''email''.';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint  c
          JOIN pg_class       rel ON rel.oid = c.conrelid
          JOIN pg_namespace   nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = current_schema()
           AND rel.relname = 'rule_hits'
           AND c.contype   = 'c'
           AND c.conname   = 'chk_rule_hits_email_fetched_at'
    ) THEN
        ALTER TABLE rule_hits
            ADD CONSTRAINT chk_rule_hits_email_fetched_at
            CHECK (entity_type != 'email' OR email_fetched_at IS NOT NULL)
            NOT VALID;
    END IF;
END;
$$;

COMMENT ON CONSTRAINT chk_rule_hits_email_fetched_at
    ON rule_hits IS
    'Requires email_fetched_at to be set whenever entity_type = ''email''. '
    'Added NOT VALID — not yet enforced on pre-existing rows. '
    'Run VALIDATE CONSTRAINT after the application backfill is complete.';


-- ------------------------------------------------------------
--  audit_log
-- ------------------------------------------------------------

ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS email_fetched_at TIMESTAMPTZ;

COMMENT ON COLUMN audit_log.email_fetched_at IS
    'The fetched_at timestamp from the emails table when entity_type = ''email''. '
    'Required to reconstruct the full composite PK (internal_id, fetched_at) of '
    'the partitioned emails table. NULL until backfilled from the application layer. '
    'Must be populated by all new inserts where entity_type = ''email''.';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint  c
          JOIN pg_class       rel ON rel.oid = c.conrelid
          JOIN pg_namespace   nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = current_schema()
           AND rel.relname = 'audit_log'
           AND c.contype   = 'c'
           AND c.conname   = 'chk_audit_log_email_fetched_at'
    ) THEN
        ALTER TABLE audit_log
            ADD CONSTRAINT chk_audit_log_email_fetched_at
            CHECK (entity_type != 'email' OR email_fetched_at IS NOT NULL)
            NOT VALID;
    END IF;
END;
$$;

COMMENT ON CONSTRAINT chk_audit_log_email_fetched_at
    ON audit_log IS
    'Requires email_fetched_at to be set whenever entity_type = ''email''. '
    'Added NOT VALID — not yet enforced on pre-existing rows. '
    'Run VALIDATE CONSTRAINT after the application backfill is complete.';


-- ============================================================
--  #11 — purge_polymorphic_orphans()
--
--  Deletes rows from the five polymorphic tables where the
--  referenced entity no longer exists.
--
--  Referential rules by entity_type:
--    'email'      — join on (internal_id, fetched_at); skip rows
--                   where email_fetched_at IS NULL (not yet backfilled).
--    'threat'     — join on enriched_threats.id.
--    'attachment' — join on attachment_library.id.
--    'campaign'   — join on campaigns.id.
--
--  Wire into pg_cron on a nightly schedule.  Safe to run
--  repeatedly.  Will skip email orphan checks until
--  email_fetched_at is backfilled.
-- ============================================================

CREATE OR REPLACE FUNCTION purge_polymorphic_orphans()
RETURNS TABLE (
    table_name  TEXT,
    entity_type TEXT,
    rows_deleted BIGINT
)
LANGUAGE plpgsql AS $$
DECLARE
    v_deleted BIGINT;
BEGIN
    -- ----------------------------------------------------------
    --  verdicts
    -- ----------------------------------------------------------

    -- email orphans (only when email_fetched_at is populated)
    DELETE FROM verdicts v
    WHERE  v.entity_type = 'email'
      AND  v.email_fetched_at IS NOT NULL
      AND  NOT EXISTS (
               SELECT 1
               FROM   emails e
               WHERE  e.internal_id = v.entity_id
                 AND  e.fetched_at  = v.email_fetched_at
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'verdicts';
    entity_type := 'email';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- threat orphans
    DELETE FROM verdicts v
    WHERE  v.entity_type = 'threat'
      AND  NOT EXISTS (
               SELECT 1 FROM enriched_threats t WHERE t.id = v.entity_id
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'verdicts';
    entity_type := 'threat';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- attachment orphans
    DELETE FROM verdicts v
    WHERE  v.entity_type = 'attachment'
      AND  NOT EXISTS (
               SELECT 1 FROM attachment_library a WHERE a.id = v.entity_id
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'verdicts';
    entity_type := 'attachment';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- campaign orphans
    DELETE FROM verdicts v
    WHERE  v.entity_type = 'campaign'
      AND  NOT EXISTS (
               SELECT 1 FROM campaigns c WHERE c.id = v.entity_id
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'verdicts';
    entity_type := 'campaign';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- ----------------------------------------------------------
    --  enrichment_jobs
    -- ----------------------------------------------------------

    -- email orphans
    DELETE FROM enrichment_jobs j
    WHERE  j.entity_type = 'email'
      AND  j.email_fetched_at IS NOT NULL
      AND  NOT EXISTS (
               SELECT 1
               FROM   emails e
               WHERE  e.internal_id = j.entity_id
                 AND  e.fetched_at  = j.email_fetched_at
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'enrichment_jobs';
    entity_type := 'email';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- threat orphans
    DELETE FROM enrichment_jobs j
    WHERE  j.entity_type = 'threat'
      AND  NOT EXISTS (
               SELECT 1 FROM enriched_threats t WHERE t.id = j.entity_id
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'enrichment_jobs';
    entity_type := 'threat';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- attachment orphans
    DELETE FROM enrichment_jobs j
    WHERE  j.entity_type = 'attachment'
      AND  NOT EXISTS (
               SELECT 1 FROM attachment_library a WHERE a.id = j.entity_id
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'enrichment_jobs';
    entity_type := 'attachment';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- campaign orphans (enrichment_jobs.entity_type check from 003
    -- does not include 'campaign', but guard here for safety)
    DELETE FROM enrichment_jobs j
    WHERE  j.entity_type = 'campaign'
      AND  NOT EXISTS (
               SELECT 1 FROM campaigns c WHERE c.id = j.entity_id
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'enrichment_jobs';
    entity_type := 'campaign';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- ----------------------------------------------------------
    --  enrichment_results
    -- ----------------------------------------------------------

    -- email orphans
    DELETE FROM enrichment_results r
    WHERE  r.entity_type = 'email'
      AND  r.email_fetched_at IS NOT NULL
      AND  NOT EXISTS (
               SELECT 1
               FROM   emails e
               WHERE  e.internal_id = r.entity_id
                 AND  e.fetched_at  = r.email_fetched_at
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'enrichment_results';
    entity_type := 'email';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- threat orphans
    DELETE FROM enrichment_results r
    WHERE  r.entity_type = 'threat'
      AND  NOT EXISTS (
               SELECT 1 FROM enriched_threats t WHERE t.id = r.entity_id
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'enrichment_results';
    entity_type := 'threat';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- attachment orphans
    DELETE FROM enrichment_results r
    WHERE  r.entity_type = 'attachment'
      AND  NOT EXISTS (
               SELECT 1 FROM attachment_library a WHERE a.id = r.entity_id
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'enrichment_results';
    entity_type := 'attachment';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- campaign orphans
    DELETE FROM enrichment_results r
    WHERE  r.entity_type = 'campaign'
      AND  NOT EXISTS (
               SELECT 1 FROM campaigns c WHERE c.id = r.entity_id
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'enrichment_results';
    entity_type := 'campaign';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- ----------------------------------------------------------
    --  rule_hits
    -- ----------------------------------------------------------

    -- email orphans
    DELETE FROM rule_hits rh
    WHERE  rh.entity_type = 'email'
      AND  rh.email_fetched_at IS NOT NULL
      AND  NOT EXISTS (
               SELECT 1
               FROM   emails e
               WHERE  e.internal_id = rh.entity_id
                 AND  e.fetched_at  = rh.email_fetched_at
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'rule_hits';
    entity_type := 'email';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- threat orphans
    DELETE FROM rule_hits rh
    WHERE  rh.entity_type = 'threat'
      AND  NOT EXISTS (
               SELECT 1 FROM enriched_threats t WHERE t.id = rh.entity_id
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'rule_hits';
    entity_type := 'threat';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- attachment orphans
    DELETE FROM rule_hits rh
    WHERE  rh.entity_type = 'attachment'
      AND  NOT EXISTS (
               SELECT 1 FROM attachment_library a WHERE a.id = rh.entity_id
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'rule_hits';
    entity_type := 'attachment';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- campaign orphans
    DELETE FROM rule_hits rh
    WHERE  rh.entity_type = 'campaign'
      AND  NOT EXISTS (
               SELECT 1 FROM campaigns c WHERE c.id = rh.entity_id
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'rule_hits';
    entity_type := 'campaign';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- ----------------------------------------------------------
    --  audit_log
    --
    --  entity_type is a free-text column on audit_log (not a typed
    --  enum), so only guard against the four known entity types.
    --  Rows for unknown entity types are left untouched.
    -- ----------------------------------------------------------

    -- email orphans
    DELETE FROM audit_log al
    WHERE  al.entity_type = 'email'
      AND  al.email_fetched_at IS NOT NULL
      AND  NOT EXISTS (
               SELECT 1
               FROM   emails e
               WHERE  e.internal_id = al.entity_id
                 AND  e.fetched_at  = al.email_fetched_at
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'audit_log';
    entity_type := 'email';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- threat orphans
    DELETE FROM audit_log al
    WHERE  al.entity_type = 'threat'
      AND  NOT EXISTS (
               SELECT 1 FROM enriched_threats t WHERE t.id = al.entity_id
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'audit_log';
    entity_type := 'threat';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- attachment orphans
    DELETE FROM audit_log al
    WHERE  al.entity_type = 'attachment'
      AND  NOT EXISTS (
               SELECT 1 FROM attachment_library a WHERE a.id = al.entity_id
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'audit_log';
    entity_type := 'attachment';
    rows_deleted := v_deleted;
    RETURN NEXT;

    -- campaign orphans
    DELETE FROM audit_log al
    WHERE  al.entity_type = 'campaign'
      AND  NOT EXISTS (
               SELECT 1 FROM campaigns c WHERE c.id = al.entity_id
           );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    table_name  := 'audit_log';
    entity_type := 'campaign';
    rows_deleted := v_deleted;
    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION purge_polymorphic_orphans() IS
    'Deletes rows from the five polymorphic tables (verdicts, enrichment_jobs, '
    'enrichment_results, rule_hits, audit_log) where the referenced entity no '
    'longer exists in its source table. '
    'Referential rules by entity_type: '
    '  email      — matched on emails(internal_id, fetched_at) using entity_id '
    '               and email_fetched_at; rows where email_fetched_at IS NULL are '
    '               skipped (not yet backfilled by the application layer). '
    '  threat     — matched on enriched_threats.id. '
    '  attachment — matched on attachment_library.id. '
    '  campaign   — matched on campaigns.id. '
    'Wire into pg_cron on a nightly schedule.  Safe to run repeatedly.  '
    'Will skip email orphan checks until email_fetched_at is backfilled. '
    'Returns one summary row per (table, entity_type) pair showing rows_deleted.';
