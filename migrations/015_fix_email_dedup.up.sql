-- ============================================================
--  015_fix_email_dedup.sql
--
--  Fixes three email deduplication issues introduced in
--  002_add_users_orgs.sql:
--
--  Issue #16: uq_emails_org_message_id includes fetched_at (the
--    partition key). Because Postgres requires the partition key
--    in every unique constraint on a partitioned table, two
--    ingestions of the same message at different timestamps are
--    treated as distinct rows — the constraint does not deduplicate
--    across partition boundaries.
--
--  Issue #17: emails.message_id is nullable. NULL values are always
--    distinct in Postgres UNIQUE indexes, so messages without a
--    Message-ID header bypass the constraint entirely.
--
--  Issue #18: emails.org_id is nullable (per the 002 TODO). NULL-org
--    rows are also excluded from deduplication by the unique index.
--
--  Fix summary:
--    1. Drop uq_emails_org_message_id (semantically useless; see #16).
--    2. Create email_identities: an unpartitioned table keyed on
--       (org_id, message_id) that provides true cross-partition dedup.
--    3. Add COMMENTs documenting the design rationale.
--    4. Add COMMENTs on emails.message_id and emails.org_id.
--
--  All statements are idempotent. No CONCURRENTLY.
--  Does not populate email_identities from existing emails rows —
--  that is a separate backfill job.
-- ============================================================


-- ============================================================
--  #1  Drop the semantically useless dedup constraint
--
--  The constraint is discovered at runtime to avoid hard-coding
--  the auto-generated name, which can differ across environments
--  or after a pg_dump / restore cycle.
--
--  We match on: partitioned parent table = emails, contype = 'u'
--  (unique), and the exact column set {org_id, message_id, fetched_at}
--  to avoid touching any other constraints that may exist.
-- ============================================================

DO $$
DECLARE
    v_conname TEXT;
BEGIN
    SELECT c.conname
      INTO v_conname
      FROM pg_constraint  c
      JOIN pg_class       rel ON rel.oid = c.conrelid
      JOIN pg_namespace   nsp ON nsp.oid = rel.relnamespace
     WHERE nsp.nspname = current_schema()
       AND rel.relname = 'emails'
       AND c.contype   = 'u'
       -- Verify that the constrained column set is exactly
       -- {org_id, message_id, fetched_at} (3 columns, no more).
       AND (
           SELECT array_agg(a.attname ORDER BY a.attname)
             FROM unnest(c.conkey) AS k(attnum)
             JOIN pg_attribute a
               ON a.attrelid = rel.oid AND a.attnum = k.attnum
       )::text[] = ARRAY['fetched_at', 'message_id', 'org_id']   -- sorted
     LIMIT 1;

    IF v_conname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE emails DROP CONSTRAINT %I', v_conname);
    END IF;
END;
$$;


-- ============================================================
--  #2  email_identities — cross-partition dedup table
--
--  One row per (org_id, message_id). Because this table is NOT
--  partitioned, a standard PRIMARY KEY gives a true cross-partition
--  uniqueness guarantee that emails itself cannot provide.
--
--  Ingestion protocol (Go layer):
--    INSERT INTO email_identities (org_id, message_id, internal_id, fetched_at)
--    VALUES ($1, $2, $3, $4)
--    ON CONFLICT (org_id, message_id) DO NOTHING;
--    -- If rows_affected == 0 → duplicate; skip the emails INSERT.
--    -- If rows_affected == 1 → new message; proceed with emails INSERT.
-- ============================================================

CREATE TABLE IF NOT EXISTS email_identities (
    org_id      BIGINT      NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    message_id  TEXT        NOT NULL,
    internal_id BIGINT      NOT NULL,
    fetched_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (org_id, message_id)
);

COMMENT ON TABLE email_identities IS
    'Cross-partition deduplication registry for emails. '
    'Holds exactly one row per (org_id, message_id) pair. '
    'This table exists as a separate, unpartitioned relation because '
    'Postgres requires the partition key (fetched_at) to participate in '
    'any UNIQUE constraint on the partitioned emails table, making it '
    'impossible to enforce uniqueness across partition boundaries with '
    'a constraint on emails alone. '
    'The Go ingestion layer must attempt INSERT … ON CONFLICT DO NOTHING '
    'here before inserting into emails; a zero-rows-affected result '
    'indicates a duplicate that should be discarded. '
    'Emails with a NULL message_id are NOT registered in this table — '
    'the ingestion layer must apply content-hash (SHA-256 of headers + '
    'body) deduplication for those messages. '
    'Do NOT backfill this table inside a migration; use a dedicated '
    'backfill job that can run safely against live traffic.';

COMMENT ON COLUMN email_identities.org_id IS
    'Organisation that owns this email. NOT NULL is enforced here even '
    'though emails.org_id is still nullable pending a full backfill. '
    'A row must not be registered in email_identities until its '
    'corresponding emails row has org_id set.';

COMMENT ON COLUMN email_identities.message_id IS
    'The RFC 5322 Message-ID header value, stored verbatim (angle '
    'brackets included if present). Combined with org_id, this is the '
    'deduplication key. NULL message_ids are excluded — see table comment.';

COMMENT ON COLUMN email_identities.internal_id IS
    'emails.internal_id of the canonical (first-seen) copy of this '
    'message. Used by the ingestion layer to surface the existing row '
    'to the caller when a duplicate is detected.';

COMMENT ON COLUMN email_identities.fetched_at IS
    'emails.fetched_at of the canonical copy. Stored alongside '
    'internal_id so the caller can reconstruct the composite partition '
    'key (internal_id, fetched_at) needed to query the partitioned '
    'emails table.';

COMMENT ON COLUMN email_identities.created_at IS
    'Timestamp when this identity row was first inserted. '
    'Corresponds to the ingestion time of the canonical email copy.';

CREATE INDEX IF NOT EXISTS idx_email_identities_internal_id
    ON email_identities(internal_id);


-- ============================================================
--  #3  Document emails.message_id nullable semantics
-- ============================================================

COMMENT ON COLUMN emails.message_id IS
    'RFC 5322 Message-ID header value. May be NULL when the header is '
    'absent or unparseable. '
    'NULL values are always distinct in Postgres UNIQUE indexes, so '
    'messages without a Message-ID bypass any unique constraint and '
    'cannot be deduplicated via email_identities. '
    'The ingestion layer MUST fall back to content-hash deduplication '
    '(SHA-256 of the normalised headers + body) for NULL message_id '
    'messages to prevent duplicate rows from accumulating.';


-- ============================================================
--  #4  Document emails.org_id nullable / backfill TODO
-- ============================================================

COMMENT ON COLUMN emails.org_id IS
    'Organisation that owns this email. '
    'Currently nullable: existing rows pre-dating 002_add_users_orgs.sql '
    'have org_id = NULL and must be backfilled before this column can be '
    'made NOT NULL. '
    'TODO: Once backfill is confirmed complete, enforce: '
    '  ALTER TABLE emails ALTER COLUMN org_id SET NOT NULL; '
    'New ingestion MUST always supply org_id. Rows with NULL org_id are '
    'excluded from all tenant-scoped queries and cannot be registered in '
    'email_identities.';
