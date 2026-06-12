-- ============================================================
--  035_email_identities_email_id.sql
--  Record the logical UUIDv7 email_id on the cross-partition
--  dedup registry so a holder of only the opaque email_id can
--  resolve the partitioned-emails composite key (internal_id,
--  fetched_at) — backing the svc-01 demo-UI /verdict read.
--
--  Depends on: 015 (email_identities table).
--
--  Why: G5/G17 give every email TWO ids — the logical email_id
--  (UUIDv7 string, assigned by svc-01, carried on Kafka + Redis,
--  opaque) and the physical (internal_id BIGINT, fetched_at)
--  partition key (assigned by Postgres in svc-02). The two were
--  never co-located in any table: email_identities keyed only on
--  (org_id, message_id), so nothing mapped a bare email_id back to
--  its row. The demo UI hands the API caller an email_id and must
--  poll the verdict by it, so svc-02 now stamps the email_id onto
--  the identity row it registers, and the read side resolves
--  email_id -> (internal_id, fetched_at) here.
--
--  Nullable + no backfill: rows registered before this migration
--  (and any future NULL-message_id email that is intentionally not
--  registered) simply carry a NULL email_id and are not resolvable
--  by email_id — which is acceptable, the mapping is best-effort
--  demo plumbing, not a correctness invariant. The (org_id,
--  message_id) primary key and the dedup contract are unchanged.
--
--  All statements are idempotent. No CONCURRENTLY.
-- ============================================================

ALTER TABLE email_identities
    ADD COLUMN IF NOT EXISTS email_id UUID;

COMMENT ON COLUMN email_identities.email_id IS
    'The logical UUIDv7 email_id (G5/G17) assigned by svc-01 and '
    'carried on every Kafka message / Redis key for this email. '
    'Stamped here by svc-02 when it registers the identity so a '
    'holder of only the opaque email_id can resolve the canonical '
    '(internal_id, fetched_at) partition key. NULL for rows '
    'registered before migration 035 and for NULL-message_id emails '
    'that are never registered — such emails are not resolvable by '
    'email_id (best-effort mapping, not a dedup invariant).';

-- A partial unique index keeps the mapping one-to-one without
-- touching the NULL legacy rows. Scoped per org so two tenants can
-- never collide and a lookup never crosses the RLS boundary.
CREATE UNIQUE INDEX IF NOT EXISTS uq_email_identities_org_email_id
    ON email_identities (org_id, email_id)
    WHERE email_id IS NOT NULL;
