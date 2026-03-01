-- ============================================================
--  008_add_missing_schema.sql
--  Resolves schema gaps tracked in issues #44–#51.
--
--  Issues #47 (emails.updated_at) and #50 (emails.sent_at
--  generated column) are intentionally deferred — emails is
--  a partitioned table and adding columns / triggers to it
--  requires extra care.
--
--  All statements are idempotent (safe to re-run).
--  No CONCURRENTLY index builds.
-- ============================================================


-- ============================================================
--  #44  EMAIL RECIPIENTS
--
--  Stores per-email To/CC/BCC recipients.  Kept outside the
--  emails table to avoid wide rows and to allow efficient
--  "find all emails sent to address X" queries.
-- ============================================================

CREATE TABLE IF NOT EXISTS email_recipients (
    id               BIGSERIAL PRIMARY KEY,
    email_id         BIGINT      NOT NULL,
    email_fetched_at TIMESTAMPTZ NOT NULL,
    org_id           BIGINT      REFERENCES organisations(id) ON DELETE CASCADE,
    address          TEXT        NOT NULL,
    display_name     TEXT,
    recipient_type   TEXT        NOT NULL
                         CHECK (recipient_type IN ('to', 'cc', 'bcc')),

    FOREIGN KEY (email_id, email_fetched_at)
        REFERENCES emails(internal_id, fetched_at) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_email_recipients_email_id
    ON email_recipients(email_id);
CREATE INDEX IF NOT EXISTS idx_email_recipients_fetched_at
    ON email_recipients(email_fetched_at);
CREATE INDEX IF NOT EXISTS idx_email_recipients_org_id
    ON email_recipients(org_id);
CREATE INDEX IF NOT EXISTS idx_email_recipients_address
    ON email_recipients(address);
CREATE INDEX IF NOT EXISTS idx_email_recipients_type
    ON email_recipients(recipient_type);


-- ============================================================
--  #45  attachment_library: storage_uri
-- ============================================================

ALTER TABLE attachment_library
    ADD COLUMN IF NOT EXISTS storage_uri TEXT;

COMMENT ON COLUMN attachment_library.storage_uri IS
    'Object-store URI pointing to the raw binary of this attachment '
    '(e.g. "s3://cybersiren-attachments/ab/cd/ef…"). '
    'NULL when only the hash has been recorded (hash-only entry) '
    'and the binary has not been persisted.';


-- ============================================================
--  #46  attachment_library: updated_at + trigger
-- ============================================================

ALTER TABLE attachment_library
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_trigger
        WHERE  tgname   = 'trg_attachment_library_updated_at'
          AND  tgrelid  = 'attachment_library'::regclass
    ) THEN
        CREATE TRIGGER trg_attachment_library_updated_at
            BEFORE UPDATE ON attachment_library
            FOR EACH ROW EXECUTE FUNCTION set_updated_at();
    END IF;
END;
$$;


-- ============================================================
--  #48  email_attachments: created_at
-- ============================================================

ALTER TABLE email_attachments
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;


-- ============================================================
--  #49  rules: rule_group_id (self-referential, deferrable FK)
--
--  All versions of the same logical rule share the same
--  rule_group_id, which equals the id of the root version.
--  DEFERRABLE INITIALLY DEFERRED allows the INSERT of the first
--  version (where rule_group_id = id) to succeed within a
--  transaction before the self-reference resolves.
-- ============================================================

ALTER TABLE rules
    ADD COLUMN IF NOT EXISTS rule_group_id BIGINT;

COMMENT ON COLUMN rules.rule_group_id IS
    'Groups all versions of the same logical rule together. '
    'Set to the id of the root (first) version when a rule is created; '
    'all subsequent versions carry the same rule_group_id. '
    'NULL for rules that pre-date this column.';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_constraint
        WHERE  conname  = 'fk_rules_rule_group_id'
          AND  conrelid = 'rules'::regclass
    ) THEN
        ALTER TABLE rules
            ADD CONSTRAINT fk_rules_rule_group_id
            FOREIGN KEY (rule_group_id) REFERENCES rules(id)
            ON DELETE SET NULL
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_rules_rule_group_id
    ON rules(rule_group_id);


-- ============================================================
--  #51  enrichment_results: ttl_seconds + expires_at + index
--
--  ttl_seconds: how long this result is considered fresh.
--  expires_at: derived from fetched_at + ttl_seconds; used by
--              the staleness-sweep query to find results that
--              need re-fetching.  NULL when ttl_seconds IS NULL
--              (result has no expiry).
-- ============================================================

ALTER TABLE enrichment_results
    ADD COLUMN IF NOT EXISTS ttl_seconds INT;

-- Add expires_at as a regular column (not GENERATED) to avoid
-- PostgreSQL immutability issues with nullable ttl_seconds
ALTER TABLE enrichment_results
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- Create trigger function to compute expires_at
CREATE OR REPLACE FUNCTION compute_expires_at()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.ttl_seconds IS NOT NULL THEN
        NEW.expires_at := NEW.fetched_at + make_interval(secs => NEW.ttl_seconds);
    ELSE
        NEW.expires_at := NULL;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Create trigger to auto-populate expires_at
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_enrichment_results_expires_at'
          AND tgrelid = 'enrichment_results'::regclass
    ) THEN
        CREATE TRIGGER trg_enrichment_results_expires_at
            BEFORE INSERT OR UPDATE ON enrichment_results
            FOR EACH ROW
            EXECUTE FUNCTION compute_expires_at();
    END IF;
END;
$$;

-- Partial index: only rows that actually have an expiry need to be
-- scanned during staleness sweeps.
CREATE INDEX IF NOT EXISTS idx_enrichment_results_expires_at
    ON enrichment_results(expires_at)
    WHERE expires_at IS NOT NULL;
