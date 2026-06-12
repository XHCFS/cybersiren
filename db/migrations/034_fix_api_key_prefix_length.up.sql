-- ============================================================
--  034_fix_api_key_prefix_length.sql
--  Correct the api_keys.key_prefix length constraint to match the
--  actual KeyManager output.
--
--  Depends on: 023 (chk_api_keys_key_prefix_length), 002 (api_keys).
--
--  Why: 023 added CHECK (length(key_prefix) = 8) NOT VALID, but the
--  shared/auth KeyManager.LookupPrefix that produces the stored prefix
--  emits len(config_prefix) + min(suffix_len - 8, 8) characters — for the
--  default config ("cs_", suffix 32) that is 3 + 8 = 11, NOT 8. The
--  fixed-8 rule could never have matched a real key (even 023's own column
--  comment example "cs_live_ab12" is 12 chars), so every genuine API-key
--  INSERT — including the demo-key seed — would violate it. The lookup
--  prefix MUST be stored verbatim or svc-01's GetAPIKeyByPrefix point
--  lookup cannot find the row.
--
--  Fix: drop the impossible equality and replace it with a sane bounded
--  range that admits every KeyManager-minted prefix
--  (len(prefix) + up to 8 suffix chars; bounded well under bcrypt's input
--  limit) while still rejecting empty / pathological values.
--
--  All statements idempotent. No CONCURRENTLY.
-- ============================================================

ALTER TABLE api_keys
    DROP CONSTRAINT IF EXISTS chk_api_keys_key_prefix_length;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_constraint  c
        JOIN   pg_class       rel ON rel.oid = c.conrelid
        JOIN   pg_namespace   nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = current_schema()
           AND rel.relname = 'api_keys'
           AND c.contype   = 'c'
           AND c.conname   = 'chk_api_keys_key_prefix_length'
    ) THEN
        ALTER TABLE api_keys
            ADD CONSTRAINT chk_api_keys_key_prefix_length
            CHECK (length(key_prefix) BETWEEN 4 AND 32)
            NOT VALID;
    END IF;
END;
$$;

COMMENT ON COLUMN api_keys.key_prefix IS
    'Leading lookup fragment of the raw API key, produced by shared/auth '
    'KeyManager.LookupPrefix: the config prefix (e.g. "cs_") plus a bounded '
    'slice of the random suffix, always omitting at least the final 8 random '
    'characters so the stored prefix never reconstructs the full key. The '
    'full key is never stored — only key_hash (salted bcrypt) is persisted. '
    'Constraint chk_api_keys_key_prefix_length bounds it to 4..32 characters.';
