-- =============================================================================
-- api_key_demo_seed.sql — one fixed demo API key for the svc-01 ingestion path
-- =============================================================================
-- Pins a single, reproducible API key bound to org_id = 1 (the Demo Tenant from
-- organisations_seed.sql) so the demo can authenticate POST /api/v1/scan without
-- minting a key at runtime.
--
-- DEMO KEY PLAINTEXT (present it as `Authorization: Bearer <plaintext>` or
-- `X-API-Key: <plaintext>`):
--
--     cs_demokey000000000000000000000DEMO
--
-- The plaintext is NEVER stored. key_hash below is the salted bcrypt hash of
-- that plaintext (cost 12, the default AuthConfig.BcryptCost); key_prefix is the
-- shared/auth KeyManager.LookupPrefix of it (config prefix "cs_" + 8 suffix
-- chars). svc-01 resolves the candidate row by key_prefix, then bcrypt-validates
-- the presented key against key_hash. The hash was computed with a throwaway Go
-- program using the real shared/auth KeyManager and verified to validate for the
-- plaintext above; it is reproducible from the plaintext at any time.
--
-- scopes are a subset of valid_api_scopes (migration 023): email:write lets the
-- key submit emails for scanning; email:read / verdict:read let a demo read the
-- result back.
--
-- Idempotent: ON CONFLICT (key_hash) DO NOTHING. Safe to re-apply on every demo
-- bring-up. Depends on: organisations_seed.sql (org 1) + migration 034
-- (key_prefix length constraint relaxed to admit the 11-char lookup prefix).
-- =============================================================================

INSERT INTO api_keys (org_id, name, key_prefix, key_hash, scopes, expires_at, revoked_at)
VALUES (
    1,
    'demo ingestion key',
    'cs_demokey0',
    '$2a$12$fEd0xNjqYZoyBt0HqQiTAO6tsWydjfiMG1Y4o8uCRAXiB65T8Q5Rm',
    ARRAY['email:write', 'email:read', 'verdict:read']::text[],
    NULL,  -- never expires
    NULL   -- not revoked
)
ON CONFLICT (key_hash) DO NOTHING;
