-- =============================================================================
-- users_seed.sql — one seeded analyst login for the svc-10 console (MVP-7)
-- =============================================================================
-- There is no interactive login user otherwise: the demo needs exactly one
-- credential to drive the read-mostly analyst console. This pins a single user
-- bound to org_id = 1 (the Demo Tenant from organisations_seed.sql) so the
-- console's POST /api/v1/auth/login authenticates without minting a user at
-- runtime.
--
-- LOGIN CREDENTIALS (present to POST /api/v1/auth/login as {email, password}):
--
--     email:    analyst@demo.cybersiren
--     password: analyst-demo-2026
--
-- The plaintext is NEVER stored. password_hash below is the salted bcrypt hash
-- of that plaintext (cost 12, the default AuthConfig.BcryptCost). The hash was
-- computed with a throwaway Go program using golang.org/x/crypto/bcrypt and
-- verified to (a) round-trip CompareHashAndPassword for the plaintext above and
-- (b) reject a wrong password, before being embedded here; the throwaway program
-- was then deleted. svc-10's login flow (GetUserByEmailWithPassword) resolves the
-- row by (org_id, email) and bcrypt-validates the presented password against this
-- hash, rejecting a NULL hash and returning a GENERIC 401 on any failure.
--
-- role 'analyst' (user_role enum, migration 002): can review emails — the read
-- views the console exposes. (MVP-7 drops verdict override / write actions, so a
-- higher role buys nothing here.)
--
-- Idempotent: ON CONFLICT (org_id, email) DO NOTHING. Safe to re-apply on every
-- demo bring-up. FK-depends on organisations_seed.sql (org 1) — must run AFTER it.
-- =============================================================================

INSERT INTO users (org_id, email, display_name, role, password_hash)
VALUES (
    1,
    'analyst@demo.cybersiren',
    'Demo Analyst',
    'analyst',
    '$2a$12$7qlvGclzIPUNwRhYI21Mfe7xtME5fxRNaIiugoGDa0u2JltYoaqve'
)
ON CONFLICT (org_id, email) DO NOTHING;
