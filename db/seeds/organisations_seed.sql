-- =============================================================================
-- organisations_seed.sql — minimal demo tenant for the spine smoke pipeline
-- =============================================================================
-- Provides org_id = 1, the default the svc-01 stub stamps on every synthetic
-- email and that scripts/dev/inject_fake_email.sh sends. Every downstream
-- service expects this row to exist (e.g. svc-08's campaign UPSERT FK
-- references organisations.id).
--
-- Idempotent: ON CONFLICT (id) DO NOTHING. Safe to re-apply on every demo
-- bring-up.
-- =============================================================================

INSERT INTO organisations (id, name, slug)
VALUES (1, 'Demo Tenant', 'demo')
ON CONFLICT (id) DO NOTHING;

-- Pin notification config for the smoke org so svc-09 deterministically gates +
-- dispatches over webhook regardless of migration-default drift. The migration
-- defaults already enable the webhook channel (threshold 70); the lower
-- threshold here makes the demo robust to verdict-score drift. Email is
-- intentionally NOT enabled (no admin users seeded ⇒ 0-recipient no-op).
UPDATE organisations
   SET notification_threshold = 50,
       notification_channels  = '["webhook"]'::jsonb
 WHERE id = 1;

-- Bump the BIGSERIAL sequence past any explicit ids so future inserts don't
-- collide with id=1.
SELECT setval(
    'organisations_id_seq',
    GREATEST(COALESCE((SELECT MAX(id) FROM organisations), 0), 1)
);
