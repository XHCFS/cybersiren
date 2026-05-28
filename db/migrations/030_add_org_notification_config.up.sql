-- ============================================================
--  030_add_org_notification_config.sql
--
--  ARCH-SPEC §15 Schema Gap #1: organisations lacks the
--  notification + retention settings columns SVC-09 reads and
--  SVC-10 writes. Adds them with interim defaults so the org
--  exists-row contract is satisfied before SVC-09 lands.
--
--  Defaults (per cybersiren-next.md §0c / issue #80):
--    notification_threshold = 70          (risk score at/above which we notify)
--    notification_channels  = ["webhook"] (SOAR/SIEM webhook is the demo default)
--    retention_days         = 30          (per-org data retention window)
--
--  Supported channel values: "email", "webhook", "slack".
--
--  Idempotent: ADD COLUMN IF NOT EXISTS. Existing rows inherit the
--  defaults at ALTER time (non-volatile defaults, no table rewrite).
-- ============================================================

ALTER TABLE organisations
    ADD COLUMN IF NOT EXISTS notification_threshold INT   DEFAULT 70,
    ADD COLUMN IF NOT EXISTS notification_channels  JSONB DEFAULT '["webhook"]'::jsonb,
    ADD COLUMN IF NOT EXISTS retention_days         INT   DEFAULT 30;

COMMENT ON COLUMN organisations.notification_threshold IS
    'Risk score (0-100) at or above which SVC-09 dispatches a notification for '
    'an emails.verdict. Interim default 70. Enforcement is in the application '
    'layer (SVC-09), not a DB constraint.';

COMMENT ON COLUMN organisations.notification_channels IS
    'JSON array of enabled notification channels for this org. Supported values: '
    '"email", "webhook", "slack". Default ["webhook"] (SOAR/SIEM POST is the '
    'highest-value demo path). SVC-09 reads this; SVC-10 (org settings) writes it.';

COMMENT ON COLUMN organisations.retention_days IS
    'Per-org data retention window in days for ingested emails and derived '
    'artifacts. Interim default 30. Consumed by the retention sweep (SVC-10 / '
    'issue #159); not enforced by a DB constraint.';
