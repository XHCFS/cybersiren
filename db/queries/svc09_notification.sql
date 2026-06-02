-- =============================================================================
-- svc09_notification.sql — notification config + recipient lookups (SVC-09)
-- =============================================================================
-- SVC-09 reads per-org notification preferences (migration 030) and resolves
-- admin recipients when the email channel is enabled. ARCH-SPEC Step 6a.
-- =============================================================================

-- name: GetOrgNotificationConfig :one
-- Returns the org's notify threshold + enabled channels. NULLs fall back to the
-- column defaults (70 / ["webhook"]) in the caller.
SELECT notification_threshold, notification_channels
FROM organisations
WHERE id = $1 AND deleted_at IS NULL;

-- name: ListOrgAdminEmails :many
-- Email recipients for the 'email' channel: active admin users of the org.
SELECT email
FROM users
WHERE org_id = $1 AND role = 'admin'::user_role AND deleted_at IS NULL;
