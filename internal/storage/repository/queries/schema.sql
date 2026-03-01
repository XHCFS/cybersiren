-- Minimal query file for sqlc to generate structs from schema.
-- sqlc automatically generates structs for all tables/views from migrations.
-- Add domain-specific queries here as needed.

-- name: GetEmailByID :one
SELECT * FROM emails
WHERE internal_id = $1 AND fetched_at = $2 AND deleted_at IS NULL;

