-- name: UpdateFeedLastFetched :exec
-- UPDATE feeds SET last_fetched_at = NOW() WHERE id = $1
UPDATE feeds
SET last_fetched_at = NOW()
WHERE id = $1;

-- name: GetEnabledFeeds :many
-- SELECT * FROM feeds WHERE enabled = TRUE
SELECT *
FROM feeds
WHERE enabled = TRUE;
