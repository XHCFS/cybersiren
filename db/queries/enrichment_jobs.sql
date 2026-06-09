-- =============================================================================
-- enrichment_jobs.sql — async enrichment work queue (SVC-03/04 workers)
-- =============================================================================
-- Workers claim pending jobs with SKIP LOCKED, run them, then mark complete or
-- failed. org_id is set for RLS scoping; email_fetched_at carries the emails
-- partition key when entity_type = 'email'. status/job_type are enum types.
-- =============================================================================

-- name: EnqueueEnrichmentJob :one
-- Enqueues a new enrichment job in the pending state. Returns the job id.
INSERT INTO enrichment_jobs (
    job_type,
    entity_type,
    entity_id,
    email_fetched_at,
    max_attempts,
    timeout_seconds,
    priority,
    org_id
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8
)
RETURNING id;

-- name: ClaimNextEnrichmentJob :one
-- Atomically claims the highest-priority pending job for a worker using
-- FOR UPDATE SKIP LOCKED, flipping it to in_progress and stamping the worker
-- identity. Returns no rows when the queue is empty.
UPDATE enrichment_jobs
SET status = 'in_progress',
    locked_by = $1,
    attempts = attempts + 1,
    started_at = NOW()
WHERE id = (
    SELECT id
    FROM enrichment_jobs
    WHERE status = 'pending'
      AND deleted_at IS NULL
    ORDER BY priority DESC, created_at ASC
    LIMIT 1
    FOR UPDATE SKIP LOCKED
)
RETURNING id, job_type, entity_type, entity_id, email_fetched_at, attempts, max_attempts;

-- name: CompleteEnrichmentJob :exec
-- Marks a claimed job as completed.
UPDATE enrichment_jobs
SET status = 'completed',
    locked_by = NULL,
    completed_at = NOW()
WHERE id = $1;

-- name: FailEnrichmentJob :exec
-- Marks a claimed job failed (or back to pending for retry when attempts remain),
-- recording the error. Releases the worker lock either way.
UPDATE enrichment_jobs
SET status = CASE WHEN attempts >= max_attempts THEN 'failed'::job_status
                  ELSE 'pending'::job_status END,
    locked_by = NULL,
    last_error = $2
WHERE id = $1;
