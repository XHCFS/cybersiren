// Package persist owns the single-transaction database write performed by
// SVC-08 Decision Engine for every emails.scored message.
//
// All primary writes happen inside one pgx transaction:
//  1. UPSERT campaigns (returns campaign_id, is_new, email_count_after).
//  2. UPDATE emails (sets risk scores, campaign_id, analysis_metadata).
//  3. INSERT verdicts (append-only).
//  4. INSERT rule_hits (one per fired rule, append-only).
//  5. UPDATE verdicts.kafka_verdict_wire (immutable emails.verdict JSON for idempotent republish).
//
// Failure of any step rolls back the transaction; the Kafka offset is
// not committed and the message is redelivered after restart/rebalance.
//
// Until `sqlc generate` is rerun in this repo, the three new queries
// (UpsertCampaign, InsertVerdict, UpdateEmailScores) are executed via
// raw pgx. The query strings here MUST stay byte-identical to the
// statements in db/queries/{campaigns,verdicts,emails_scores}.sql so
// the future sqlc-generated code compiles to the same wire shape.
package persist

const queryUpsertCampaign = `
INSERT INTO campaigns (
    org_id,
    fingerprint,
    name,
    threat_type,
    target_brand,
    first_seen,
    last_seen,
    risk_score,
    analysis_metadata,
    tags
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    NOW(),
    NOW(),
    $6,
    jsonb_build_object('email_count', 1),
    $7
)
ON CONFLICT (org_id, fingerprint) DO UPDATE SET
    last_seen        = NOW(),
    risk_score       = ROUND(
        ( COALESCE(campaigns.risk_score, 0)::numeric *
          COALESCE((campaigns.analysis_metadata->>'email_count')::int, 0)
          + EXCLUDED.risk_score::numeric )
        /
        ( COALESCE((campaigns.analysis_metadata->>'email_count')::int, 0) + 1 )
    )::int,
    analysis_metadata = jsonb_set(
        COALESCE(campaigns.analysis_metadata, '{}'::jsonb),
        '{email_count}',
        to_jsonb( COALESCE((campaigns.analysis_metadata->>'email_count')::int, 0) + 1 )
    )
RETURNING
    id,
    (xmax = 0) AS is_new,
    COALESCE((analysis_metadata->>'email_count')::int, 1) AS email_count
`

const queryGetCampaignByFingerprint = `
SELECT
    id,
    risk_score,
    COALESCE((analysis_metadata->>'email_count')::int, 0) AS email_count
FROM campaigns
WHERE org_id = $1
  AND fingerprint = $2
  AND deleted_at IS NULL
`

const queryFindExistingVerdict = `
SELECT id, kafka_verdict_wire::text AS kafka_wire
FROM verdicts
WHERE entity_type = $1::entity_type_enum
  AND entity_id = $2
  AND email_fetched_at IS NOT NULL
  AND email_fetched_at = $3::timestamptz
LIMIT 1
`

const queryUpdateVerdictKafkaWire = `
UPDATE verdicts SET kafka_verdict_wire = $1::jsonb WHERE id = $2
`

const queryEmailCampaignSnapshot = `
SELECT
    e.campaign_id,
    COALESCE((c.analysis_metadata->>'email_count')::int, 0) AS email_count
FROM emails e
JOIN campaigns c ON c.id = e.campaign_id AND c.deleted_at IS NULL
WHERE e.internal_id = $1
  AND e.fetched_at = $2::timestamptz
`

const queryInsertVerdict = `
INSERT INTO verdicts (
    entity_type,
    entity_id,
    email_fetched_at,
    label,
    confidence,
    source,
    model_version,
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
RETURNING id
`

const queryUpdateEmailScores = `
UPDATE emails
SET risk_score            = $3,
    header_risk_score     = $4,
    content_risk_score    = $5,
    url_risk_score        = $6,
    attachment_risk_score = $7,
    campaign_id           = $8,
    analysis_metadata     = $9
WHERE internal_id = $1 AND fetched_at = $2
`
