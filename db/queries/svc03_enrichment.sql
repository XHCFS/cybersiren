-- =============================================================================
-- svc03_enrichment.sql — URL enrichment persistence owned by SVC-03 URL Analysis
-- =============================================================================
-- After scoring an email's URLs, SVC-03 enriches each one and persists the
-- result: it UPDATEs the bare enriched_threats row SVC-02 created, records the
-- per-provider raw response in enrichment_results, logs an enrichment_jobs row,
-- and writes an email_url_ti_matches audit row for every TI-feed hit.
-- ARCH-SPEC §1 step 3a, §14 step 3a.
-- =============================================================================

-- name: ListEmailURLsForEmail :many
-- Maps each URL of an email to its email_urls.id and enriched_threats.id, so
-- SVC-03 can attach enrichment and TI-match rows to the SVC-02-created rows.
SELECT eu.id AS email_url_id, eu.threat_id, et.url
FROM email_urls eu
JOIN enriched_threats et ON et.id = eu.threat_id
WHERE eu.email_id = $1 AND eu.email_fetched_at = $2;

-- name: GetEnrichedThreatByURL :one
-- Prior-email reuse: returns the enrichment freshness + score for a URL already
-- seen on a previous email, so a still-fresh row can be reused without a refetch.
SELECT id, last_checked, risk_score
FROM enriched_threats
WHERE url = $1;

-- name: UpdateEnrichedThreatEnrichment :exec
-- Fills the bare enriched_threats row with live enrichment (DNS/IP geo, TLS,
-- WHOIS, HTTP) and refreshes the freshness timestamps.
UPDATE enriched_threats
SET online           = $2,
    http_status_code = $3,
    ip_address       = $4,
    cidr_block       = $5,
    asn              = $6,
    asn_name         = $7,
    isp              = $8,
    country          = $9,
    country_name     = $10,
    region           = $11,
    city             = $12,
    latitude         = $13,
    longitude        = $14,
    ssl_enabled      = $15,
    cert_issuer      = $16,
    cert_subject     = $17,
    cert_valid_from  = $18,
    cert_valid_to    = $19,
    registrar        = $20,
    creation_date    = $21,
    expiry_date      = $22,
    updated_date     = $23,
    name_servers     = $24,
    page_language    = $25,
    page_title       = $26,
    risk_score       = $27,
    last_checked     = NOW(),
    last_seen        = NOW()
WHERE id = $1;

-- name: UpsertEnrichmentResult :exec
-- Stores one provider's raw response keyed (entity_type, entity_id, provider).
-- ttl_seconds drives the compute_expires_at trigger; setting fetched_at=NOW()
-- on conflict refreshes expires_at so stale rows re-fetch correctly.
INSERT INTO enrichment_results (
    entity_type, entity_id, provider, raw_response, ttl_seconds, reputation_score
) VALUES ('threat', $1, $2, $3, $4, $5)
ON CONFLICT (entity_type, entity_id, provider) DO UPDATE
SET raw_response     = EXCLUDED.raw_response,
    ttl_seconds      = EXCLUDED.ttl_seconds,
    reputation_score = EXCLUDED.reputation_score,
    fetched_at       = NOW();

-- name: InsertEnrichmentJob :exec
-- Logs a completed synchronous url_scan enrichment job for the threat entity.
INSERT INTO enrichment_jobs (job_type, status, entity_type, entity_id, started_at, completed_at)
VALUES ('url_scan'::job_type, 'completed'::job_status, 'threat', $1, NOW(), NOW());

-- name: InsertEmailURLTIMatch :exec
-- Audit row linking an email URL to the TI indicator that matched it.
INSERT INTO email_url_ti_matches (email_url_id, ti_indicator_id, match_type)
VALUES ($1, $2, 'domain')
ON CONFLICT (email_url_id, ti_indicator_id) DO NOTHING;
