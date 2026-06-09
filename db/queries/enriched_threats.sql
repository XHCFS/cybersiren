-- =============================================================================
-- enriched_threats.sql — email-observed URL/domain artefacts + enrichment
-- =============================================================================
-- See ARCH-SPEC §1 Step 2/3 and migration 026 table comment.
--
-- Two write phases:
--   1. SVC-02 Parser UPSERTs a BARE row (url/domain/tld only) so it can take
--      the returned id as the email_urls.threat_id FK. The url column carries a
--      global UNIQUE constraint (enriched_threats_url_key), so the conflict
--      target is (url).
--   2. SVC-03/04 enrichers later UPDATE the same row in place with WHOIS, geo,
--      ASN, cert, page metadata, scoring, etc.
--
-- enriched_threats has FORCE RLS with a policy that also admits is_global rows;
-- the surrounding tx must set app.current_org_id (see WithOrgTx).
-- =============================================================================

-- name: UpsertBareEnrichedThreat :one
-- Idempotent bare insert keyed on the PER-ORG (org_id, url) unique
-- (uq_enriched_threats_org_url, migration 032). On conflict we only refresh
-- last_seen and keep the existing enrichment untouched, so a re-observed URL
-- never loses data populated by a later enrichment pass. Returns the row id
-- used as email_urls.threat_id.
--
-- The conflict target is (org_id, url), NOT the old global (url): enriched_threats
-- is per-org RLS-forced (018), so a global UNIQUE(url) made cross-tenant
-- re-observation conflict on a row the second org's tenant_isolation policy hides,
-- erroring the parse tx once the app connects as the non-bypass role (031). Each
-- org now owns its row for the same url. (Same fix 013 #9 applied to campaigns.)
-- source_feed = 'email' records the provenance the chk_enriched_threats_feed_or_source
-- CHECK (migration 012) requires: every row must carry feed_id OR source_feed.
-- Post-026 this table is reserved for email-pipeline-observed artefacts, so the
-- bare row's source is the email pipeline. Without it the INSERT fails the CHECK
-- on every first observation.
INSERT INTO enriched_threats (
    url,
    domain,
    tld,
    org_id,
    is_global,
    source_feed,
    first_seen,
    last_seen
) VALUES (
    $1,
    $2,
    $3,
    $4,
    FALSE,
    'email',
    NOW(),
    NOW()
)
ON CONFLICT (org_id, url) DO UPDATE SET
    last_seen = NOW()
RETURNING id;

-- name: UpdateEnrichedThreatEnrichment :exec
-- Applies enrichment results to an existing threat row. Each parameter that is
-- NULL leaves the corresponding column unchanged (COALESCE pattern), so a
-- partial enricher (e.g. geo-only) does not clobber WHOIS data and vice versa.
--
-- WHERE pins org-owned rows only (is_global = FALSE). The enriched_threats RLS
-- policy admits is_global = TRUE OR org_id = current, so without this guard one
-- tenant's enrichment pass could UPDATE a SHARED global row by id. The bare
-- UPSERT always writes is_global = FALSE, so the email pipeline only ever
-- enriches its own org rows; a stray global id simply matches zero rows.
UPDATE enriched_threats
SET
    online           = COALESCE($2, online),
    http_status_code = COALESCE($3, http_status_code),
    ip_address       = COALESCE($4, ip_address),
    cidr_block       = COALESCE($5, cidr_block),
    asn              = COALESCE($6, asn),
    asn_name         = COALESCE($7, asn_name),
    isp              = COALESCE($8, isp),
    country          = COALESCE($9, country),
    country_name     = COALESCE($10, country_name),
    region           = COALESCE($11, region),
    city             = COALESCE($12, city),
    latitude         = COALESCE($13, latitude),
    longitude        = COALESCE($14, longitude),
    ssl_enabled      = COALESCE($15, ssl_enabled),
    cert_issuer      = COALESCE($16, cert_issuer),
    cert_subject     = COALESCE($17, cert_subject),
    cert_valid_from  = COALESCE($18, cert_valid_from),
    cert_valid_to    = COALESCE($19, cert_valid_to),
    cert_serial      = COALESCE($20, cert_serial),
    registrar        = COALESCE($21, registrar),
    creation_date    = COALESCE($22, creation_date),
    expiry_date      = COALESCE($23, expiry_date),
    updated_date     = COALESCE($24, updated_date),
    name_servers     = COALESCE($25, name_servers),
    page_language    = COALESCE($26, page_language),
    page_title       = COALESCE($27, page_title),
    threat_type      = COALESCE($28, threat_type),
    risk_score       = COALESCE($29, risk_score),
    analysis_metadata = COALESCE($30::jsonb, analysis_metadata),
    last_checked     = NOW()
WHERE id = $1
  AND is_global = FALSE;
