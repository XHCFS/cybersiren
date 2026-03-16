# CyberSiren — Database Schema Reference

> **Version:** 2.2
> **Last Updated:** March 15, 2026
> **Database:** PostgreSQL 15+

---

## Schema Overview

The database uses a **shared PostgreSQL instance with service-owned tables**.
Each microservice has clear read/write boundaries documented below.

Total tables: 18 + 5 materialized views + 1 view

### Identifier Convention

- `internal_id` (BIGSERIAL): Physical primary key for `emails`. Auto-generated. Part of composite PK `(internal_id, fetched_at)` required by partitioning.
- `email_id` (UUIDv7): Logical identifier assigned at ingestion. Carried in all Kafka messages and Redis keys. Not stored as a separate DB column — the `emails.scored` Kafka message includes both `email_id` and `(internal_id, fetched_at)` to enable DB writes without extra lookups.
- `fetched_at` (TIMESTAMPTZ): Monthly partition key. Part of composite PK. Not part of logical identity — exists purely for partition routing.
- `message_id` (TEXT): RFC 5322 Message-ID from the original email. Used with `org_id` for dedup. Not globally unique.

---

## 1. Core Tables

### 1.1 `emails` (partitioned by `fetched_at`, monthly)

The central entity. One row per ingested email.

| Column | Type | Service That Writes | Purpose |
|--------|------|-------------------|---------|
| `internal_id` | BIGSERIAL | Email Parser | Auto-generated PK |
| `fetched_at` | TIMESTAMPTZ | Email Parser | Partition key, ingestion timestamp |
| `org_id` | BIGINT FK → organisations | Email Parser | Tenant isolation |
| `message_id` | TEXT | Email Parser | RFC 5322 Message-ID for dedup |
| `campaign_id` | BIGINT FK → campaigns | Decision Engine | Campaign association (set after verdict) |
| `sender_name` | TEXT | Email Parser | Display name of sender |
| `sender_email` | TEXT | Email Parser | Full sender address |
| `sender_domain` | TEXT | Email Parser | Extracted domain part |
| `reply_to_email` | TEXT | Email Parser | Reply-To header value |
| `return_path` | TEXT | Email Parser | Return-Path header value |
| `originating_ip` | INET | Email Parser | Source IP from headers |
| `auth_spf` | TEXT | Email Parser | SPF verification result |
| `auth_dkim` | TEXT | Email Parser | DKIM verification result |
| `auth_dmarc` | TEXT | Email Parser | DMARC verification result |
| `auth_arc` | TEXT | Email Parser | ARC verification result |
| `x_originating_ip` | INET | Email Parser | X-Originating-IP header |
| `mailer_agent` | TEXT | Email Parser | X-Mailer / User-Agent |
| `in_reply_to` | TEXT | Email Parser | Threading header |
| `references_list` | TEXT[] | Email Parser | Threading references |
| `content_charset` | TEXT | Email Parser | Content-Type charset |
| `precedence` | TEXT | Email Parser | Precedence header |
| `list_id` | TEXT | Email Parser | List-Id header |
| `vendor_security_tags` | JSONB | Email Parser | X-MS-Exchange-* etc. |
| `subject` | TEXT | Email Parser | Email subject line |
| `sent_timestamp` | BIGINT | Email Parser | Unix epoch from Date header |
| `headers_json` | JSONB | Email Parser | Full raw headers archive |
| `body_plain` | TEXT | Email Parser | Plain text body (TTL-purged) |
| `body_html` | TEXT | Email Parser | HTML body (TTL-purged) |
| `header_risk_score` | INT 0–100 | Decision Engine | Score from Header Analysis |
| `content_risk_score` | INT 0–100 | Decision Engine | Score from NLP Analysis |
| `attachment_risk_score` | INT 0–100 | Decision Engine | Score from Attachment Analysis |
| `url_risk_score` | INT 0–100 | Decision Engine | Score from URL Analysis |
| `analysis_metadata` | JSONB | Decision Engine | Full analysis breakdown |
| `risk_score` | INT 0–100 | Decision Engine | Final weighted composite score |
| `deleted_at` | TIMESTAMPTZ | API/Dashboard | Soft delete |

**PK:** `(internal_id, fetched_at)` — composite required by PostgreSQL partitioning
**Unique:** `(org_id, message_id, fetched_at)` — deduplication constraint
**Partition strategy:** Monthly ranges, pre-created 2025-01 through 2026-12 + default

---

### 1.2 `enriched_threats`

Email-observed threat entities. Stores URLs, domains, and IPs extracted from emails that have been (or are candidates for) enrichment with WHOIS, SSL, geo, ASN, and content analysis data.

> **Scope:** This table is reserved for indicators discovered through the email pipeline. External TI feed indicators are stored in `ti_indicators` (see §1.5). An email-observed threat may *also* match a feed indicator — that relationship is recorded in `email_url_ti_matches` (see §2.4), not by duplicating the row here.

| Column | Type | Service That Writes | Purpose |
|--------|------|-------------------|---------|
| `id` | BIGSERIAL PK | URL Analysis | Auto-generated |
| `url` | TEXT UNIQUE | URL Analysis | The indicator URL (email-observed) |
| `domain` | TEXT | URL Analysis | Extracted domain |
| `online` | BOOLEAN | URL Analysis (enrichment) | Availability status |
| `http_status_code` | INT | URL Analysis (enrichment) | HTTP response code |
| `ip_address` | INET | URL Analysis (enrichment) | Resolved IP |
| `cidr_block` | TEXT | URL Analysis (enrichment) | CIDR of hosting network |
| `asn` | INT | URL Analysis (enrichment) | Autonomous system number |
| `asn_name` | TEXT | URL Analysis (enrichment) | ASN organization name |
| `isp` | TEXT | URL Analysis (enrichment) | ISP name |
| `country` | TEXT | URL Analysis (enrichment) | Country code |
| `country_name` | TEXT | URL Analysis (enrichment) | Full country name |
| `region` | TEXT | URL Analysis (enrichment) | Region/state |
| `city` | TEXT | URL Analysis (enrichment) | City |
| `latitude` | DOUBLE PRECISION | URL Analysis (enrichment) | Geolocation |
| `longitude` | DOUBLE PRECISION | URL Analysis (enrichment) | Geolocation |
| `ssl_enabled` | BOOLEAN | URL Analysis (enrichment) | TLS present |
| `cert_issuer` | TEXT | URL Analysis (enrichment) | Certificate issuer |
| `cert_subject` | TEXT | URL Analysis (enrichment) | Certificate subject |
| `cert_valid_from` | TIMESTAMPTZ | URL Analysis (enrichment) | Certificate start |
| `cert_valid_to` | TIMESTAMPTZ | URL Analysis (enrichment) | Certificate expiry |
| `cert_serial` | TEXT | URL Analysis (enrichment) | Certificate serial |
| `tld` | TEXT | URL Analysis (enrichment) | Top-level domain |
| `registrar` | TEXT | URL Analysis (enrichment) | WHOIS registrar |
| `creation_date` | DATE | URL Analysis (enrichment) | Domain creation date |
| `expiry_date` | DATE | URL Analysis (enrichment) | Domain expiry date |
| `updated_date` | DATE | URL Analysis (enrichment) | Domain last update |
| `name_servers` | TEXT[] | URL Analysis (enrichment) | DNS name servers |
| `page_language` | TEXT | URL Analysis (enrichment) | Landing page language |
| `page_title` | TEXT | URL Analysis (enrichment) | Landing page title |
| `threat_type` | TEXT | URL Analysis | Classification |
| `target_brand` | TEXT | URL Analysis | Targeted brand name (legacy; use `brand_id`) |
| `threat_tags` | TEXT[] | URL Analysis | Classification tags |
| `source_feed` | TEXT | (deprecated) | Legacy: feed name — use `feed_id` |
| `feed_id` | BIGINT FK → feeds | URL Analysis | Optional: feed that independently confirmed this indicator |
| `source_id` | TEXT | URL Analysis | ID within source feed (if any) |
| `org_id` | BIGINT FK → organisations | URL Analysis | Tenant attribution |
| `first_seen` | TIMESTAMPTZ | URL Analysis | First email observation |
| `last_seen` | TIMESTAMPTZ | URL Analysis | Last email observation |
| `last_checked` | TIMESTAMPTZ | URL Analysis (enrichment) | Last enrichment run |
| `notes` | TEXT | Analyst via API | Human notes |
| `analysis_metadata` | JSONB | URL Analysis | Additional analysis data |
| `risk_score` | INT 0–100 | URL Analysis (ML) | Threat risk level |
| `is_global` | BOOLEAN | (legacy) | Deprecated after migration 026 — new TI feed indicators go to `ti_indicators` |
| `deleted_at` | TIMESTAMPTZ | URL Analysis | Soft delete |
| `created_at` | TIMESTAMPTZ | auto | Row creation |
| `updated_at` | TIMESTAMPTZ | trigger | Last modification |

> **After migration 026:** `is_global` and `source_feed` are deprecated on this table. New external feed indicators must be stored in `ti_indicators`. Rows in `enriched_threats` with `is_global = TRUE` that are referenced by `email_urls` are legitimate (email-observed AND feed-confirmed) and are not moved.

---

### 1.3 `campaigns`

Phishing campaign groupings based on shared infrastructure/tactics.

| Column | Type | Service That Writes | Purpose |
|--------|------|-------------------|---------|
| `id` | BIGSERIAL PK | Decision Engine | Auto-generated |
| `org_id` | BIGINT FK → organisations | Decision Engine | Tenant isolation |
| `name` | TEXT | Decision Engine / Analyst | Human-readable name |
| `description` | TEXT | Analyst via API | Campaign description |
| `fingerprint` | TEXT UNIQUE | Decision Engine | Deterministic campaign ID |
| `threat_type` | TEXT | Decision Engine | Primary threat type |
| `target_brand` | TEXT | Decision Engine | Targeted brand |
| `tags` | TEXT[] | Decision Engine / Analyst | Classification tags |
| `first_seen` | TIMESTAMPTZ | Decision Engine | First email in campaign |
| `last_seen` | TIMESTAMPTZ | Decision Engine | Most recent email |
| `risk_score` | INT 0–100 | Decision Engine | Rolling average of member emails |
| `analysis_metadata` | JSONB | Decision Engine | Campaign-level analysis |
| `deleted_at` | TIMESTAMPTZ | API/Dashboard | Soft delete |
| `created_at` | TIMESTAMPTZ | auto | Row creation |
| `updated_at` | TIMESTAMPTZ | trigger | Last modification |

---

### 1.5 `ti_indicators`

Normalised store for external threat-intelligence feed indicators. Each row represents a single indicator (URL, domain, IP, CIDR block, file hash, or email address) ingested from an external TI feed. These rows are **not enriched** — they carry no WHOIS, SSL, geo, ASN, or content analysis data. They exist solely for fast matching against URLs/domains/IPs/hashes extracted from emails.

> **Key distinction from `enriched_threats`:** `enriched_threats` stores email-observed URLs/domains that have been enriched (expensive external calls). `ti_indicators` stores feed-origin indicators that are cheap to ingest and used only for matching. The two tables serve orthogonal roles:
> - `email_urls.threat_id → enriched_threats` = "here is the enrichment data for this email URL"
> - `email_url_ti_matches → ti_indicators` = "here is which TI feed recognised this email URL"

| Column | Type | Service That Writes | Purpose |
|--------|------|-------------------|---------|
| `id` | BIGSERIAL PK | TI Feed Sync | Auto-generated |
| `feed_id` | BIGINT FK → feeds | TI Feed Sync | Source feed (required) |
| `indicator_type` | ti_indicator_type ENUM | TI Feed Sync | url/domain/ip/cidr/hash/email_address |
| `indicator_value` | TEXT | TI Feed Sync | Canonical normalised value (lowercased, scheme-normalised) |
| `threat_type` | TEXT | TI Feed Sync | Classification (validated via threat_type_values) |
| `brand_id` | BIGINT FK → brands | TI Feed Sync | Canonical brand reference |
| `target_brand` | TEXT | (deprecated) | Legacy free-text brand; use `brand_id` |
| `threat_tags` | TEXT[] | TI Feed Sync | Feed taxonomy tags |
| `source_id` | TEXT | TI Feed Sync | Original feed identifier (e.g. PhishTank phish_id) |
| `first_seen` | TIMESTAMPTZ | TI Feed Sync | First observation by feed |
| `last_seen` | TIMESTAMPTZ | TI Feed Sync | Most recent feed report |
| `confidence` | DOUBLE PRECISION 0–1 | TI Feed Sync | Feed-assigned confidence (NULL = not provided) |
| `risk_score` | INT 0–100 | TI Feed Sync | Feed-assigned severity (matching/prioritisation only) |
| `is_active` | BOOLEAN | TI Feed Sync | FALSE when feed removes indicator |
| `raw_metadata` | JSONB | TI Feed Sync | Unparsed extra fields from feed response |
| `created_at` | TIMESTAMPTZ | auto | Row creation |
| `updated_at` | TIMESTAMPTZ | trigger | Last modification |

**Unique:** `(feed_id, indicator_type, indicator_value)` — one row per indicator per feed. Same indicator across different feeds is allowed (corroboration signal).

**Key indexes:**
- `idx_ti_indicators_value` — fast lookup by indicator value (the primary matching query)
- `idx_ti_indicators_type_value` — narrow lookup when indicator kind is known
- `idx_ti_indicators_active_value` — partial index filtered on `is_active = TRUE`
- GIN index on `threat_tags`

---

### 1.4 `verdicts` (append-only)

Immutable verdict history. Current verdict = latest by `created_at` per entity.

| Column | Type | Service That Writes | Purpose |
|--------|------|-------------------|---------|
| `id` | BIGSERIAL PK | Decision Engine / Analyst | Auto-generated |
| `entity_type` | TEXT (enum check) | Decision Engine / Analyst | 'email', 'threat', 'attachment', 'campaign' |
| `entity_id` | BIGINT | Decision Engine / Analyst | FK to the entity |
| `label` | verdict_label ENUM | Decision Engine / Analyst | benign/suspicious/phishing/malware/spam/unknown |
| `confidence` | DOUBLE PRECISION 0–1 | Decision Engine | Label certainty (NOT risk score / 100). Based on distance from nearest threshold boundary, with penalties for partial analysis and rule-only verdicts |
| `source` | verdict_source ENUM | Decision Engine / Analyst | model/analyst/feed/rule |
| `model_version` | TEXT | Decision Engine | Which model version produced this |
| `notes` | TEXT | Analyst via API | Human notes |
| `created_by` | BIGINT FK → users | Analyst via API | Analyst identity (NULL for automated) |
| `created_at` | TIMESTAMPTZ | auto | Verdict timestamp |

**View:** `current_verdicts` — `DISTINCT ON (entity_type, entity_id) ORDER BY created_at DESC`

---

## 2. Junction Tables

### 2.1 `email_urls`

| Column | Service That Writes | Purpose |
|--------|-------------------|---------|
| `email_id` | Email Parser | FK to emails |
| `email_fetched_at` | Email Parser | Composite FK |
| `threat_id` | Email Parser / URL Analysis | FK to enriched_threats (enrichment data) |
| `visible_text` | Email Parser | Anchor text shown to recipient |

> **Two relationships on `email_urls`:** `threat_id → enriched_threats` links to enrichment data for this URL. TI feed match data is in `email_url_ti_matches` (§2.4), not here. Both can exist simultaneously for the same email URL.

### 2.2 `email_attachments`

| Column | Service That Writes | Purpose |
|--------|-------------------|---------|
| `email_id` | Email Parser | FK to emails |
| `email_fetched_at` | Email Parser | Composite FK |
| `attachment_id` | Email Parser | FK to attachment_library |
| `filename` | Email Parser | Original filename |
| `content_type` | Email Parser | MIME type |
| `content_id` | Email Parser | Content-ID header |
| `disposition` | Email Parser | inline/attachment |
| `analysis_metadata` | Attachment Analysis | Analysis results |
| `risk_score` | Attachment Analysis / Decision Engine | Per-attachment risk |

### 2.3 `email_recipients`

| Column | Service That Writes | Purpose |
|--------|-------------------|---------|
| `email_id` | Email Parser | FK to emails |
| `email_fetched_at` | Email Parser | Composite FK |
| `org_id` | Email Parser | Tenant isolation |
| `address` | Email Parser | Recipient email address |
| `display_name` | Email Parser | Recipient display name |
| `recipient_type` | Email Parser | to/cc/bcc |

### 2.4 `email_url_ti_matches`

Audit trail of TI feed matches against email URLs. Records which `ti_indicator` was matched for each `email_url`, how the match was determined, and when. This table is orthogonal to `email_urls.threat_id → enriched_threats` (which links to enrichment data, not feed match data).

| Column | Type | Service That Writes | Purpose |
|--------|------|-------------------|---------|
| `id` | BIGSERIAL PK | URL Analysis | Auto-generated |
| `email_url_id` | BIGINT FK → email_urls | URL Analysis | Which email URL matched |
| `ti_indicator_id` | BIGINT FK → ti_indicators | URL Analysis | Which feed indicator matched |
| `match_type` | TEXT CHECK | URL Analysis | How the match was made: `exact`, `domain`, `ip`, `cidr`, `hash` |
| `matched_at` | TIMESTAMPTZ | URL Analysis | When the match was recorded |

**Unique:** `(email_url_id, ti_indicator_id)` — one match record per (email URL, feed indicator) pair.

---

## 3. Analysis Infrastructure Tables

### 3.1 `attachment_library` (global dedup by SHA256)

| Column | Service That Writes | Purpose |
|--------|-------------------|---------|
| `sha256` | Email Parser | UNIQUE hash for dedup |
| `md5`, `sha1` | Email Parser | Additional hashes |
| `actual_extension` | Email Parser | File extension |
| `size_bytes` | Email Parser | File size |
| `entropy` | Email Parser | Shannon entropy |
| `is_malicious` | Attachment Analysis / TI Feed Sync | TI match flag |
| `risk_score` | Attachment Analysis | Hash-level risk |
| `threat_tags` | TI Feed Sync | Classification tags |
| `storage_uri` | Email Parser | S3 URI for binary (optional) |

### 3.2 `enrichment_jobs`

| Column | Service That Writes | Purpose |
|--------|-------------------|---------|
| `job_type` | URL Analysis / Attachment Analysis | whois/dns/asn/ssl_cert/etc. |
| `status` | URL Analysis / Attachment Analysis | pending/in_progress/completed/failed/skipped |
| `entity_type` | URL Analysis / Attachment Analysis | email/threat/attachment |
| `entity_id` | URL Analysis / Attachment Analysis | FK to entity |
| `attempts` | URL Analysis / Attachment Analysis | Retry counter |
| `max_attempts` | URL Analysis / Attachment Analysis | Retry limit (default 3) |
| `last_error` | URL Analysis / Attachment Analysis | Error message |

### 3.3 `enrichment_results`

| Column | Service That Writes | Purpose |
|--------|-------------------|---------|
| `entity_type` | URL Analysis / Attachment Analysis | email/threat/attachment |
| `entity_id` | URL Analysis / Attachment Analysis | FK to entity |
| `provider` | URL Analysis / Attachment Analysis | e.g., "virustotal", "whois" |
| `raw_response` | URL Analysis / Attachment Analysis | Full API response (JSONB) |
| `malicious_votes` | URL Analysis / Attachment Analysis | Parsed from response |
| `harmless_votes` | URL Analysis / Attachment Analysis | Parsed from response |
| `reputation_score` | URL Analysis / Attachment Analysis | Parsed from response |
| `ttl_seconds` | URL Analysis / Attachment Analysis | Cache freshness |
| `expires_at` | trigger-computed | When to re-fetch |

---

## 4. Rule Engine Tables

### 4.1 `rules`

| Column | Service That Writes | Purpose |
|--------|-------------------|---------|
| `org_id` | API/Dashboard | NULL = global rule, else per-org |
| `name` | API/Dashboard | Human-readable rule name |
| `version` | API/Dashboard | Semantic version |
| `status` | API/Dashboard | draft/active/disabled/archived |
| `logic` | API/Dashboard | JSONB rule conditions |
| `score_impact` | API/Dashboard | -100 to +100 score adjustment |
| `target` | API/Dashboard | email/url/attachment/header/campaign |
| `rule_group_id` | API/Dashboard | Links versions of same logical rule |
| `created_by` | API/Dashboard | Analyst who created it |

### 4.2 `rule_hits`

| Column | Service That Writes | Purpose |
|--------|-------------------|---------|
| `rule_id` | Header Analysis / Decision Engine | Which rule fired |
| `rule_version` | Header Analysis / Decision Engine | Which version |
| `entity_type` | Header Analysis / Decision Engine | What it fired on |
| `entity_id` | Header Analysis / Decision Engine | FK to entity |
| `score_impact` | Header Analysis / Decision Engine | Actual score change |
| `match_detail` | Header Analysis / Decision Engine | JSONB showing what matched |

---

## 5. Multi-Tenancy & Auth Tables

### 5.1 `organisations`
Written by: **API/Dashboard**

### 5.2 `users`
Written by: **API/Dashboard**

### 5.3 `api_keys`
Written by: **API/Dashboard**

### 5.4 `audit_log`
Written by: **API/Dashboard** (every mutating action)

### 5.5 `feeds`
Written by: **TI Feed Sync** (last_fetched_at) and **API/Dashboard** (CRUD)

> `feeds` rows are referenced by `ti_indicators.feed_id` (every feed indicator traces back to its source feed) and optionally by `enriched_threats.feed_id` (when an email-observed threat was independently confirmed by a feed).

---

## 6. Materialized Views

| View | Refresh Interval | Used By |
|------|-----------------|---------|
| `mv_threat_summary` | 15 min | Dashboard (threat landscape) |
| `mv_campaign_summary` | 5 min | Dashboard (campaign list) |
| `mv_feed_health` | 10 min | Admin panel (feed monitoring) |
| `mv_rule_performance` | 30 min | Rule tuning interface |
| `mv_org_ingestion_summary` | 5 min | Org home screen |

All views support `REFRESH CONCURRENTLY` (reads never blocked).
Refresh triggered by TI Feed Sync after sync cycles and by a pg_cron schedule.

---

## 7. Index Strategy

All indexes are defined in the migration files. Key patterns:
- **Primary lookup paths** indexed directly (e.g., `idx_emails_fetched_at`, `idx_enriched_domain`)
- **TI indicator matching** indexed for fast feed lookups (`idx_ti_indicators_value`, `idx_ti_indicators_type_value`, partial index on `is_active = TRUE`)
- **Partial indexes** for active records (`WHERE deleted_at IS NULL`, `WHERE status = 'active'`, `WHERE is_active = TRUE`)
- **GIN indexes** on JSONB and array columns (`headers_json`, `threat_tags`)
- **Covering indexes** on verdict lookups (`entity_type, entity_id, created_at DESC`)
- **Composite unique** for dedup (`org_id, message_id, fetched_at` on emails; `feed_id, indicator_type, indicator_value` on ti_indicators)
