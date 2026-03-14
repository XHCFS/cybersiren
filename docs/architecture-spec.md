# CyberSiren — System Architecture

> **Version:** 2.1 (Microservices Redesign)
> **Last Updated:** March 11, 2026
> **Status:** Implementation Baseline — Approved Architecture with Tracked Deltas

---

## 1. System Overview

CyberSiren is an open-source, multi-signal phishing email detection platform. It fuses
URL intelligence, NLP content analysis, email header forensics, attachment threat scoring,
and threat intelligence feeds into a single explainable verdict per email.

**Architecture style:** Event-driven microservices over Apache Kafka
**Primary language:** Go (pipeline services), Python (ML inference services)
**Database:** PostgreSQL 15+ (shared, service-owned tables)
**Cache/State:** Redis 7+ (TI cache, dedup, aggregator state)
**Message broker:** Apache Kafka (inter-service communication)

---

## 2. Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Modularity** | Each analysis dimension is an independent service with its own consumer group |
| **Explainability** | Every score component is stored; rule_hits trace exactly why a score was assigned |
| **Privacy-first** | Raw email bodies are TTL-purged; only metadata and scores persist long-term |
| **Fail-open with neutral scores** | Service failure returns score 50 (neutral), never blocks the pipeline |
| **Idempotency** | Message-ID dedup at ingestion; Kafka consumer offsets prevent re-processing |
| **Extensibility** | New email source = new adapter; new TI feed = new feed config; new rule = DB insert |

---

## 2a. Canonical Identifier Strategy

| Identifier | Format | Assigned By | Scope | Purpose |
|-----------|--------|-------------|-------|---------|
| `email_id` | UUIDv7 | Email Ingestion (SVC-01) | Kafka messages, Redis keys, trace context | Logical identifier carried through the entire pipeline. Used as Kafka partition key on all topics. |
| `internal_id` | BIGSERIAL | PostgreSQL (auto) | Database only | Physical primary key. Part of composite PK `(internal_id, fetched_at)` required by partitioning. |
| `fetched_at` | TIMESTAMPTZ | Email Ingestion (SVC-01) | Database, Kafka messages | Partition key for the `emails` table (monthly range). Part of composite PK. Not part of logical identity. |
| `message_id` | TEXT (RFC 5322) | Original email sender | Deduplication only | Used with `org_id` for dedup constraint. Not globally unique — scoped per org. |

**Mapping:** `email_id` (UUID) is stored in `emails.internal_id` via a type-aware insert (UUID → BIGINT is not valid; `internal_id` is auto-generated). The `email_id` UUID is carried in Kafka messages and Redis keys. DB queries from downstream services use `(internal_id, fetched_at)` for the composite PK. The Decision Engine (SVC-08) receives `email_id` from Kafka and must resolve it to `(internal_id, fetched_at)` for DB writes — this mapping is performed via a lookup on `emails` using `org_id` and `message_id`, or by including `internal_id` and `fetched_at` in the `emails.scored` Kafka message payload (preferred approach, avoids extra DB round-trip).

## 2b. Data Role Taxonomy

| Role | Technology | Characteristics |
|------|-----------|----------------|
| **Source of Record** | PostgreSQL | Authoritative state. All persistent data lives here. |
| **Ephemeral Coordination** | Redis | Cache, dedup, aggregator state, rate limiting. Lossy — can be rebuilt from DB. |
| **Transport / Replay** | Apache Kafka | Message delivery between services. Bounded retention (24h–7d). Replay for reprocessing. |
| **Read Optimization** | Materialized Views | Pre-computed dashboard queries. Refreshed periodically. Never the source of truth. |
| **Binary Retention** | Object Storage (S3/MinIO) | Attachment binaries. Referenced by `attachment_library.storage_uri`. TTL: 90 days. |

---

## 3. Service Inventory

### 3.1 Email Ingestion Service (Go)

**Responsibility:** Receive emails from external sources, normalize to internal format, publish to Kafka.

**Adapter pattern:**
- Gmail Adapter — Google OAuth2 + Gmail API (push via Pub/Sub or poll)
- Outlook Adapter — Microsoft Graph API + webhooks
- IMAP Adapter — Generic IMAP polling (any provider)
- API Adapter — Direct EML/RFC 822 upload via REST endpoint
- Custom Adapters — Users implement the `EmailSource` interface

**Internal format:** `ParsedEmail` struct (defined in `pkg/models/email.go`)

**Flow:**
1. Adapter receives/fetches raw email
2. Convert to `ParsedEmail` (the standardized internal representation)
3. Assign `email_id` (UUID), `org_id` (from auth context), `fetched_at` (now)
4. Dedup check: lookup `(org_id, message_id)` in Redis set (fast path) or DB (authoritative)
5. If duplicate → discard with log entry
6. If new → publish to Kafka topic `emails.raw`

**Kafka output:** `emails.raw`
**DB access:** Read-only (dedup check against `emails` table via Redis cache)

**Message size policy:** Raw RFC 822 bytes are published directly to `emails.raw`. At the stated throughput (~1 msg/s steady, burst to 50/s) and typical email sizes (50–500 KB), this is well within Kafka's default `message.max.bytes` (1 MB). For production deployments expecting attachment-heavy traffic, configure `message.max.bytes` up to 10 MB on the `emails.raw` topic, or adopt a pointer-based design: store raw bytes in object storage (S3/MinIO) and publish only a reference URI to Kafka. This is a deployment-time decision, not an architectural change.

---

### 3.2 Email Parser Service (Go)

**Responsibility:** Decompose standardized email into analysis-ready components, fan out to analysis topics.

**Processing steps:**
1. Consume from `emails.raw`
2. Parse MIME structure → extract body (plain + HTML), attachments, headers
3. Extract URLs from HTML (href, src, action attributes) and plain text (regex)
4. Strip HTML → clean plain text (for NLP)
5. Hash each attachment (SHA256, MD5, SHA1), compute entropy, detect file type
6. Extract authentication results (SPF/DKIM/DMARC/ARC) from headers
7. Build Analysis Plan: list which analysis components are applicable
   - Has URLs? → expect `url` score
   - Has attachments? → expect `attachment` score
   - Has text body? → expect `nlp` score
   - Always → expect `header` score
8. Insert initial email record to PostgreSQL `emails` table
9. Insert `email_urls`, `email_attachments`, `attachment_library`, `email_recipients`
10. Publish to fan-out topics

**Kafka output:**
- `analysis.urls` — `{email_id, org_id, urls: [{url, visible_text, position}]}`
- `analysis.attachments` — `{email_id, org_id, attachments: [{sha256, md5, sha1, filename, content_type, size_bytes, entropy}]}`
- `analysis.headers` — `{email_id, org_id, spf, dkim, dmarc, arc, sender_email, sender_domain, reply_to, return_path, originating_ip, mailer_agent, hop_count, headers_json}`
- `analysis.text` — `{email_id, org_id, plain_text, subject, sender_name}`
- `analysis.plans` — `{email_id, org_id, expected_scores: ["url","header","attachment","nlp"], created_at}`

**DB access:**
- **Writes:** `emails`, `email_urls`, `email_attachments`, `attachment_library`, `email_recipients`

---

### 3.3 URL Analysis Service (Go + Python subprocess)

**Responsibility:** Determine risk level of each URL through TI lookup, enrichment, and ML inference.

**Pipeline (per URL):**
```
URL → Redis Cache Check → TI Blocklist → Enrichment → ML Model → Score
         ↓ (cache hit)        ↓ (blocked)
      Reuse score         Score = 95
```

**Step 1 — Cache check:**
Redis key: `url_score:{sha256(url)}` with 6-hour TTL.
If cached → reuse score, skip everything below.

**Step 2 — TI Blocklist:**
Lookup URL/domain against `enriched_threats` table (indexed, cached in Redis).
If exact match found → `url_risk_score = 95`, `ti_matched = true`. Skip ML.

**Step 3 — URL Enrichment:**
For URLs that pass the blocklist, collect:
- WHOIS data (domain age, registrar, creation/expiry dates)
- SSL certificate info (issuer, validity, self-signed check)
- DNS records (A, MX, NS, CNAME resolution)
- HTTP probe (status code, redirect chain length, final landing URL)
- Geo/ASN data (IP geolocation, ISP, ASN)
Concurrency limit: 5 simultaneous external calls (prevents rate-limiting by WHOIS servers).
All enrichment data maps to the existing `EnrichmentData` struct.

**Step 4 — ML Inference:**
Features from enrichment → XGBoost model (Python subprocess or HTTP microservice).
Output: `url_risk_score` (0-100) per URL.

**Score aggregation across URLs:**
Per-email URL score = `max(individual_url_scores)` — the riskiest URL determines the email's URL risk.

**Kafka input:** `analysis.urls`
**Kafka output:** `scores.url` — `{email_id, org_id, component: "url", score: 72, url_details: [...]}`
**DB access:**
- **Reads:** `enriched_threats` (TI lookup)
- **Writes:** `enriched_threats` (new unknown URLs), `enrichment_results`, `enrichment_jobs`

---

### 3.4 Header Analysis Service (Go)

**Responsibility:** Assess email authenticity and sender trustworthiness from header metadata. Produces a `header_risk_score` (0–100) based on authentication results, sender reputation signals, and structural anomalies.

> **Research status:** The signal categories below are architecturally defined. The specific scoring weights and thresholds within each category are preliminary heuristics and require empirical calibration before production use. All signals are implemented as configurable **rules** in the `rules` table, making them adjustable without code changes.

**Three analysis dimensions:**

#### 3.4.1 Authentication Verification
Evaluates SPF, DKIM, DMARC, and ARC authentication results from email headers. Detects mismatches between `From`, `Reply-To`, and `Return-Path` addresses. Each authentication failure or mismatch contributes to the header risk score.

#### 3.4.2 Sender Reputation
Assesses sender trustworthiness through domain age analysis (via WHOIS data from `enriched_threats`), threat intelligence matches against sender domain and originating IP, typosquatting detection (edit distance against known brand domains), and contextual signals such as free email providers sending corporate-style content.

#### 3.4.3 Structural Anomaly Detection
Identifies suspicious structural patterns in the email: HTML-only messages without plain text alternatives, hidden text elements, embedded form elements, encoding anomalies, excessive received hops, and timestamp drift between `Date` header and actual delivery time.

**Score computation:** Each signal that fires contributes to the `header_risk_score`. The combination method (additive, weighted, or otherwise) and individual signal weights are subject to research and will be calibrated against labeled data. Every signal that fires creates a `rule_hits` row for full auditability and explainability.

**Kafka input:** `analysis.headers`
**Kafka output:** `scores.header` — `{email_id, org_id, component: "header", score: int 0-100, fired_rules: [...]}`
**DB access:**
- **Reads:** `enriched_threats` (sender domain reputation), `rules` (active header rules)
- **Writes:** `rule_hits`

---

### 3.5 Attachment Analysis Service (Go)

**Responsibility:** Determine risk level of email attachments via hash intelligence and heuristics.

**Pipeline:**
1. For each attachment hash (SHA256):
   - Check `attachment_library.is_malicious` → if true, score = 90
   - Check against external TI (VirusTotal API if integrated) → cache in `enrichment_results`
2. Heuristic signals:
   - High entropy (> 7.5) → +20 (likely encrypted/packed)
   - Extension vs MIME mismatch (e.g., .pdf that's application/x-msdownload) → +30
   - Known dangerous extension (.exe, .scr, .bat, .ps1, .vbs, .js) → +25
   - Macro-enabled Office format (.docm, .xlsm) → +20
3. Per-email attachment score = `max(individual_attachment_scores)`

**Kafka input:** `analysis.attachments`
**Kafka output:** `scores.attachment` — `{email_id, org_id, component: "attachment", score: 30, attachment_details: [...]}`
**DB access:**
- **Reads:** `attachment_library` (hash lookup)
- **Writes:** `attachment_library` (new hashes), `enrichment_results` (if external TI queried)

---

### 3.6 NLP Analysis Service (Python — FastAPI)

**Responsibility:** Evaluate phishing risk of email text content through natural language analysis. Produces a `content_risk_score` (0–100) and structured facet outputs that downstream services use for campaign detection and verdict determination.

> **Research status:** The analysis facets below are architecturally defined. The specific model architectures, training methodology, and score composition method are under active research. The candidate models listed are starting points, not final selections.

**Analysis facets (functional requirements):**

| Facet | Function | Output |
|-------|----------|--------|
| Urgency Detection | Identify language patterns that create false urgency (e.g., "act now", "account suspended") | urgency_score (0.0–1.0) |
| Intent Classification | Classify the email's apparent goal | intent_label + confidence |
| Brand Impersonation | Detect attempts to impersonate known brands through text content and sender identity | impersonation_score (0.0–1.0) |
| Deception Language | Identify manipulative or deceptive linguistic patterns | deception_score (0.0–1.0) |

**Intent labels:** `credential_harvesting`, `malware_delivery`, `bec` (business email compromise), `scam`, `legitimate`

**Candidate model architectures (subject to research):**
- Fine-tuned DistilBERT (66M params) for urgency and intent classification
- NER + cosine similarity for brand impersonation
- Fine-tuned TinyBERT (14.5M params) for deception detection
- All candidates target INT8 quantization via ONNX Runtime for CPU inference

**Score composition:** The method for combining facet scores into a single `content_risk_score` is subject to research. The combination must be explainable — the individual facet scores are always preserved alongside the composite score for transparency.

**Training data (candidate corpora):**
- Nazario phishing corpus, IWSPA-AP 2.0, Nigerian fraud corpus (phishing examples)
- Enron email dataset, Ling-Spam (legitimate examples)
- Custom labeled data from TI-enriched emails

**Deployment:**
- Served as a FastAPI HTTP microservice with a Kafka consumer wrapper
- Horizontal scaling: multiple consumer instances in the same consumer group
- Timeout: 10s. On timeout: score = 50.

**Kafka input:** `analysis.text`
**Kafka output:** `scores.nlp` — `{email_id, org_id, component: "nlp", score: int 0-100, facets: {urgency: float, intent: string, intent_confidence: float, impersonation: float, deception: float}}`
**DB access:** None (stateless inference service)

---

### 3.7 Score Aggregator Service (Go + Redis)

**Responsibility:** Collect all component scores for an email and produce a unified payload containing all available scores when all expected components have reported (or on timeout). This service does not perform scoring — it is a gather/synchronization barrier.

**Design note:** Aggregator instances are stateless workers. All aggregation state lives in Redis, which means events for the same email may be processed by different instances. This is correct and intentional — Redis is the single source of truth for aggregation state, not instance-local memory.

**State model (in Redis):**
```
Key: aggregator:{email_id}
Value: {
    expected: ["url", "header", "attachment", "nlp"],
    received: {
        "url": {score: 72, details: {...}, received_at: ...},
        "header": {score: 45, details: {...}, received_at: ...}
    },
    created_at: timestamp
}
TTL: 120 seconds (auto-cleanup of abandoned entries)
```

**Flow:**
1. Consume `analysis.plans` → create entry in Redis with expected list
2. Consume `scores.url`, `scores.header`, `scores.attachment`, `scores.nlp` → update Redis entry
3. After each score received, check: are all expected scores present?
   - **YES** → package all component scores into a single payload, publish to `emails.scored`, delete Redis key
   - **NO** → wait for more
4. **Timeout:** Background goroutine checks entries older than 30s. If expired:
   - Flag `partial_analysis: true`, list missing components
   - Publish to `emails.scored` with whatever scores have arrived

**Output payload:** The `emails.scored` message contains the raw component scores, all component detail payloads, and metadata about which components are present or missing. It does NOT contain a final composite score — final scoring is the responsibility of the Decision Engine (SVC-08).

If a component is absent (email has no URLs), this is indicated in the `missing_components` field.

**Kafka input:** `analysis.plans`, `scores.url`, `scores.header`, `scores.attachment`, `scores.nlp`
**Kafka output:** `emails.scored` — `{email_id, org_id, internal_id, fetched_at, url_score, header_score, attachment_score, nlp_score, partial_analysis: bool, missing_components: [], component_details: {...}}`
**DB access:** None (Redis state only)

---

### 3.8 Decision Engine / Verdict Service (Go)

**Responsibility:** This is the terminal processing block for each email. It receives collected component scores from the Aggregator, computes the final composite risk score, determines the verdict, manages campaign lifecycle, and persists all results. Campaign context feeds back into scoring for future emails.

> **Research status:** The method for combining component scores into a final `risk_score` is under active research. The score-to-verdict thresholds below are preliminary and subject to calibration. The campaign-informed scoring mechanism is architecturally defined but not yet implemented.

**Functional pipeline:**

**Step 1 — Final Score Computation:**
Receives individual component scores (`url_score`, `header_score`, `attachment_score`, `nlp_score`) from the `emails.scored` payload. Combines them into a single `risk_score` (0–100). The combination method is subject to research — it must be explainable, and the individual component scores are always preserved alongside the composite for transparency. If a component is missing (email had no URLs), this must be accounted for rather than defaulting to a neutral value.

**Step 2 — Rule Engine:**
Load active rules from `rules` table (cached in-memory, refreshed every 60s). Evaluate rules against the scored email — each firing rule adjusts the score by its `score_impact` (-100 to +100). Rules provide a transparent, auditable mechanism for score adjustment independent of the ML-derived component scores.

**Step 3 — Verdict Determination:**
Map the final score to a verdict label. Preliminary thresholds (subject to calibration):
- 0–25: `benign`
- 26–50: `suspicious`
- 51–75: `phishing` (medium confidence)
- 76–100: `phishing` (high confidence) — or `malware` if attachment_score dominates

Verdict confidence is computed separately from risk score: it reflects certainty in the label assignment, not threat severity.

**Step 4 — Campaign Management:**
Compute campaign fingerprint from normalized sender domain, primary URL domain, subject template hash, and NLP intent classification. Upsert into `campaigns` table via `ON CONFLICT (fingerprint) DO UPDATE`. Perform SimHash near-duplicate detection against existing campaigns in Redis (per-org scoped). Associate the email with a matched or newly created campaign.

**Step 5 — Campaign-Informed Scoring:**
Campaign context enriches the scoring of subsequent emails. When an email matches an existing campaign with a high-risk history (high average `risk_score`, many member emails, or analyst-confirmed phishing verdicts), this campaign association serves as an additional signal that can elevate the email's final score. This creates a feedback loop: as a campaign accumulates evidence, new emails matching that campaign are scored with the benefit of that accumulated context. The specific mechanism for how campaign history adjusts scoring is subject to research.

**Step 6 — Persistence (single PostgreSQL transaction):**
- `UPDATE emails SET risk_score, header_risk_score, content_risk_score, url_risk_score, attachment_risk_score, campaign_id, analysis_metadata`
- `INSERT INTO verdicts` (append-only — the authoritative verdict record)
- `INSERT INTO rule_hits` (for each fired rule)
- `UPSERT campaigns` (update or create campaign)

**Step 7 — Publish:**
Publish final verdict to `emails.verdict` for downstream consumption by Notification and Dashboard services.

**Kafka input:** `emails.scored`
**Kafka output:** `emails.verdict` — `{email_id, org_id, verdict_label, confidence, risk_score, url_risk_score, header_risk_score, content_risk_score, attachment_risk_score, campaign_id, campaign_fingerprint, is_new_campaign, fired_rules: [...], partial_analysis: bool}`
**DB access:**
- **Reads:** `rules`, `campaigns`, `verdicts` (campaign history for campaign-informed scoring)
- **Writes:** `emails` (UPDATE scores), `verdicts`, `rule_hits`, `campaigns`

---

### 3.9 Notification Service (Go)

**Responsibility:** Alert users/administrators about high-risk emails based on configurable thresholds.

**Channels:**
- Email alert (to org admin)
- Webhook (for SIEM/SOAR integration)
- WebSocket push (to Dashboard in real-time)
- Slack/Teams integration (optional)

**Logic:**
1. Consume `emails.verdict`
2. Check org notification preferences
3. If verdict meets threshold (e.g., score ≥ 70 or label = phishing/malware) → send alert
4. Rate limiting: max 1 alert per campaign per org per hour (prevent alert fatigue)

**Kafka input:** `emails.verdict`
**DB access:**
- **Reads:** `organisations` (notification preferences), `users` (contact info)

---

### 3.10 TI Feed Sync Service (Go)

**Responsibility:** Periodically fetch and ingest threat intelligence feeds into the shared TI database.

**Supported feeds:**
- PhishTank (verified phishing URLs)
- OpenPhish (community phishing URLs)
- URLhaus (malware distribution URLs)
- MalwareBazaar (malware hashes — for attachment_library)
- Abuse.ch ThreatFox (IOCs)
- Custom feeds (configurable via `feeds` table)

**Schedule:** Every 6 hours (configurable per feed)

**Flow:**
1. For each enabled feed in `feeds` table:
   - Fetch latest data from feed URL
   - Parse feed format (CSV, JSON, STIX)
   - Deduplicate against existing `enriched_threats` entries
   - Bulk upsert new/updated indicators
   - Update `feeds.last_fetched_at`
2. After all feeds complete: `REFRESH MATERIALIZED VIEW CONCURRENTLY` for all MVs
3. Update Redis TI cache (for fast URL Analysis lookups)

**DB access:**
- **Reads/Writes:** `enriched_threats`, `feeds`, `attachment_library` (malware hashes)

---

### 3.11 API / Dashboard Service (Go + React)

**Responsibility:** Serve the web dashboard and REST API for users, analysts, and integrations.

**API endpoints:**
- `POST /api/v1/scan` — Submit email for analysis (API Adapter for Email Ingestion)
- `GET /api/v1/emails` — List emails with filtering/pagination
- `GET /api/v1/emails/:id` — Email detail with all scores and verdicts
- `GET /api/v1/campaigns` — Campaign list
- `GET /api/v1/campaigns/:id` — Campaign detail with member emails
- `GET /api/v1/dashboard/stats` — Org-level statistics (from materialized views)
- `POST /api/v1/verdicts` — Analyst verdict submission
- `CRUD /api/v1/rules` — Rule management
- `CRUD /api/v1/api-keys` — API key management
- `GET /api/v1/feeds` — TI feed health status

**Authentication:** JWT tokens + API keys (scoped per org)
**Real-time:** WebSocket endpoint for live verdict stream (consumes `emails.verdict` internally)

**DB access:** All tables (read-heavy, write for analyst actions)

---

## 4. Kafka Topic Topology

```
Topic                    Partitions  Retention  Producers              Consumers
─────────────────────────────────────────────────────────────────────────────────
emails.raw               6           48h        Email Ingestion        Email Parser
analysis.urls            6           24h        Email Parser           URL Analysis
analysis.attachments     3           24h        Email Parser           Attachment Analysis
analysis.headers         6           24h        Email Parser           Header Analysis
analysis.text            6           24h        Email Parser           NLP Analysis
analysis.plans           6           24h        Email Parser           Score Aggregator
scores.url               6           24h        URL Analysis           Score Aggregator
scores.header            6           24h        Header Analysis        Score Aggregator
scores.attachment        3           24h        Attachment Analysis    Score Aggregator
scores.nlp               6           24h        NLP Analysis           Score Aggregator
emails.scored            6           48h        Score Aggregator       Decision Engine
emails.verdict           6           7d         Decision Engine        Notification, Dashboard
```

Partition key: `email_id` (ensures all messages for the same email go to the same partition *within each topic*, enabling ordered processing per email within each consumer group).

**Important:** Same partition key does NOT guarantee cross-topic co-location (e.g., the URL score and header score for the same email may be processed by different aggregator instances). This is by design — the Score Aggregator (SVC-07) uses Redis as shared state, making aggregator instances stateless workers. Any instance can process any score event for any email.

---

## 5. Database Architecture

### 5.1 Shared PostgreSQL with Service-Owned Tables

Each service owns specific tables and accesses others read-only.
This is a pragmatic tradeoff: true DB-per-service is overkill for this scale.

### 5.2 Service-to-Table Access Matrix

| Table | Ingestion | Parser | URL Analysis | Header Analysis | Attachment Analysis | NLP | Aggregator | Decision Engine | TI Sync | API/Dashboard |
|-------|-----------|--------|-------------|-----------------|--------------------|----|-----------|-----------------|---------|---------------|
| `emails` | R (dedup) | **W** | - | - | - | - | - | **W** (update scores) | - | R |
| `email_urls` | - | **W** | R | - | - | - | - | - | - | R |
| `email_attachments` | - | **W** | - | - | R | - | - | - | - | R |
| `email_recipients` | - | **W** | - | - | - | - | - | - | - | R |
| `attachment_library` | - | **W** | - | - | R/**W** | - | - | - | **W** | R |
| `enriched_threats` | - | - | R/**W** | R | - | - | - | - | **W** | R |
| `enrichment_results` | - | - | **W** | - | **W** | - | - | - | - | R |
| `enrichment_jobs` | - | - | **W** | - | - | - | - | - | - | R |
| `verdicts` | - | - | - | - | - | - | - | R/**W** | - | R/**W** (analyst) |
| `campaigns` | - | - | - | - | - | - | - | R/**W** | - | R |
| `rules` | - | - | - | R | - | - | - | R | - | R/**W** |
| `rule_hits` | - | - | - | **W** | - | - | - | **W** | - | R |
| `feeds` | - | - | - | - | - | - | - | - | R/**W** | R |
| `organisations` | R | - | - | - | - | - | - | - | - | R/**W** |
| `users` | - | - | - | - | - | - | - | - | - | R/**W** |
| `api_keys` | R | - | - | - | - | - | - | - | - | R/**W** |
| `audit_log` | - | - | - | - | - | - | - | - | - | **W** |
| `mv_*` views | - | - | - | - | - | - | - | - | refresh | R |

**R** = Read, **W** = Write, **R/W** = Both

### 5.3 Privacy & Data Lifecycle

| Data | Retention | Purge Strategy |
|------|-----------|---------------|
| `emails.body_plain`, `emails.body_html` | Configurable per org (default 30 days) | Scheduled job NULLs columns |
| `emails` metadata (sender, headers, scores) | Indefinite | Soft delete via `deleted_at` |
| `enriched_threats` | Indefinite (TI value) | Soft delete stale entries |
| `enrichment_results` | TTL-based (`expires_at` column) | Staleness sweep re-fetches |
| `verdicts` | Indefinite (audit trail) | Append-only, never deleted |
| `attachment_library` binaries | 90 days | S3 lifecycle policy |
| `attachment_library` hashes | Indefinite | Hash-only, no PII |
| `audit_log` | Indefinite | Append-only compliance log |
| Kafka `emails.raw` | 48 hours | Topic retention config |
| Kafka `scores.*` | 24 hours | Topic retention config |

---

## 6. Campaign Detection

### 6.1 Fingerprint Algorithm

Campaigns are groups of related phishing emails sharing common infrastructure or tactics.

```
fingerprint = SHA256(
    normalize(sender_domain) + "|" +
    normalize(primary_url_domain) + "|" +
    template_hash(subject) + "|" +
    intent_classification
)
```

Where:
- `normalize(domain)` = lowercase, strip TLD variations
- `template_hash(subject)` = replace proper nouns/numbers with placeholders, then hash
  - "Your PayPal account #12345 needs verification" → "Your {BRAND} account #{NUM} needs verification"
- `intent_classification` = from NLP service

### 6.2 Near-Duplicate Detection

For emails that don't match an existing campaign fingerprint exactly:
1. Compute SimHash of email body text
2. Check Hamming distance against recent campaign SimHashes in Redis (scoped per org: `simhash:{org_id}:{campaign_id}`)
3. If distance ≤ 3 → associate with existing campaign
4. If distance > 3 → potential new campaign seed

### 6.3 Campaign Lifecycle

```
New email verdict → Compute fingerprint
    ↓
Lookup in campaigns table
    ↓ (match)                    ↓ (no match)
UPDATE last_seen,            Check SimHash similarity
  increment count                ↓ (similar)          ↓ (no match)
                             Link to campaign       Create new campaign
                                                    if score ≥ 50
```

---

## 7. Deduplication Strategy

| Level | Method | Where | Purpose |
|-------|--------|-------|---------|
| Exact email dedup | `(org_id, message_id)` unique constraint | Email Ingestion | Prevent re-processing duplicate deliveries |
| URL score cache | Redis key `url_score:{sha256(url)}` TTL 6h | URL Analysis | Skip enrichment for recently-scored URLs |
| Attachment hash dedup | `attachment_library.sha256` unique | Email Parser | Global dedup — same attachment = same risk |
| Near-duplicate email | SimHash with Hamming distance ≤ 3 | Decision Engine | Reuse cached verdict, link to campaign |
| TI indicator dedup | `enriched_threats.url` unique | TI Feed Sync | Prevent duplicate TI entries across feeds |

---

## 8. Error Handling & Resilience

| Failure | Behavior | Rationale |
|---------|----------|-----------|
| URL enrichment timeout | Return cached data or neutral score 50 | External services are unreliable |
| ML inference timeout (5s URL, 10s NLP) | Return score 50 | Better partial analysis than no analysis |
| Kafka consumer lag > 10k messages | Auto-scale consumer instances | Horizontal scaling via consumer groups |
| DB connection failure | Retry with exponential backoff (3 attempts) | Transient failures are common |
| Score Aggregator timeout (30s) | Emit partial result with available scores | Users get results even when services degrade |
| TI feed fetch failure | Log error, continue with stale data | Feed will retry next cycle (6h) |

---

## 9. Observability

| Layer | Tool | Purpose |
|-------|------|---------|
| **Structured logging** | zerolog (Go), structlog (Python) | JSON logs with trace_id, email_id, service_name |
| **Distributed tracing** | OpenTelemetry → Jaeger | Trace an email through all services |
| **Metrics** | Prometheus + Grafana | Latency histograms, throughput, error rates, Kafka lag |
| **Health checks** | `/healthz` and `/readyz` per service | Kubernetes liveness/readiness probes |
| **Alerting** | Grafana alerts | Pipeline SLA violations, feed staleness, DB connection pool exhaustion |

**Key metrics to track:**
- End-to-end latency: `fetched_at` → `verdict.created_at` (target: <60s p95)
- Per-service processing time
- Kafka consumer group lag per topic
- ML inference latency (p50, p95, p99)
- TI feed freshness (seconds since last successful sync)
- Verdict distribution (% phishing, suspicious, benign over time)

---

## 10. Deployment Architecture

```
                    ┌─────────────────────────────────┐
                    │         Load Balancer            │
                    │       (Nginx / Traefik)          │
                    └───────────────┬──────────────────┘
                                    │
                    ┌───────────────┴──────────────────┐
                    │      API / Dashboard Service     │
                    │         (Go + React SPA)         │
                    └───────────────┬──────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
   PostgreSQL 15              Apache Kafka              Redis 7
   (persistent               (message broker)         (cache +
    storage)                                           state)
```

**Container orchestration:** Docker Compose (development), Kubernetes (production)
**Scaling strategy:**
- Stateless services (URL Analysis, Header Analysis, NLP, Attachment): horizontal scaling via Kafka consumer groups
- Stateful services (Score Aggregator): single instance with Redis state (Redis provides the persistence)
- DB: Single PostgreSQL instance with read replicas for dashboard queries
- Kafka: 3-broker minimum for production

---

## 11. Assumptions & Non-Goals

**Assumptions:**
- Target throughput: ~1 email/second steady state, burst to 50/s. Architecture supports this without exotic tuning.
- Single PostgreSQL instance with read replicas is sufficient. Sharding is not needed at this scale.
- Redis is ephemeral coordination — loss of Redis data causes temporary cache misses and aggregator state resets, but no data loss. All persistent state is in PostgreSQL.
- Raw email bytes through Kafka are acceptable at current scale (see §3.1 message size policy for scale-up path).
- The Email Parser (SVC-02) is intentionally consolidated. MIME parsing, URL extraction, attachment hashing, and header extraction are all part of the same decompose-and-fan-out operation. Splitting them into separate services would multiply Kafka hops and create coupling between decomposition stages for no benefit at this scale.

**Non-goals (current version):**
- No sandbox detonation or dynamic analysis of attachments. Attachment risk is hash-based + heuristic only.
- No cross-topic Kafka co-partitioning guarantee. Aggregator is designed around shared Redis state, not instance affinity.
- No real-time model retraining. ML models are updated via offline pipeline and deployed as new versions.
- No multi-region deployment. Single-region assumed.

---

## 12. Technology Stack Summary

| Component | Technology | Justification |
|-----------|-----------|---------------|
| Pipeline services | Go 1.24 | Performance, single binary, goroutine concurrency |
| ML inference | Python 3.11 + FastAPI | Native ML ecosystem, ONNX Runtime |
| URL ML model | XGBoost | Proven accuracy on tabular URL features |
| NLP models | DistilBERT, TinyBERT | 97% BERT accuracy at 60% the compute |
| Database | PostgreSQL 15 | Partitioning, JSONB, materialized views, RLS |
| Message broker | Apache Kafka | Durability, replay, consumer groups, exactly-once |
| Cache | Redis 7 | Sub-ms lookups for TI, dedup, aggregator state |
| Web dashboard | React + Vite | Modern SPA framework, fast builds |
| Containerization | Docker | Consistent environments across dev/prod |
| Orchestration | Kubernetes | Auto-scaling, health checks, rolling deploys |
| CI/CD | GitHub Actions | Existing workflow files in .github/ |
| Observability | OpenTelemetry + Grafana | Industry standard, vendor-neutral |
