# CyberSiren — Changelog

---

## [2.2] — 2026-03-15 — TI Indicator Separation (Migration 026)

### Why This Change Was Made

The `enriched_threats` table was serving two incompatible roles:

1. **Email-observed threats** — URLs/domains/IPs extracted from emails and enriched
   with WHOIS, SSL certificates, geo/ASN, content analysis, etc. These are
   expensive to produce (multiple external API calls per indicator) and are the
   primary output of the enrichment pipeline.

2. **TI feed indicators** — raw indicators bulk-imported from external feeds
   (PhishTank, OpenPhish, URLhaus, etc.) that exist solely for matching against
   email-derived indicators. These are cheap to store and carry no enrichment data.

Mixing both roles in one table created several problems:

- **Wasted enrichment cost:** The enrichment pipeline could not distinguish feed-only
  rows from email-observed rows, risking unnecessary enrichment attempts on bulk feed
  data that never needs WHOIS/SSL/geo lookups.
- **Schema ambiguity:** Most enrichment columns (30+ fields) were NULL for feed-only
  rows, making the table semantically unclear and queries error-prone.
- **Ingestion bottleneck:** Bulk feed upserts contended with the enrichment write path
  on the same table and indexes.
- **Unclear auditability:** There was no way to answer "which TI feed recognised this
  email URL?" without inspecting `enriched_threats` rows that mixed both concerns.

### Schema Changes (Migration 026)

| Change | Description |
|--------|-------------|
| **New table: `ti_indicators`** | Normalised store for feed-origin indicators. Columns: `feed_id`, `indicator_type` (enum: url/domain/ip/cidr/hash/email_address), `indicator_value`, `threat_type`, `brand_id`, `threat_tags`, `confidence`, `risk_score`, `is_active`, `raw_metadata`. No enrichment fields. Unique on `(feed_id, indicator_type, indicator_value)`. |
| **New enum: `ti_indicator_type`** | `url`, `domain`, `ip`, `cidr`, `hash`, `email_address`. |
| **New table: `email_url_ti_matches`** | Junction/audit table linking `email_urls` to `ti_indicators`. Columns: `email_url_id`, `ti_indicator_id`, `match_type` (exact/domain/ip/cidr/hash), `matched_at`. Unique on `(email_url_id, ti_indicator_id)`. |
| **Data migration** | Feed-only rows in `enriched_threats` (where `is_global = TRUE`, `feed_id IS NOT NULL`, and not referenced by any `email_urls` row) are copied into `ti_indicators`. Source rows are not deleted (supervised cleanup recommended). |
| **`enriched_threats` role change** | Now reserved for email-observed threats only. `is_global` and `source_feed` columns are deprecated. New feed indicators must go to `ti_indicators`. |

### Architecture / Data Flow Changes

| Area | Before (v2.1) | After (v2.2) |
|------|---------------|--------------|
| **TI Feed Sync writes to** | `enriched_threats` | `ti_indicators` |
| **URL Analysis TI lookup reads** | `enriched_threats` | `ti_indicators` (feed match) + `enriched_threats` (existing enrichment for previously-seen email URLs) |
| **URL Analysis TI match audit** | (none) | Writes `email_url_ti_matches` row on each match |
| **Header Analysis reputation lookup** | `enriched_threats` | `ti_indicators` (via Redis `ti_domain:` cache) |
| **Enrichment target** | Both feed indicators and email URLs | Email-observed URLs only |
| **TI dedup constraint** | `enriched_threats.url` UNIQUE | `ti_indicators (feed_id, indicator_type, indicator_value)` UNIQUE — same indicator from different feeds is allowed |

### Benefits

- **Enrichment cost reduced:** Only URLs/domains/IPs extracted from emails are enriched.
  Feed indicators (which can number in the hundreds of thousands) are never sent through
  the expensive WHOIS/SSL/geo/content analysis pipeline.
- **TI ingestion faster and cleaner:** Bulk feed upserts target a dedicated, lean table
  (`ti_indicators`) with no enrichment columns. No contention with the enrichment write
  path. Idempotent via `ON CONFLICT` on the composite unique constraint.
- **Schema semantics clearer:** `enriched_threats` = email-observed + enriched.
  `ti_indicators` = feed-origin + normalised. No more NULL-heavy rows mixing both roles.
- **Better separation of passive intelligence from active analysis:** Feed data is
  passive reference material for matching. Email-observed threats are actively analysed
  artefacts. The schema now reflects this fundamental distinction.
- **Auditability:** `email_url_ti_matches` provides an explicit, queryable record of
  which feed indicator matched which email URL, and how (exact/domain/ip/cidr/hash).

### Terminology

| Term | Definition |
|------|-----------|
| **Feed indicator** | A normalised indicator (URL, domain, IP, CIDR, hash, email address) ingested from an external TI feed. Stored in `ti_indicators`. Not enriched. |
| **Email-observed threat** | A URL, domain, or IP extracted from an email during parsing. Candidate for enrichment. Stored in `enriched_threats` after enrichment. |
| **Enriched threat** | An email-observed threat for which enrichment has been performed (WHOIS, SSL, geo, ASN, content). The full record lives in `enriched_threats` + `enrichment_results`. |

### Migration File

`migrations/026_add_ti_indicators.up.sql`

### Documents Updated

| Document | Changes |
|----------|---------|
| `architecture-spec.md` | §3.3 URL Analysis, §3.4 Header Analysis, §3.10 TI Feed Sync, §5.2 Access Matrix, §5.3 Data Lifecycle, §7 Dedup — all updated to v2.2 |
| `architecture-spec-detail.html` | Steps 3a/3b/BG, §4 Access Matrix, §5 Redis Keys, §7 Dedup, §9 Privacy, §10 Infrastructure, §13 Table Origin, §14 Column-Level Flow — all updated to v2.2 |
| `architecture-diagram.html` | TI Feed Sync box, PostgreSQL table list, URL Analysis box, Header Analysis box — all updated to v2.2 |
| `database-schema.md` | Table count, `enriched_threats` redefined, `ti_indicators` §1.5 added, `email_url_ti_matches` §2.4 added, index strategy — all updated to v2.2 |
