# URL Analysis — Known Issues & Improvement Roadmap

CyberSiren's URL analysis pipeline has three detection layers: **ML scoring**
(LightGBM lexical model), **TI lookup** (Valkey domain cache fed by 4 threat
feeds), and **enrichment** (currently a stub). This document covers known gaps in
all three layers and a prioritised roadmap to address them.

---

## Table of Contents

1. [Current Architecture](#current-architecture)
2. [ML Classifier Issues](#ml-classifier-issues)
3. [TI Lookup Issues](#ti-lookup-issues)
4. [Enrichment Gaps](#enrichment-gaps)
5. [Verdict Logic Issues](#verdict-logic-issues)
6. [Normalization Gaps](#normalization-gaps)
7. [Improvement Roadmap](#improvement-roadmap)
8. [Existing Infrastructure to Leverage](#existing-infrastructure-to-leverage)

---

## Current Architecture

```
POST /scan { url }
  │
  ├─► ML Model (LightGBM, 28 lexical features)
  │     └─► score: 0–100, probability: 0.0–1.0
  │
  ├─► TI Cache Lookup (Valkey HGETALL on exact normalised domain)
  │     └─► matched: bool, risk_score: 0–100, threat_type: string
  │
  └─► Enricher (TODO — stub only)
        └─► (nothing yet)

Verdict logic:
  if TI matched AND ti_risk_score ≥ 80 → "phishing"
  else if ml_score ≥ 70              → "phishing"
  else if ml_score ≥ 40              → "suspicious"
  else                               → "legitimate"
```

---

## ML Classifier Issues

### Training Data

The model is **LightGBM** (28 features, 300 estimators, max_depth=8) trained on
~300K URLs from the PhiUSIIL dataset:

- 164K phishing (54.8%) — PhishTank, OpenPhish, and aggregator feeds
- 135K legitimate (45.2%) — **Cisco Umbrella top-1M** (almost all `www.`-prefixed)

### Issue 1: Naked Domain False Positives

| URL | Score | Label | Expected |
|-----|-------|-------|----------|
| `google.com` | 90 | phishing | legitimate |
| `www.google.com` | 0 | legitimate | legitimate |
| `x.com` | ~85 | phishing | legitimate |
| `t.co` | ~88 | phishing | legitimate |

**Root cause:** Legitimate training data is almost entirely `www.`-prefixed. The
model learned that `num_subdomains=0` correlates with phishing. Short naked
domains also produce high `char_continuation_rate` (0.50 vs training avg 0.38)
and `avg_subdomain_length=0`.

### Issue 2: Legitimate Subdomain False Positives

| URL | Score | Label | Expected |
|-----|-------|-------|----------|
| `meet.google.com` | ~70 | phishing | legitimate |
| `drive.google.com` | ~65 | suspicious | legitimate |
| `login.microsoftonline.com` | ~80 | phishing | legitimate |

**Root cause:** No domain reputation signal. The model sees
`{service}.{legit-brand}.com` and `{lure}.{fake-brand}.com` as structurally
identical — same subdomain count, similar hostname length.

### Issue 3: No Domain Reputation Feature

The 28-feature vector is entirely lexical. The **Cisco Umbrella top-1M CSV
exists in the repo** (`ml/data/top-1m.csv`) and was used during training to
build the `charProbTable` and `tldLegitProb` lookup tables — but it is **never
consulted at inference time** as a direct "is this domain popular?" signal.

### Issue 4: Overconfident Probabilities

The model outputs 0.90 probability for `google.com` — clearly miscalibrated.
Raw LightGBM outputs are not calibrated to reflect true posterior probabilities.

---

## TI Lookup Issues

### Issue 5: Exact-Domain-Only Matching

`IsBlocklisted()` in `shared/valkey/ti_cache.go` performs a single
`HGETALL ti_domain:{normalised_domain}` lookup. No parent-domain walking.

**Impact:**

| TI Entry | Lookup Domain | Result |
|----------|---------------|--------|
| `evil.com` | `evil.com` | ✅ Match |
| `evil.com` | `phishing.evil.com` | ❌ Miss |
| `evil.com` | `a.b.evil.com` | ❌ Miss |
| `*.evil.com` | `phishing.evil.com` | ❌ Miss (wildcards not expanded) |

Attackers routinely rotate subdomains under a blocklisted registrable domain.
The current implementation misses all of them.

### Issue 6: Path-Level TI Data Lost

The TI feeds (PhishTank, URLhaus, OpenPhish, ThreatFox) store **full URLs** in
`ti_indicators.indicator_value` (e.g., `https://evil.com/phish/login.html`).
But the Valkey cache only stores the extracted **domain**. The path component is
discarded during `RefreshDomainCache()`.

**Impact:** A feed entry for `https://legitimate-host.com/phishing-page` would
blocklist the entire domain `legitimate-host.com`, not just the malicious path.
And if the domain is common, it likely won't be in the TI at all — only the
specific phishing URL would be.

### Issue 7: No Domain-Only Feed Fallback

All 4 feeds ingest indicators as `indicator_type=url`. The cache refresh
extracts domains from these URLs. But:

- ThreatFox also provides `IOCType=domain` indicators — these are filtered out
  (current filter: `IOCType == "url"` only).
- Some phishing campaigns register throwaway domains — the **domain itself** is
  the indicator, not a specific URL path. Storing only the URL misses this.

### Issue 8: Limited Feed Coverage

Only 4 URL-focused feeds are ingested. Missing:

| Feed Type | Examples | Signal |
|-----------|----------|--------|
| IP blocklists | AbuseIPDB, Spamhaus DROP | Hosting infrastructure |
| Hash feeds | MalwareBazaar, VirusTotal | Attachment/payload matching |
| DNS sinkholes | Sinkhole lists, passive DNS | Known C2 resolution |
| Certificate transparency | crt.sh, Certstream | Newly registered lookalike certs |
| Domain reputation | DomainTools, WHOIS history | Registration patterns |

---

## Enrichment Gaps

### Issue 9: Enricher Is a Stub

`services/svc-03-url-analysis/internal/url/enricher.go` contains only:
```go
package url
// TODO: implement enricher.
```

No live enrichment signals are available at scan time. The following are
standard in phishing detection pipelines but entirely absent:

| Signal | Value | Effort |
|--------|-------|--------|
| **WHOIS domain age** | Domains < 30 days old are 10× more likely to be phishing | Medium |
| **SSL certificate issuer** | Let's Encrypt free certs are disproportionately used by phishing | Low |
| **SSL certificate age** | Certs issued < 7 days ago correlate with phishing | Low |
| **DNS MX/SPF/DKIM records** | Missing or misconfigured email auth = suspicious | Medium |
| **Passive DNS history** | First-seen date, resolution count, IP diversity | Medium |
| **HTTP redirect chain** | Phishing URLs often chain 3–5 redirects through shorteners | Medium |
| **Page content analysis** | Login form presence, brand logo detection, form action URL | High |
| **VirusTotal / URLScan API** | Community verdicts + full page rendering | Low (API call) |
| **Geo-IP of hosting** | Hosting in unusual jurisdictions for the claimed brand | Low |

---

## Verdict Logic Issues

### Issue 10: Hard TI Override Threshold

The current rule `if ti_risk_score >= 80 → phishing` is a hard cutoff with no
gradation. Problems:

- A TI match with `risk_score=79` is completely ignored in the verdict.
- No weighting between ML confidence and TI confidence.
- No way to express "TI says suspicious but not certain."

### Issue 11: No Signal Fusion

ML and TI run in parallel but their results are combined with simple if/else
logic, not probabilistic fusion. There's no way to express:

- "ML says 60% phishing AND TI says known-bad domain" → should be very high
  confidence phishing
- "ML says 30% phishing AND TI says no match AND domain is 10 years old" →
  should be very low confidence

### Issue 12: No Feedback Loop

There's no mechanism to feed confirmed verdicts (user reports, SOC analyst
decisions) back into the model or TI cache. False positives and false negatives
are not tracked or used to improve future scoring.

---

## Normalization Gaps

### Issue 13: eTLD+1 Not Exposed in Shared Package

`shared/normalization/` has `ExtractDomain()` and `NormalizeDomain()` but no
`ExtractRegisteredDomain()` using the public suffix list. This function exists
in the feature extractor (`golang.org/x/net/publicsuffix`) but is not reusable
from other packages. Both the TI cache (for domain walking) and the allowlist
would need it.

---

## Improvement Roadmap

### Tier 1 — Post-Processing, No Retraining

These can ship as Go code changes without touching the ML model.

#### 1A. Top-Domain Allowlist ⭐ P0

Load the existing `ml/data/top-1m.csv` (or a curated top-10K subset) into
memory at startup. Before returning the ML score, check if the URL's registered
domain is in the set. If it matches, clamp the score:

```go
registered := normalization.ExtractRegisteredDomain(url)
if rank, ok := topDomainRank[registered]; ok && rank <= 10_000 {
    if mlScore > 20 {
        mlScore = 20
    }
}
```

**What already exists:**
- `ml/data/top-1m.csv` — 1M entries, `rank,domain` format
- `feature_extractor.go` — `golang.org/x/net/publicsuffix` for eTLD+1 parsing

**What needs to be built:**
- Extract eTLD+1 helper into `shared/normalization/`
- `DomainAllowlist` struct: loads CSV at startup (top-10K ≈ 200 KB)
- Post-scoring clamp in `/scan` handler
- Config: `CYBERSIREN_ML__ALLOWLIST_TOP_N=10000`

**Impact:** Eliminates false positives for google.com, meet.google.com, x.com,
t.co, and all top-10K domains + their subdomains. Zero model changes.

#### 1B. TI Domain Walking ⭐ P0

When checking a URL like `phishing.evil.com`, walk up the domain hierarchy:

```
1. phishing.evil.com   → HGETALL ti_domain:phishing.evil.com
2. evil.com            → HGETALL ti_domain:evil.com           ← match!
```

Implementation in `IsBlocklisted()`:

```go
func (c *TICache) IsBlocklisted(ctx context.Context, domain string) (Result, error) {
    domain = NormalizeDomain(domain)
    labels := strings.Split(domain, ".")

    // Walk from full domain up to eTLD+1
    for i := 0; i < len(labels)-1; i++ {
        candidate := strings.Join(labels[i:], ".")
        result, err := c.lookupDomain(ctx, candidate)
        if err != nil { return Result{}, err }
        if result.Matched { return result, nil }
    }
    return Result{Matched: false}, nil
}
```

**Impact:** Catches all subdomain variants of blocklisted domains. Critical for
domains that rotate subdomains (common in phishing campaigns).

#### 1C. www-Normalization Fallback — P2

Before inference, if hostname lacks `www.`, also score `www.` + hostname and
take the minimum (most-legitimate) score:

```go
score1 := predict(url)
if !strings.HasPrefix(hostname, "www.") {
    score2 := predict("https://www." + hostname + path)
    score = min(score1, score2)
}
```

**Pros:** Directly addresses the `www.` training bias.
**Cons:** Doubles inference time for non-`www.` URLs. Combine with 1A for best
results.

#### 1D. Confidence Calibration (Platt Scaling) — P2

Apply sigmoid calibration on a held-out validation set to fix overconfident
probabilities:

```python
from sklearn.calibration import CalibratedClassifierCV
calibrated = CalibratedClassifierCV(model, method='sigmoid', cv='prefit')
calibrated.fit(X_val, y_val)
```

Won't fix ordering but reduces absolute probabilities (0.90 → ~0.55 for
google.com), moving misclassifications from "phishing" to "suspicious."

#### 1E. Configurable TI Threshold — P2

Make the TI override threshold configurable instead of hard-coded at 80:

```go
// config
type ScoringConfig struct {
    TIOverrideThreshold int `koanf:"ti_override_threshold" default:"80"`
}
```

---

### Tier 2 — Feature Engineering (Requires Model Retraining)

#### 2A. Add `domain_in_top_1m` Feature (F31) ⭐ P1

Binary feature: is the registered domain in Cisco Umbrella top-1M?

```python
top1m = set(pd.read_csv("top-1m.csv", header=None)[1])
def domain_in_top_1m(url):
    return 1 if tldextract.extract(url).registered_domain in top1m else 0
```

Would likely become the #1 most important feature by gain. The Go feature
extractor already parses eTLD+1, so inference-time implementation is
straightforward: load set, add one boolean → 29 features.

#### 2B. Add `domain_rank_log` Feature (F32) — P1

Log of domain rank for a smooth popularity signal:

| Domain | Rank | log₁₀(rank) |
|--------|------|-------------|
| google.com | 1 | 0.0 |
| example.com | 5,000 | 3.7 |
| unknown.xyz | 1,500,000 | 6.2 |

#### 2C. Add `is_subdomain_of_top_domain` Feature (F33) — P2

Specifically fixes `meet.google.com` — model learns that subdomains of top-10K
domains are safe, while subdomains of unknown domains are suspicious.

#### 2D. TLD Risk Category Feature (F34) — P2

Group TLDs into risk tiers based on Spamhaus/SURBL abuse-rate data:

| Tier | Example TLDs | Weight |
|------|-------------|--------|
| 0 (safe) | .com, .org, .edu, .gov | 0 |
| 1 (neutral) | .io, .co, .me, .app | 1 |
| 2 (risky) | .xyz, .top, .club, .loan | 2 |
| 3 (high risk) | .bond, .work, .click, .surf | 3 |

---

### Tier 3 — TI Pipeline Improvements

#### 3A. Path-Level TI Matching — P1

Store both the full URL and extracted domain in the Valkey cache. When scanning,
check the full normalised URL first, then fall back to domain:

```
1. HGETALL ti_url:https://evil.com/phish/login   → exact URL match
2. HGETALL ti_domain:evil.com                     → domain match
```

**Why it matters:** Distinguishes `https://legitimate-host.com/phishing-page`
(only the path is malicious) from `https://legitimate-host.com` (the domain
itself is fine).

#### 3B. Expand ThreatFox IOC Types — P1

Current filter: `IOCType == "url"`. Should also capture:

- `IOCType == "domain"` — standalone malicious domains
- `IOCType == "ip:port"` — C2 infrastructure
- `IOCType == "hash"` — for future attachment analysis

#### 3C. Domain-Only Feed Extraction — P2

During `RefreshDomainCache()`, extract and store both:

- The full URL (for path-level matching)
- The registered domain (for domain-level matching)
- The eTLD+1 (for subdomain walking)

This maximises cache hit rates across all matching strategies.

#### 3D. Additional Feed Sources — P3

| Feed | Type | Free? | Signal |
|------|------|-------|--------|
| AbuseIPDB | IP reputation | Yes (1K/day) | Hosting infra flagging |
| Spamhaus DROP | IP/CIDR | Yes | Known bad networks |
| MalwareBazaar | File hashes | Yes | Attachment matching |
| Certstream | CT log stream | Yes | Newly registered lookalike certs |
| SURBL | Domain lists | Free tier | Domain-level phishing/malware |

---

### Tier 4 — Training Data Improvements (Requires Retraining)

#### 4A. Balance www-Prefix Distribution ⭐ P0

The core data bias fix:

1. Strip `www.` from 50% of legitimate training URLs
2. Add naked versions of top-10K domains as explicit legitimate examples
3. Add `www.`-prefixed versions of known phishing URLs

Teaches the model that `www.` presence is not a phishing signal.

#### 4B. Augment with Short Legitimate URLs — P2

Add top-1K domains by traffic (google.com, x.com, t.co), URL shorteners
(bit.ly, tinyurl.com), and single-word domains from Tranco top-10K.

#### 4C. Use Tranco Instead of Cisco Umbrella — P2

[Tranco](https://tranco-list.eu/) averages multiple ranking sources over 30 days
(Umbrella, Majestic, Chrome UX Report, Cloudflare Radar). More resistant to
manipulation and more representative than Umbrella alone.

---

### Tier 5 — Enrichment Implementation

#### 5A. WHOIS Domain Age ⭐ P1

Domains registered < 30 days ago are 10× more likely phishing. Query via RDAP
(successor to WHOIS, structured JSON):

```go
type EnrichmentResult struct {
    DomainAgeDays    int
    RegistrarName    string
    SSLCertAgeDays   int
    SSLIssuer        string
    RedirectCount    int
    ResolvedIPs      []string
}
```

#### 5B. SSL Certificate Inspection — P1

Check certificate issuer, age, and SAN list. Let's Encrypt free certs with
< 7-day age on suspicious domains are a strong phishing signal.

#### 5C. HTTP Redirect Chain Analysis — P2

Follow redirects (up to 5 hops) and flag:

- Chains through URL shorteners (bit.ly → tinyurl → evil.com)
- Cross-domain redirects (paypal-login.com → evil.com)
- Redirect loops

#### 5D. External API Integration — P2

Query VirusTotal (4 req/min free), URLScan.io (public scans), or Google Safe
Browsing (free) for community verdicts. Cache results in Valkey with 1-hour TTL.

#### 5E. Passive DNS Lookup — P3

Query passive DNS (SecurityTrails, CIRCL) for:

- First-seen date of domain resolution
- IP diversity (many IPs = CDN/legitimate; few IPs = small hosting)
- Known sinkhole IP detection

---

### Tier 6 — Architecture Changes

#### 6A. Weighted Signal Fusion — P2

Replace hard if/else verdict logic with weighted scoring:

```
final = α × ml_score + β × ti_risk + γ × enrichment_score + δ × allowlist_bonus
```

Where weights are learned from labelled data or set by policy. Produces nuanced
verdicts that reflect confidence from multiple sources.

#### 6B. Two-Stage Model — P3

- **Stage 1 (current):** Fast LightGBM on lexical features (~5 ms).
- **Stage 2 (new):** If score is 30–70 (uncertain), fetch live signals (WHOIS,
  SSL, DNS) and run a second model (~500 ms). Keeps latency low for obvious
  cases.

#### 6C. Feedback Loop — P3

Track confirmed verdicts (user reports, SOC decisions) and:

1. Auto-add confirmed phishing URLs to TI cache
2. Auto-add confirmed false positives to allowlist
3. Periodically retrain ML model on accumulated labelled data

#### 6D. eTLD+1 Shared Package — P1

Extract the `publicsuffix.EffectiveTLDPlusOne()` logic from
`feature_extractor.go` into `shared/normalization/` so it can be reused by:

- TI cache (domain walking needs to know where to stop)
- Allowlist (match on registered domain, not full hostname)
- Enrichment (WHOIS lookup on registered domain)

---

## Priority Summary

| Priority | Fix | Layer | Effort | Retrain? |
|----------|-----|-------|--------|----------|
| **P0** | 1A — Top-domain allowlist | ML | ~2 hours | No |
| **P0** | 1B — TI domain walking | TI | ~3 hours | No |
| **P0** | 4A — Balance www-prefix training data | ML | ~1 day | Yes |
| **P1** | 2A — `domain_in_top_1m` feature | ML | ~2 hours + retrain | Yes |
| **P1** | 3A — Path-level TI matching | TI | ~4 hours | No |
| **P1** | 3B — Expand ThreatFox IOC types | TI | ~1 hour | No |
| **P1** | 5A — WHOIS domain age | Enrichment | ~1 day | No |
| **P1** | 5B — SSL certificate inspection | Enrichment | ~4 hours | No |
| **P1** | 6D — eTLD+1 shared package | Normalization | ~1 hour | No |
| **P2** | 1C — www-normalization fallback | ML | ~30 min | No |
| **P2** | 1D — Platt scaling calibration | ML | ~2 hours | Calibration |
| **P2** | 1E — Configurable TI threshold | Verdict | ~30 min | No |
| **P2** | 2B — `domain_rank_log` feature | ML | ~2 hours + retrain | Yes |
| **P2** | 2C — Subdomain-of-top feature | ML | ~1 hour + retrain | Yes |
| **P2** | 3C — Domain-only feed extraction | TI | ~2 hours | No |
| **P2** | 5C — Redirect chain analysis | Enrichment | ~4 hours | No |
| **P2** | 5D — External API integration | Enrichment | ~1 day | No |
| **P2** | 6A — Weighted signal fusion | Verdict | ~3 days | Optional |
| **P3** | 2D — TLD risk categories | ML | ~1 hour + retrain | Yes |
| **P3** | 3D — Additional feed sources | TI | ~1 week | No |
| **P3** | 4B — Short URL augmentation | ML | ~1 day | Yes |
| **P3** | 4C — Use Tranco ranking | ML | ~2 hours + retrain | Yes |
| **P3** | 5E — Passive DNS lookup | Enrichment | ~1 day | No |
| **P3** | 6B — Two-stage model | Architecture | ~1 week | Yes |
| **P3** | 6C — Feedback loop | Architecture | ~1 week | Ongoing |

---

## Existing Infrastructure to Leverage

| Asset | Location | Status |
|-------|----------|--------|
| Cisco Umbrella top-1M CSV | `ml/data/top-1m.csv` | ✅ 1M ranked entries |
| eTLD+1 parsing | `feature_extractor.go` L559–581 | ✅ Uses `golang.org/x/net/publicsuffix` |
| Domain normalization | `shared/normalization/url.go` | ✅ `NormalizeDomain()`, `ExtractDomain()` |
| TI cache interface | `shared/valkey/ti_cache.go` | ✅ `IsBlocklisted()` + `RefreshDomainCache()` |
| TI indicators table | `db/migrations/026_*` | ✅ Stores URL, domain, IP, hash types |
| 4 feed parsers | `svc-11-ti-sync/internal/ti/feeds/` | ✅ PhishTank, OpenPhish, URLhaus, ThreatFox |
| Training notebook | `ml/cybersiren-url-model.ipynb` | ✅ Full pipeline, ready to re-run |
| LightGBM model binary | `ml/model/url_model.txt` | ✅ Current 28-feature model |
| Enricher stub | `internal/url/enricher.go` | ❌ Package exists, no implementation |
| TLD legit probabilities | `feature_extractor.go` `tldLegitProb` | ✅ Derived from top-1M |
| Char probabilities | `feature_extractor.go` `charProbTable` | ✅ Derived from top-1M |
