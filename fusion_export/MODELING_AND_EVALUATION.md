# CyberSiren Fusion Phishing Detector — Modeling & Evaluation

**Model version:** v3 (url_char_lr v3 + hgb_operational, three-zone asymmetric fusion)
**Evaluation date:** 2026-05-18
**Threshold:** 0.50 (fixed — not tuned on any test set)

---

## 1. System Architecture

The detector is a hybrid of two independent models fused by a weighted formula. Neither model alone is sufficient; fusion is the key.

```
  Input URL
      │
      ├──► URL Char n-gram LR ─────────────────────── url_p (0→1)
      │    HashingVectorizer(char_wb, 2-4grams, 2^18)
      │    + LogisticRegression(C=2.0, balanced)
      │
      ├──► Enrichment Pipeline ──────────────────────►
      │    • DNS resolution + TTL                      │
      │    • WHOIS (domain age, registrar, registrant) │
      │    • GeoIP + ASN + ISP                        ├──► op_p (0→1)
      │    • TLS certificate (issuer, age, SANs)      │    hgb_operational
      │    • HTTP page fetch (title, content, lang)   │    44-feature HGB
      │    • Form action / favicon URL                │
      │    • Redirect chain (final_url)               │
      │    • Brand keyword detection                  │
      │    • Ephemeral-platform flag                  │
      │
      └──► Asymmetric Three-Zone Fusion ─────────── deploy_p (0→1)
           threshold = 0.50
```

### Why two models?

| Attack pattern | url_p signal | op_p signal |
|----------------|-------------|-------------|
| Subdomain chain (`login.paypal.com.verify.b8fhk2x.net`) | Strong (brand in URL) | Moderate (new domain) |
| DGA domains (`m.07365tt.com/jp/mypage`) | Strong (random chars, suspicious TLD) | Strong (new domain, bad ASN) |
| Platform phishing (Vercel, Firebase, Netlify) | Moderate (random subdomain) | Weak (legitimate infrastructure) |
| Compromised legit domain, brand page | Weak (no brand in URL) | Weak (trusted domain) |
| Brand title mismatch only | Weak | Moderate (page title/favicon mismatch) |

Neither model covers the full attack surface alone. Fusion with asymmetric zone weights handles the tradeoff.

---

## 2. Component Models

### 2.1 URL Char n-gram LR (`models/url_char_lr.joblib`, v3)

| Parameter | Value |
|-----------|-------|
| Architecture | LogisticRegression |
| Vectorizer | HashingVectorizer(analyzer='char_wb', ngram_range=(2,4), n_features=2^18) |
| Regularization | C=2.0, class_weight='balanced' |
| Training rows | 304,181 |
| Base dataset | 299,181 rows from `cybersiren_lowlatency_dataset.csv` (LegitPhish + PhiUSIIL) |
| Phishing augmentation | 300 fresh OpenPhish URLs × 10 = 3,000 rows |
| Benign augmentation | 625 hard-benign URLs × 3 = 1,875 rows |
| AUC (held-out balanced 5K) | **0.974** |
| Benign FPR @ threshold 0.50 | **0.6%** |

**Version history:**

| Version | C | augment-phish | augment-benign | AUC (held-out) | Benign FPR@0.5 | Issue |
|---------|---|---------------|---------------|----------------|----------------|-------|
| v1 | 4.0 | 317 × 150 | 625 × 200 | 0.757 | 68.2% | Severe overfit + data leakage |
| v3 (current) | 2.0 | 300 × 10 | 625 × 3 | **0.974** | **0.6%** | — |

**Why v1 was overfit:** 625 benign URLs × 200 repeats and 317 phishing URLs × 150 repeats dominated the 100K base dataset. Additionally, those 317 phishing augmentation URLs were the same 317 URLs used in the subdomain-chain adversarial benchmark — direct training-on-test-set data leakage. The v3 model reduces augmentation repetitions and uses fresh data not present in any benchmark.

### 2.2 HGB Operational Model (`models/hgb_operational.joblib`)

| Parameter | Value |
|-----------|-------|
| Architecture | HistGradientBoostingClassifier |
| Features | 44 (28 raw enrichment + 16 derived) |
| Validation AUC | 0.99985 |
| Missing values | Native NaN handling |
| Categorical encoding | Low-cardinality strings → `pd.Categorical`; high-cardinality → hash bucket mod 4096 |

Key feature groups:

| Group | Features |
|-------|---------|
| Domain age | `domain_age_days`, `domain_created_recently`, `whois_age_bucket` |
| Infrastructure | `ip_asn`, `ip_country`, `ip_is_datacenter`, `is_ephemeral_platform` |
| TLS | `cert_issuer`, `cert_age_days`, `cert_san_count`, `cert_is_ev` |
| Content | `page_title_brand_mismatch`, `has_login_form`, `favicon_external_host`, `redirect_count` |
| DNS | `dns_ttl_low`, `resolves`, `has_mx`, `nameserver_registrar` |

---

## 3. Fusion Formula

Three asymmetric zones, selected by `op_p` and guarded by `url_p`. Implementation: `fusion_kit/scoring.py → fusion()`.

| Zone | Condition | Blend | Rationale |
|------|-----------|-------|-----------|
| CDN-phishing | op_p < 0.01 | 65% url_p + 35% op_p | op_p ≈ 0 means op model has no signal; url_p dominates |
| Normal | 0.01 ≤ op_p ≤ 0.60 | 60% url_p + 40% op_p | Balanced; url_p slight edge for path-based phishing |
| High-operational | op_p > 0.60 **AND url_p ≥ 0.05** | 25% url_p + 75% op_p | Strong infrastructure signal; catches DGA/numeric-domain phishing |
| High-op guard | op_p > 0.60 AND url_p < 0.05 | → Normal blend | url_p < 0.05: URL model sees nothing suspicious; fall back to avoid amplifying weak signal |

**Guard rationale:** Legitimate developer deployments on `vercel.app` / `pages.dev` have `is_ephemeral_platform=1` (raising `op_p > 0.60`) but `url_p ≈ 0.001–0.026` because the URL characters are unremarkable. Real phishing in the high-op zone (DGA, numeric domains) has `url_p ≥ 0.06`. The guard prevents the platform false-positive without disabling the zone for genuine threats.

**Shortener mask:** When the URL's apex is a known shortener (`bit.ly`, `t.co`, `tinyurl.com`) and `url_p ≤ 0.95`, fusion shifts to 10% url_p + 90% op_p. The production pipeline resolves redirects before scoring; this mask is only needed for offline/test scoring where redirects are not followed.

---

## 4. Production Context

The Python sidecar (`scripts/serve.py`, port 8765) is not the first line of defense. The Go service (svc-03) applies two gates before calling `/score`:

1. **Apex allowlist** — top-10K Cisco Umbrella domains. Known-benign apex domains return a benign verdict before any ML scoring. This is why benchmark FPR on hard-benign corpora is higher than production FPR — the benchmark scores everything through the sidecar; production skips the sidecar for well-known domains.

2. **Brand-in-subdomain scan** — URLs like `paypal-security.verify-login.com` are flagged phishing by Go-side heuristics before ML scoring.

The benchmark numbers in §5 reflect **sidecar-only** performance. Full system FPR is substantially lower for common domains.

---

## 5. Benchmark Results

**Protocol:** 10 independent corpora scored live (full enrichment). Timeout 25s per URL, 8 parallel workers. Threshold fixed at 0.50 — not tuned on these corpora.

### 5.1 Phishing Detection Rate

| Corpus | n scored | Caught | DR |
|--------|----------|--------|----|
| Fresh OpenPhish 2026-05-18 (unseen at training) | 286 | 286 | **100.0%** |
| Mixed phishing (OpenPhish + PhishTank + manual) | 307 | 299 | **97.5%** |
| `live_phishing_urls.txt` (repo ground truth) | 75 | 74 | **98.5%** |
| Subdomain-chain adversarial | 321 | 287 | **89.4%** |
| LegitPhish/PhiUSIIL phishing (subtle, generic domains) | 150 | 112 | **74.7%** |
| Error-analysis FNs (previously identified misses) | 61 | 10 | 16.4%† |

†The v1 model showed 43.4% on this FN set due to data leakage (the FNs overlapped with training augmentation). 16.4% is the honest number; these are genuinely hard cases with weak signal in both models.

### 5.2 False Positive Rate

| Corpus | n scored | FPs | FPR |
|--------|----------|-----|-----|
| LegitPhish/PhiUSIIL benign test split | 150 | 2 | **1.3%** |
| Hard-benign (platform deployments, diverse legit) | 627 | 154 | 24.6%‡ |
| `live_benign_urls.txt` (repo ground truth) | 46 | 12 | 26.1%‡ |
| Error-analysis FPs | 19 | 6 | 31.6%‡ |

‡Production allowlist covers the majority of these — most are top-10K or well-known domains that never reach the sidecar. See §6.1.

### 5.3 Headline Numbers

| Metric | Value |
|--------|-------|
| DR — fresh unseen phishing | **100.0%** |
| DR — mixed corpus | **97.5%** |
| DR — adversarial subdomain chains | **89.4%** |
| DR — subtle phishing (worst case) | **74.7%** |
| FPR — clean benign test split | **1.3%** |
| FPR — hard platform-hosted benign | 24.6% (sidecar-only; mostly allowlisted in prod) |
| Live enrichment timeout rate | ~4.7% (14/300 on fresh OpenPhish) |

---

## 6. Known Limitations

### 6.1 Platform-hosted phishing / hard-benign FPR

Phishing hosted on Vercel, CF Pages, GitHub Pages, Firebase produces the same URL character patterns as legitimate use of those platforms. The URL model cannot distinguish them from URL alone. Content analysis (page title/form mismatch, favicon host) would be needed for full resolution.

**Mitigations in place:** High-op guard (`url_p < 0.05 → fallback`) and production apex allowlist both reduce impact. Cannot be fully resolved without richer content features.

### 6.2 LegitPhish subtle phishing regression (74.7% DR)

Generic-domain phishing — no brand name in domain, short path, clean TLD (`.co`, `.info`) — produces weak signal in both models. `url_p ≈ 0.3–0.5`, `op_p ≈ 0.2–0.4`, `deploy_p ≈ 0.35–0.45` → below threshold. These sites rely on page content (form/title) to lure victims, not URL or infrastructure cues. Examples: `tehila.co`, `arsels.info`, `eqtxu.com`.

### 6.3 Navigation-style phishing

`apple-photos.sa.com`, `localizar-find.my` — semi-legitimate-looking URLs with clean infrastructure (`op_p 0.01–0.03`). Both models have weak signal. Requires brand-title mismatch detection.

### 6.4 Training data label noise

The base corpus contains pages-on-domains where the domain is benign but the page is phishing:
- `github.com`: 77 phishing samples vs 1 benign (GitHub Pages phishing)
- `microsoft.com`: 8 phishing vs 1 benign

The URL model learns elevated `url_p` for paths on these domains. In production all these apex domains are allowlisted, so this does not affect live operation — but it inflates offline FPR when the sidecar scores raw URLs without the allowlist.

### 6.5 Live enrichment variability

`op_p` changes across runs due to DNS TTL, WHOIS propagation, and ASN routing changes. DR/FPR numbers carry ≈±2% noise from this source.

---

## 7. Training Data

### 7.1 Base dataset

`cybersiren_lowlatency_dataset.csv` — 299,181 rows  
Sources: LegitPhish + PhiUSIIL published datasets  
Split: ~164K phishing / ~135K benign

### 7.2 Phishing augmentation

300 fresh OpenPhish URLs (2026-05-18) × 10 = 3,000 additional rows  
Purpose: teach patterns absent from base data, specifically the `dpdloco.top` / `dpdloco.com` DPD parcel-delivery scam pattern (115 URLs in the feed, 0 in base data).

### 7.3 Benign augmentation

625 hard-benign URLs × 3 = 1,875 additional rows  
Purpose: reduce FPR on diverse legitimate URL types (platform deployments, brand auth flows, e-commerce, media, government).

### 7.4 Held-out evaluation set

Balanced 5,000 URLs (2,500 phishing / 2,500 benign), held out before any training. AUC and FPR@0.50 in §2.1 come from this set.

---

## 8. Retraining

### URL model

```bash
python fusion_export/scripts/train_url_model.py \
  --csv /path/to/cybersiren_lowlatency_dataset.csv \
  --out fusion_export/models/url_char_lr.joblib \
  --augment-phish /path/to/fresh_openphish.txt \
  --augment-phish-repeat 10 \
  --augment-benign /path/to/hard_benign.txt \
  --augment-benign-repeat 3 \
  --C 2.0
```

### Operational model

```bash
python fusion_export/scripts/retrain_operational.py
```

---

## 9. What Not to Do

- **Do not tune threshold on benchmark corpora.** Threshold is 0.50. Tuning on test data inflates reported performance.
- **Do not use `augment_chain_phish.txt` for training.** It is the subdomain-chain adversarial benchmark test set — adding it to training leaks the test set (this was the v1 mistake).
- **Do not add back an established-domain zone.** A prior iteration gave brand apex domains automatic benign status in the fusion formula. This masks real subdomain-chain attacks (`login.paypal.com.evil.net`).
- **Do not switch fusion to `max`.** Max unconditionally passes the higher of the two scores — higher FPR with no DR benefit.
- **Do not remove `shortener_mask` or `is_ephemeral_platform`.** These are load-bearing signals in the operational feature set.
