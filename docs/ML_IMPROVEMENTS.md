# ML URL Classifier — Known Issues & Improvement Roadmap

## Current State

The URL classifier is a **LightGBM** model (28 lexical features, 300 estimators,
max_depth=8) trained on ~300K URLs from the PhiUSIIL dataset:

- 164K phishing (54.8%) — aggregated from PhishTank, OpenPhish, and other feeds
- 135K legitimate (45.2%) — sourced from **Cisco Umbrella top-1M**

The model scores URLs purely on structural/lexical features (length, entropy,
subdomain count, hyphens, TLD probability, sensitive keywords, etc.). It has no
awareness of domain reputation, brand ownership, or real-time signals.

---

## Known Issues

### 1. Naked Domain False Positives

| URL | Score | Label | Expected |
|-----|-------|-------|----------|
| `google.com` | 90 | phishing | legitimate |
| `www.google.com` | 0 | legitimate | legitimate |
| `x.com` | ~85 | phishing | legitimate |
| `t.co` | ~88 | phishing | legitimate |

**Root cause:** The legitimate training data (Cisco Umbrella) predominantly uses
`www.`-prefixed URLs. The model learned that `num_subdomains=0` correlates with
phishing because almost all its legitimate examples have at least one subdomain
(`www`). Short naked domains also produce:

- High `char_continuation_rate` (0.50 vs training avg 0.38)
- `avg_subdomain_length=0` (rare in legitimate training data)
- Low `url_length` (the model saw few short legitimate URLs)

### 2. Legitimate Subdomain False Positives

| URL | Score | Label | Expected |
|-----|-------|-------|----------|
| `meet.google.com` | ~70 | phishing | legitimate |
| `drive.google.com` | ~65 | suspicious | legitimate |
| `login.microsoftonline.com` | ~80 | phishing | legitimate |

**Root cause:** The model cannot distinguish `{service}.{legit-brand}.com` from
`{lure}.{fake-brand}.com`. Features like `num_subdomains=1` and
`hostname_length` are similar in both cases. The model has no concept of brand
ownership or domain trust.

### 3. No Domain Reputation Signal

The feature vector (F01–F30) is entirely lexical. There is no feature that says
"this registered domain is ranked #1 globally." The **Cisco Umbrella top-1M CSV
exists in the repo** (`ml/data/top-1m.csv`) and is used during training to build
the `charProbTable` and `tldLegitProb` lookup tables — but it is **never
consulted at inference time** as a direct "is this domain popular?" signal.

---

## Proposed Fixes

### Tier 1 — No Retraining Required (Post-Processing)

These can be implemented in Go in the scan endpoint or as a wrapper around the
model output.

#### 1A. Top-Domain Allowlist (Recommended — Quick Win)

Load the existing `top-1m.csv` (or a curated top-10K subset) into memory at
startup. Before returning the ML score, check if the URL's registered domain
appears in the list. If it does, clamp the score:

```go
// Pseudocode — in the /scan handler or a post-processing step
registered := extractRegisteredDomain(url) // already have eTLD+1 parsing
if rank, ok := topDomainRank[registered]; ok && rank <= 10_000 {
    if mlScore > 20 {
        mlScore = 20 // clamp — top-10K domains are overwhelmingly safe
    }
}
```

**What already exists:**
- `ml/data/top-1m.csv` — Cisco Umbrella top-1M, ranked. 1M entries, `rank,domain` format.
- `feature_extractor.go` — already imports `golang.org/x/net/publicsuffix` and
  extracts `eTLD+1` (registered domain). The parsing infrastructure is in place.

**What needs to be built:**
- A `TopDomainSet` or `DomainAllowlist` struct that loads the CSV at startup
  (only the first 10K entries — ~200 KB in memory).
- A post-scoring check in `main.go`'s `/scan` handler that clamps the score.
- A config toggle: `CYBERSIREN_ML__ALLOWLIST_ENABLED=true` (default true) and
  `CYBERSIREN_ML__ALLOWLIST_TOP_N=10000`.

**Impact:** Eliminates false positives for google.com, x.com, t.co,
meet.google.com, drive.google.com, and all other top-10K domains and their
subdomains. Zero model changes.

#### 1B. www-Normalization Fallback

Before inference, if the hostname lacks `www.`, also score `www.` + hostname and
take the **minimum** (most-legitimate) score:

```go
score1 := predict(url)
if !strings.HasPrefix(hostname, "www.") {
    score2 := predict("https://www." + hostname + path)
    score = min(score1, score2)
}
```

**Pros:** Directly addresses the `www.` bias without any external data.
**Cons:** Doubles inference time for non-`www.` URLs. Can be combined with 1A.

#### 1C. Confidence Calibration (Platt Scaling)

The model outputs raw probabilities that are poorly calibrated (0.90 for
`google.com` is clearly wrong). Apply sigmoid calibration on a held-out
validation set:

```python
from sklearn.calibration import CalibratedClassifierCV
calibrated = CalibratedClassifierCV(model, method='sigmoid', cv='prefit')
calibrated.fit(X_val, y_val)
```

This won't fix the ordering (google.com will still rank higher than it should)
but will reduce the absolute probability, turning 0.90 → ~0.55, which moves the
label from "phishing" to "suspicious."

---

### Tier 2 — Feature Engineering (Requires Retraining)

#### 2A. Add `domain_in_top_1m` Feature (F31)

Add a binary feature: is the registered domain in the Cisco Umbrella top-1M?

```python
top1m = set(pd.read_csv("top-1m.csv", header=None)[1])

def domain_in_top_1m(url):
    registered = tldextract.extract(url).registered_domain
    return 1 if registered in top1m else 0
```

This is the single highest-impact feature addition. The Go feature extractor
already parses eTLD+1, so the inference-time implementation is straightforward:
load top-1M set, add one boolean to the 28-feature vector → 29 features.

**Estimated impact:** Would likely become the #1 or #2 most important feature by
gain, directly encoding "is this a known legitimate domain?"

#### 2B. Add `domain_rank_log` Feature (F32)

Instead of binary, use the log of the domain's rank:

```python
def domain_rank_log(url):
    registered = tldextract.extract(url).registered_domain
    rank = top1m_rank.get(registered, 1_500_000)  # default: beyond top-1M
    return math.log10(rank)
```

- `google.com` → log10(1) = 0.0
- `example.com` → log10(5000) ≈ 3.7
- Unknown domain → log10(1500000) ≈ 6.2

The model learns a smooth relationship between popularity and legitimacy instead
of a hard binary cutoff.

#### 2C. Add `is_subdomain_of_top_domain` Feature (F33)

```python
def is_subdomain_of_top_domain(url):
    registered = tldextract.extract(url).registered_domain
    return 1 if registered in top_10k else 0
```

This specifically fixes `meet.google.com` — the model learns that subdomains of
top-10K domains are safe, while subdomains of unknown domains are suspicious.

#### 2D. TLD Risk Category Feature (F34)

Group TLDs into risk tiers instead of using raw `tld_legit_prob`:

| Tier | TLDs | Risk Weight |
|------|------|-------------|
| 0 (safe) | .com, .org, .net, .edu, .gov | 0 |
| 1 (neutral) | .io, .co, .me, .app | 1 |
| 2 (risky) | .xyz, .top, .club, .loan | 2 |
| 3 (high risk) | .bond, .work, .click, .surf | 3 |

Based on abuse rates from Spamhaus and SURBL data.

---

### Tier 3 — Training Data Improvements (Requires Retraining)

#### 3A. Balance www-Prefix Distribution

The core data bias: legitimate URLs are almost all `www.`-prefixed (Cisco
Umbrella), while phishing URLs rarely use `www.`. Fix:

1. Strip `www.` from 50% of legitimate training URLs
2. Add naked versions of top-10K domains as explicit legitimate examples
3. Add `www.`-prefixed versions of known phishing URLs

This teaches the model that `www.` presence/absence is not a phishing signal.

#### 3B. Augment with Short Legitimate URLs

The training set underrepresents short domains. Add:

- Top-1K domains by traffic (most are short: google.com, x.com, t.co)
- URL shortener domains (bit.ly, tinyurl.com, goo.gl)
- Single-word domains from Tranco top-10K

#### 3C. Use Tranco Instead of (or Alongside) Cisco Umbrella

[Tranco](https://tranco-list.eu/) is a research-grade domain ranking that
averages multiple lists (Umbrella, Majestic, Chrome UX Report, Cloudflare Radar)
over 30 days. It's more resistant to manipulation and more representative.

---

### Tier 4 — Architecture Changes (Significant Effort)

#### 4A. Two-Stage Model

- **Stage 1 (current):** Fast LightGBM on lexical features. If score is in the
  uncertain zone (30–70), pass to Stage 2.
- **Stage 2 (new):** Fetch live signals — WHOIS domain age, SSL certificate
  info, DNS record patterns — and run a second model that incorporates these.

This keeps latency low for obvious cases (score < 30 or > 70) while improving
accuracy for ambiguous URLs.

#### 4B. Ensemble with TI Confidence

Instead of the current hard rule (TI risk ≥ 80 → phishing), learn weights:

```
final_score = α × ml_score + β × ti_risk_score + γ × domain_rank_signal
```

Where α, β, γ are learned from labeled data. This produces more nuanced verdicts
than either signal alone.

---

## Recommended Implementation Order

| Priority | Fix | Effort | Impact | Retraining? |
|----------|-----|--------|--------|-------------|
| **P0** | 1A — Top-domain allowlist | ~2 hours | Eliminates all top-10K FPs | No |
| **P0** | 3A — Balance www-prefix | ~1 day | Fixes root cause | Yes |
| **P1** | 2A — `domain_in_top_1m` feature | ~2 hours (code) + retrain | Highest single-feature gain | Yes |
| **P1** | 2B — `domain_rank_log` feature | ~2 hours (code) + retrain | Smooth popularity signal | Yes |
| **P2** | 1B — www-normalization | ~30 min | Quick bias mitigation | No |
| **P2** | 2C — Subdomain-of-top feature | ~1 hour (code) + retrain | Fixes meet.google.com class | Yes |
| **P2** | 1C — Platt scaling | ~2 hours | Better calibration | Calibration only |
| **P3** | 3B — Short URL augmentation | ~1 day | Better short-domain accuracy | Yes |
| **P3** | 2D — TLD risk tiers | ~1 hour (code) + retrain | Better TLD signal | Yes |
| **P4** | 4A — Two-stage model | ~1 week | Handles uncertain zone | Yes (new model) |
| **P4** | 4B — TI ensemble | ~3 days | Better signal fusion | Yes |

---

## Existing Infrastructure to Leverage

| Asset | Location | Status |
|-------|----------|--------|
| Cisco Umbrella top-1M CSV | `ml/data/top-1m.csv` | ✅ In repo, 1M entries |
| eTLD+1 / public suffix parsing | `feature_extractor.go` L559-581 | ✅ Working, uses `golang.org/x/net/publicsuffix` |
| TLD legitimacy probabilities | `feature_extractor.go` `tldLegitProb` | ✅ Derived from top-1M during training |
| Character probabilities | `feature_extractor.go` `charProbTable` | ✅ Derived from top-1M during training |
| Training notebook | `ml/cybersiren-url-model.ipynb` | ✅ Full pipeline, ready to re-run |
| LightGBM model binary | `ml/model/url_model.txt` | ✅ Current 28-feature model |
| Python inference service | `python/url-ml/` | ✅ Loads model, exposes HTTP API |
| TI cache (Valkey) | `shared/valkey/ti_cache.go` | ✅ `IsBlocklisted()` + `RefreshDomainCache()` |

The P0 allowlist fix can be built entirely from existing components — `top-1m.csv`
+ `publicsuffix.EffectiveTLDPlusOne()` are already in the codebase.
