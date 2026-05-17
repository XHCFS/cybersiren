# Sidecar Refactor + Sanity Battery — Agent Instructions

Read this entire document before touching any file.

---

## What You Are Doing and Why

The fusion sidecar currently blends two model scores:

- **`url_p`** — structural LightGBM on 33 URL-appearance features (fast, no network)
- **`op_p`** — HistGradientBoosting on live enrichment features: DNS, WHOIS, TLS, ASN, GeoIP, HTTP headers (slow, authoritative)

The `url_p` model was built as a **routing gate** — decide whether a URL is suspicious enough to bother enriching. It was never intended to contribute to the final verdict. It scores deep legitimate URLs like `github.com/login`, `accounts.google.com/o/oauth2/v2/auth`, and `signin.aws.amazon.com/signin?redirect_uri=console` at url_p ≈ 1.000 because path length, entropy, and sensitive-word features fire on any login flow regardless of whether the domain is legitimate. Fusing url_p into the final score — even asymmetrically — corrupts op_p with a signal that is structurally wrong on the most common legitimate URL patterns.

**The fix**: `deploy_p = op_p`. The `url_p` score stays in the response for observability but drives zero weight in the verdict. If enrichment fails completely, fail open (benign), not fail closed.

---

## Files to Change

All paths are relative to the repo root.

### 1. `fusion_export/fusion_kit/scoring.py` — add `"op_only"` mode

The `fusion()` function currently has two modes: `"mean"` and `"max"`. Add `"op_only"`:

```python
def fusion(
    url_p: np.ndarray,
    op_p: np.ndarray | None,
    *,
    mode: Literal["max", "mean", "op_only"] = "op_only",
    shortener_mask: np.ndarray | None = None,
) -> np.ndarray:
```

New behavior for `"op_only"`:
- If `op_p is None` (enrichment did not run at all): return `np.zeros_like(url_p)` — fail open, every URL scores 0.0 = benign.
- Otherwise: return `op_p` directly. `url_p` and `shortener_mask` are ignored entirely.
- `"mean"` and `"max"` modes remain unchanged for backwards-compatibility.

Change the default `mode` parameter from `"mean"` to `"op_only"`.

### 2. `fusion_export/scripts/serve.py` — three changes

**a. `--fusion` default and choices**

```python
ap.add_argument("--fusion", choices=("max", "mean", "op_only"), default="op_only")
```

**b. Verdict threshold — fail open on degraded enrichment**

Line 197 currently reads:
```python
"verdict": "phishing" if dp >= self.threshold else "benign",
```
Change to strictly greater-than:
```python
"verdict": "phishing" if dp > self.threshold else "benign",
```
Reason: when enrichment fails for a URL the HGB may return op_p ≈ 0.5 (NaN path through trees). With `>=` at threshold=0.50 this would be classified phishing. With `>` it is benign — correct fail-open behavior.

**c. Startup log**

Update the startup print to reflect `fusion=op_only`:
```
url_model=structural_lgb threshold=0.50 fusion=op_only content_gate=False
```

### 3. No Go changes needed

`internal/phishing/detector.go` and `cmd/url-analysis/main.go` read `verdict` from the sidecar response (`"phishing"` or `"benign"`). That field is still present. `deploy_p` is still in the response. No Go-side changes required.

---

## Sanity Battery — Mindset

**Your job does not end when you make the code change. Your job ends when you have exhausted every plausible failure mode and proven the system handles it correctly.**

Run the battery below against the live sidecar at `http://localhost:8765`. Restart the sidecar with the new code before starting:

```bash
cd /path/to/cybersiren/fusion_export
pkill -f "serve.py" || true
python scripts/serve.py --port 8765 --workers 4 &
sleep 3
curl -sf http://localhost:8765/health
# must print: {"status": "ok", "models_loaded": true}
```

For each URL below, POST to `/score_one` and record `url_p`, `op_p`, `deploy_p`, `verdict`. A test **passes** when verdict matches the expected label in the right column. If it fails, diagnose, fix, and re-run the entire battery from the top.

```bash
score() {
    curl -sf -X POST http://localhost:8765/score_one \
         -H "Content-Type: application/json" \
         -d "{\"url\": \"$1\"}" | python3 -m json.tool
}
```

---

### Category 1 — Obvious Benign (must all be `benign`)

These are well-known domains. `url_p` may be high or low. With `op_only`, `op_p` is the only thing that matters. Expect op_p < 0.15 for all of these.

| URL | Expected |
|-----|----------|
| `https://google.com` | benign |
| `https://github.com` | benign |
| `https://amazon.com` | benign |
| `https://microsoft.com` | benign |
| `https://apple.com` | benign |
| `https://linkedin.com` | benign |
| `https://wikipedia.org` | benign |
| `https://stackoverflow.com` | benign |

**Pass criterion**: all 8 return `"verdict": "benign"`. If any fail, the op model is miscalibrated on well-known domains — investigate `op_p` and `url_p` values and report the finding.

---

### Category 2 — Deep Path Benign (the primary motivation for this refactor)

These are the URLs that broke the old fusion. `url_p` will be high (≥ 0.9 for most). With `op_only`, `op_p` must carry the verdict alone.

| URL | Expected |
|-----|----------|
| `https://mail.google.com/mail/u/2/#inbox/FMfcgzQgLjSzssBCDsxTdncpMfxlqKlW` | benign |
| `https://accounts.google.com/o/oauth2/v2/auth?scope=email&redirect_uri=https%3A%2F%2Fexample.com` | benign |
| `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc&response_type=code` | benign |
| `https://outlook.office365.com/mail/inbox` | benign |
| `https://signin.aws.amazon.com/signin?redirect_uri=https%3A%2F%2Fconsole.aws.amazon.com%2Fconsole%2Fhome` | benign |
| `https://github.com/login?return_to=https%3A%2F%2Fgithub.com%2Fpull%2F12345` | benign |
| `https://paypal.com/signin` | benign |
| `https://appleid.apple.com/sign-in` | benign |
| `https://www.facebook.com/login/?next=https%3A%2F%2Fwww.facebook.com%2F` | benign |
| `https://chase.com/personal/credit-cards/secure/login` | benign |

**Pass criterion**: all 10 return `"verdict": "benign"`. Document `url_p` for each — these are the exact cases where url_p was corrupting the verdict.

---

### Category 3 — Long, High-Entropy, Complex Benign

Random-looking strings in paths, very long URLs, deep nested paths — all legitimate.

| URL | Expected |
|-----|----------|
| `https://docs.google.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms/edit?usp=sharing` | benign |
| `https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLbpi6ZahtOH6Ar_3GPy3us5IZDmVdOagn&index=1&t=0s` | benign |
| `https://github.com/torvalds/linux/commit/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2` | benign |
| `https://console.aws.amazon.com/s3/buckets/my-company-prod-logs?region=us-east-1&tab=objects&prefix=2024%2F05%2F` | benign |
| `https://stackoverflow.com/questions/11828270/how-do-i-exit-vim/11828573#11828573` | benign |
| `https://en.wikipedia.org/wiki/Phishing#Techniques` | benign |
| `https://www.dropbox.com/sh/abcdefghijklmnop/AABqrstuvwxyz1234567890?dl=0` | benign |

**Pass criterion**: all 7 return `"verdict": "benign"`.

---

### Category 4 — Shortened URLs (redirect resolution)

The sidecar resolves shortener redirects before scoring. Test that resolution is happening and that the verdict reflects the destination, not the shortener.

```bash
# Check effective_url in the response — it must differ from the input URL
# if the redirect was followed successfully.
score "https://bit.ly/3fTq2Lx"   # resolves to a legitimate destination
score "https://tinyurl.com/4wr8b9wf"
score "https://ow.ly/abc123"
```

**Pass criterion for resolved URLs**: `effective_url != input url` AND verdict reflects destination domain's op_p.

**Pass criterion for unresolved (redirect fails or target is down)**: verdict = `benign` (fail-open, do not let shortener ambiguity produce a phishing label). `effective_url == input url` in this case.

If a shortened URL resolves to a known phishing destination, it should score phishing — verify that the destination's op_p drives the verdict, not the shortener domain's op_p.

---

### Category 5 — Obvious Phishing (must all be `phishing` or caught by domain guard before reaching sidecar)

Note: some of these will be short-circuited by the Go domain guard (typosquat / brand-in-subdomain) before the sidecar is ever called. The sidecar battery tests the sidecar in isolation, so test them directly here even if the full stack would catch them earlier.

| URL | Expected |
|-----|----------|
| `http://paypal-verify-account.tk/login/confirm?user=victim@gmail.com` | phishing |
| `http://amazon-secure-update.xyz/confirm-payment` | phishing |
| `http://microsoft-account-suspended.ru/recover` | phishing |
| `http://apple-id-verify.support/signin` | phishing |
| `http://secure-bankofamerica-login.com/auth` | phishing |
| `http://chase-fraud-alert.net/verify` | phishing |
| `http://paypal-secure.netlify.app/verify` | phishing |

**Pass criterion**: deploy_p ≥ threshold (currently 0.50) AND verdict = `"phishing"` for the majority. If op_p is low for a phishing domain (e.g., newly registered domain with no history), document whether url_p would have helped and at what cost to benign accuracy. **Do not re-add url_p to fix this — report the gap and move on.**

---

### Category 6 — IP-Based and Malformed URLs

| URL | Expected |
|-----|----------|
| `http://192.168.1.1/admin` | benign (private IP, local traffic) |
| `http://198.51.100.1/phishing/login` | phishing (public IP hosting phishing page) |
| `ftp://malicious-site.xyz/payload.exe` | phishing |
| `http://evil.tk/?url=https://paypal.com` | phishing |

---

### Category 7 — Enrichment Failure / Degraded Mode

Test what happens when the sidecar cannot enrich a URL (non-resolving domain, timeout).

```bash
# Non-resolving domain — DNS lookup will fail
score "https://this-domain-does-not-exist-at-all-xyz-abc-123.xyz/login"

# Localhost / private — not a real public domain
score "http://localhost:8080/admin"
score "http://10.0.0.1/admin"
```

**Pass criterion**: all return `"verdict": "benign"` — fail open. Record `op_p` for each. If op_p > 0.50 on a non-resolving domain, that is a miscalibration bug in the operational model — report it.

---

### Category 8 — Adversarial Benign (stress test for op-only reliability)

These are benign URLs designed to look maximally suspicious to appearance-based models:

| URL | Why it looks suspicious | Expected |
|-----|------------------------|----------|
| `https://google.com/search?q=how+to+verify+paypal+account+secure+login+password+update` | query contains sensitive words | benign |
| `https://github.com/security/advisories/GHSA-xxxx-xxxx-xxxx` | "security" in path | benign |
| `https://amazon.com/gp/product/B08N5WRWNW/ref=sr_1_1?ie=UTF8&qid=1234567890&sr=8-1&keywords=secure+login+verify` | long query, "secure", "verify", "login" | benign |
| `https://microsoft.com/en-us/security/blog/2024/01/15/phishing-campaign-targets-azure-users/` | "phishing" in path | benign |
| `https://support.apple.com/en-us/HT204306` | Apple support URL | benign |

**Pass criterion**: all return `"verdict": "benign"`. These are the exact adversarial cases that prove op-only is the right architecture.

---

## Iteration Protocol

After running the full battery:

1. **Record results** in a table: URL | url_p | op_p | deploy_p | verdict | pass/fail
2. **For each failure**: identify whether the root cause is in `fusion()`, the threshold, the operational model calibration, or enrichment failure handling.
3. **Fix the root cause** — do not paper over failures by tuning the threshold globally. If one category fails, understand why before touching numbers.
4. **Re-run the full battery** after every fix. Do not only re-run the category you just fixed.
5. **Stop when**: every category passes, or every remaining failure is a documented known limitation (e.g., op-only cannot catch a brand-new domain with clean DNS/TLS/ASN profile — that is a fundamental limitation, not a bug, and should be noted).

Do not open the PR or commit until the battery is clean.

---

## Commit and PR Update

Once the battery is clean:

```bash
# Stage only the changed sidecar files
git add fusion_export/fusion_kit/scoring.py fusion_export/scripts/serve.py

git commit -m "$(cat <<'EOF'
refactor(sidecar): op_only fusion — url_p is routing gate, not verdict

url_p (structural LightGBM) scores deep legitimate URLs at ≥ 0.9 because
path-entropy, path-depth, and sensitive-word features fire on any login
flow regardless of domain legitimacy. Fusing url_p into deploy_p produced
false positives on paypal.com/signin, github.com/login, and all OAuth
redirect flows.

deploy_p = op_p. url_p stays in the response for observability only.
Enrichment failure → fail open (verdict=benign, deploy_p=0.0).
Threshold condition changed from >= to > to prevent NaN-path op_p ≈ 0.5
from being classified as phishing.

Sanity battery: N/N pass (document final count here).

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"

git push origin feat/svc-03-domain-guard-v2
```

Then add a comment to PR #140 summarising the battery results:

```bash
gh pr comment 140 --body "$(cat <<'EOF'
## Sidecar refactor: op_only fusion

**Change**: `deploy_p = op_p` — url_p is now a routing gate only, zero weight in verdict.

**Why**: url_p (structural LightGBM) scores deep legitimate OAuth/login URLs at ≥ 0.9
because path-entropy and sensitive-word features are structurally triggered by legitimate
login flows. Asymmetric fusion was a patch; op-only is the correct architecture.

**Fail-open**: enrichment failure → deploy_p = 0.0 → verdict = benign.
Threshold condition changed from `>=` to `>` to prevent NaN-path op_p ≈ 0.5 from
triggering a phishing verdict.

**Sanity battery results** (paste table here):
| Category | Pass | Fail |
|---|---|---|
| Obvious benign (8 URLs) | | |
| Deep path benign (10 URLs) | | |
| Long/high-entropy benign (7 URLs) | | |
| Shortened URLs | | |
| Obvious phishing (7 URLs) | | |
| IP-based / malformed | | |
| Enrichment failure / degraded | | |
| Adversarial benign (5 URLs) | | |

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Known Limitations to Document (not bugs, do not try to fix)

- **Fresh phishing domains with clean profiles**: a domain registered 30 minutes ago with valid DNS, TLS from Let's Encrypt, and a clean ASN will have low op_p. This is a fundamental blind spot of any enrichment-based system. The domain guard (brand-in-subdomain + typosquat check) catches the cases where the attacker impersonates a known brand. Pure infrastructure-clean phishing is out of scope for this PR.
- **Unresolved shortener redirects**: if `resolve_short_url()` cannot follow the redirect (target down, requires JS, etc.), the sidecar scores the shortener domain itself (bit.ly, tinyurl.com) — these have low op_p → verdict = benign. This is a pre-existing limitation. Do not add url_p back to fix it.
- **op_p calibration on very sparse enrichment rows**: when enrichment partially succeeds (some features NaN, some present), the HGB NaN-handling may produce op_p values that are not well-calibrated. This is a training-data gap, not a code bug.
