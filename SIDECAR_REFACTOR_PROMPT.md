# Sidecar Refactor + Exhaustive Sanity Battery — Agent Instructions

Read this entire document before touching any file.

---

## What You Are Doing and Why

The fusion sidecar currently blends two model scores:

- **`url_p`** — structural LightGBM on 33 URL-appearance features (fast, no network)
- **`op_p`** — HistGradientBoosting on live enrichment features: DNS, WHOIS, TLS, ASN, GeoIP, HTTP headers (slow, authoritative)

The `url_p` model was designed as a **routing gate** — decide whether a URL looks suspicious enough to bother enriching. It was never supposed to contribute to the final verdict. It scores deep legitimate URLs like `github.com/login`, `accounts.google.com/o/oauth2/v2/auth`, and `signin.aws.amazon.com/signin?redirect_uri=console` at url_p ≈ 1.000 because path-depth, entropy, and sensitive-word features fire on any login flow regardless of whether the domain is legitimate. Fusing url_p into the final score — even asymmetrically — corrupts op_p with a signal that is structurally wrong on the most common legitimate URL patterns.

**The fix**: `deploy_p = op_p`. The `url_p` score stays in the response for observability but drives zero weight in the verdict. If enrichment fails completely, fail open (benign).

---

## Files to Change

All paths are relative to the repo root.

### 1. `fusion_export/fusion_kit/scoring.py` — add `"op_only"` mode

The `fusion()` function currently has modes `"mean"` and `"max"`. Add `"op_only"`:

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

Line currently reads:
```python
"verdict": "phishing" if dp >= self.threshold else "benign",
```
Change to strictly greater-than:
```python
"verdict": "phishing" if dp > self.threshold else "benign",
```
Reason: when enrichment fails the HGB may return op_p ≈ 0.5 (NaN path through trees). With `>=` at threshold=0.50 this would be classified phishing. With `>` it is benign — correct fail-open behavior.

**c. Startup log**

```
url_model=structural_lgb threshold=0.50 fusion=op_only content_gate=False
```

### 3. No Go changes needed

`internal/phishing/detector.go` and `cmd/url-analysis/main.go` read `verdict` from the sidecar JSON response. That field is still present. No Go changes required.

---

## Sanity Battery — Core Mindset

**You are not running a fixed list of checks. You are trying to break the system.**

After every round of tests, ask yourself: "What failure mode have I not tried yet?" Write the next category, run it, record results. Keep going until you genuinely cannot think of a new angle that would produce a different outcome than one you have already tested. Only then stop.

Full live enrichment must be used for every test — no mocking, no offline features. Every URL is scored by hitting the live sidecar at `http://localhost:8765` which performs real DNS, WHOIS, TLS, HTTP, and GeoIP lookups.

---

## Setup

```bash
# Kill any stale sidecar
pkill -f "serve.py" || true
sleep 1

# Start with op_only (the new default after your code change)
cd /path/to/cybersiren/fusion_export
python scripts/serve.py --port 8765 --workers 8 &
sleep 5

# Verify startup log contains: fusion=op_only
curl -sf http://localhost:8765/health
# must return: {"status": "ok", "models_loaded": true}
```

Helper function — use this for every test:

```bash
score() {
    local url="$1"
    curl -sf -X POST http://localhost:8765/score_one \
         -H "Content-Type: application/json" \
         -d "{\"url\": \"$(echo "$url" | sed 's/"/\\"/g')\"}"
}

score_batch() {
    # Usage: score_batch url1 url2 url3 ...
    local json='{"urls":['
    local first=1
    for u in "$@"; do
        [ $first -eq 0 ] && json+=','
        json+="\"$(echo "$u" | sed 's/"/\\"/g')\""
        first=0
    done
    json+=']}'
    curl -sf -X POST http://localhost:8765/score \
         -H "Content-Type: application/json" \
         -d "$json"
}
```

---

## Seed Battery — Run These First

These seed categories are starting points. They are not exhaustive. After completing each one, brainstorm what is missing before continuing.

### Category 1 — Obvious Benign

Well-known apex domains. op_p must be < 0.10 for all.

```
https://google.com
https://github.com
https://amazon.com
https://microsoft.com
https://apple.com
https://linkedin.com
https://wikipedia.org
https://stackoverflow.com
https://cloudflare.com
https://netflix.com
https://spotify.com
https://adobe.com
https://salesforce.com
https://stripe.com
https://twilio.com
```

**Pass**: verdict = benign for all 15. Any failure is a critical op model calibration bug.

---

### Category 2 — Deep OAuth / Login Path Benign

The primary motivation for this refactor. url_p will be ≥ 0.9 for most. op_p must override.

```
https://accounts.google.com/signin/v2/identifier
https://accounts.google.com/o/oauth2/v2/auth?scope=email%20profile&redirect_uri=https%3A%2F%2Fexample.com&response_type=code&client_id=123456789
https://mail.google.com/mail/u/2/#inbox/FMfcgzQgLjSzssBCDsxTdncpMfxlqKlW
https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc&response_type=code&scope=openid
https://outlook.office365.com/mail/inbox
https://signin.aws.amazon.com/signin?redirect_uri=https%3A%2F%2Fconsole.aws.amazon.com%2Fconsole%2Fhome&client_id=arn%3Aaws%3Aiam%3A%3A015428540659%3Auser%2Fhomepage
https://github.com/login?return_to=https%3A%2F%2Fgithub.com%2Fpull%2F12345
https://appleid.apple.com/sign-in
https://www.paypal.com/signin
https://www.facebook.com/login/?next=https%3A%2F%2Fwww.facebook.com%2F
https://auth.chase.com/login/auth
https://secure.bankofamerica.com/login/sign-in/entry/
https://zoom.us/signin
https://slack.com/signin
https://dashboard.stripe.com/login
```

**Pass**: verdict = benign for all 15. For each failure, record url_p — this is the exact signal that was corrupting verdicts.

---

### Category 3 — Long / High-Entropy / Complex Path Benign

Random-looking tokens in paths and query strings. All legitimate.

```
https://docs.google.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms/edit?usp=sharing
https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLbpi6ZahtOH6Ar_3GPy3us5IZDmVdOagn&index=1&t=42s
https://github.com/torvalds/linux/commit/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
https://console.aws.amazon.com/s3/buckets/my-company-prod-logs?region=us-east-1&tab=objects&prefix=2024%2F05%2F17%2F
https://stackoverflow.com/questions/11828270/how-do-i-exit-vim/11828573#11828573
https://www.dropbox.com/sh/abcdefghijklmnopqrstuv/AABqrstuvwxyz1234567890abcdef?dl=0
https://onedrive.live.com/edit.aspx?resid=ABC123DEF456!789&cid=abc123def456&app=Word&authkey=!AaBbCcDdEeFfGgHh
https://trello.com/b/xYzAbCdE/project-roadmap-q3-2024-internal-planning
https://app.asana.com/0/1234567890123456/1234567890123456/f
https://api.github.com/repos/torvalds/linux/commits?sha=master&per_page=100&page=3
https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js
https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css
https://raw.githubusercontent.com/torvalds/linux/master/kernel/sched/fair.c
```

**Pass**: verdict = benign for all 13.

---

### Category 4 — Adversarial Benign (Sensitive Words in Legitimate Paths)

Benign URLs that contain words from `SENSITIVE_WORDS` ("secure", "account", "verify", "update", "login", "password", "confirm") or brand names in paths. These are guaranteed to produce high url_p. op_p must carry the verdict.

```
https://google.com/search?q=how+to+verify+paypal+account+secure+login+password+update
https://github.com/security/advisories/GHSA-xxxx-xxxx-xxxx
https://microsoft.com/en-us/security/blog/2024/01/15/phishing-campaign-targets-azure-users
https://amazon.com/gp/product/B08N5WRWNW/ref=sr_1_1?ie=UTF8&qid=1234567890&keywords=secure+login+verify
https://support.apple.com/en-us/HT204306
https://help.paypal.com/us/helpcenter/article/secure-your-paypal-account
https://support.google.com/accounts/answer/41078?hl=en#verify
https://www.irs.gov/individuals/get-an-identity-protection-pin
https://www.bankofamerica.com/security-center/account-protect/
https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
https://owasp.org/www-community/attacks/Phishing
https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id
```

**Pass**: verdict = benign for all 12.

---

### Category 5 — Shortened URLs (Full Redirect Resolution Required)

The sidecar must follow redirects and score the destination. `effective_url` in the response must differ from the input for all successfully resolved URLs.

```
https://bit.ly/3fTq2Lx
https://tinyurl.com/4wr8b9wf
https://t.co/example
https://ow.ly/abc123
https://rb.gy/example
```

For each: record `effective_url`, `url_p`, `op_p`, `deploy_p`, `verdict`.
- If redirect resolves to a known benign domain → verdict must = benign.
- If redirect fails (target down) → `effective_url == input`, verdict must = benign (fail-open).
- Verdict must always reflect the **destination** domain's op_p, not the shortener's.

---

### Category 6 — Fresh OpenPhish URLs (Live Phishing Feed)

**Step 1**: Fetch the live OpenPhish feed and the existing cached feed. Deduplicate. Use all unique URLs.

```bash
# Fetch live feed
curl -sf https://openphish.com/feed.txt > /tmp/openphish_live.txt 2>/dev/null || true

# Merge with existing cached feed
cat /path/to/cybersiren/fusion_export/fresh_openphish.txt /tmp/openphish_live.txt \
    | grep -v '^#' | grep -v '^$' | sort -u > /tmp/all_phishing.txt

wc -l /tmp/all_phishing.txt
# Use ALL of these — not a sample. Score them in batches of 50 via /score endpoint.
```

**Step 2**: Score all URLs in batches of 50:

```bash
split -l 50 /tmp/all_phishing.txt /tmp/phish_batch_
for f in /tmp/phish_batch_*; do
    urls=$(cat "$f" | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))")
    curl -sf -X POST http://localhost:8765/score \
         -H "Content-Type: application/json" \
         -d "{\"urls\": $urls}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data['results']:
    verdict = r['verdict']
    dp = r['deploy_p']
    op = r['op_p']
    up = r['url_p']
    print(f\"{verdict:8s} deploy={dp:.3f} op={op:.3f} url={up:.3f}  {r['url'][:80]}\")
"
done 2>&1 | tee /tmp/phishing_results.txt
```

**Step 3**: Count and report.

```bash
echo "=== PHISHING DETECTION SUMMARY ==="
grep -c "^phishing" /tmp/phishing_results.txt || true
grep -c "^benign"   /tmp/phishing_results.txt || true
echo ""
echo "=== MISSED (benign verdict on phishing URL) ==="
grep "^benign" /tmp/phishing_results.txt
```

**Pass criterion**: ≥ 70% of OpenPhish URLs are classified phishing. Document the miss rate. For missed URLs, record op_p — if op_p is consistently low (< 0.3) for missed phishing, the enrichment model has a blind spot on infrastructure-clean fresh domains. This is a known limitation, not a bug. Do not add url_p back to fix it.

---

### Category 7 — Existing Live Benign URL File

Score every URL in `fusion_export/live_benign_urls.txt` (60 URLs):

```bash
grep -v '^#' /path/to/cybersiren/fusion_export/live_benign_urls.txt | grep -v '^$' | while read url; do
    result=$(score "$url")
    verdict=$(echo "$result" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['verdict'])")
    dp=$(echo "$result" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['deploy_p'])")
    op=$(echo "$result" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['op_p'])")
    up=$(echo "$result" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['url_p'])")
    echo "$verdict deploy=$dp op=$op url=$up  $url"
done 2>&1 | tee /tmp/benign_results.txt

echo "=== BENIGN ACCURACY ==="
grep -c "^benign" /tmp/benign_results.txt || true
grep -c "^phishing" /tmp/benign_results.txt || true
echo "=== FALSE POSITIVES ==="
grep "^phishing" /tmp/benign_results.txt
```

**Pass**: 0 false positives. Any false positive on this list is a regression that must be fixed before continuing.

---

### Category 8 — Enrichment Failure / Degraded Mode

Non-resolving, local, and malformed URLs. All must return benign (fail-open).

```
https://this-domain-does-not-exist-at-all-xyz-abc-123456789.xyz/login/verify
https://nonexistent-phish-domain-abc-def.tk/secure/account/update
http://localhost:8080/admin/login
http://127.0.0.1:3000/dashboard
http://10.0.0.1/admin
http://192.168.1.254/router/login
http://[::1]/admin
```

**Pass**: verdict = benign for all 7. op_p must be ≤ 0.50 for all (fail-open does not produce phishing labels). If any return phishing, the threshold condition change (`>` not `>=`) was not applied correctly.

---

### Category 9 — IP-Based URLs

```
http://192.168.1.1/admin
http://203.0.113.42/phishing/login?verify=1
http://185.220.101.1/secure/account/update
http://45.33.32.156/wp-login.php
http://8.8.8.8/
```

First two: private/documentation IPs → benign. Last three: public IPs hosting paths — these may or may not resolve; record op_p and verdict. A public IP hosting a login page with no domain name is a strong phishing signal in the op model (no WHOIS, no cert SAN match, raw IP).

---

### Category 10 — Homograph / IDN / Punycode Attacks

Internationalized domain names that visually mimic legitimate brands:

```
https://xn--googl-e.com/
https://xn--pypal-4ve.com/
https://xn--microsft-1cb.com/
https://аррle.com/
https://goоgle.com/
```

These bypass character-level domain matching. The op model should catch them via enrichment (young domains, suspicious registrar, no org WHOIS). Record op_p for each.

---

### Category 11 — CDN / Cloud Storage / Hosting Platform Benign

Legitimate use of shared infrastructure. url_p will be high for some (random bucket names look like random phishing subdomains).

```
https://my-company-assets.s3.amazonaws.com/dist/bundle.min.js
https://storage.googleapis.com/my-bucket/public/image.png
https://d1234abcdef.cloudfront.net/static/main.css
https://my-site.netlify.app/
https://my-app.vercel.app/
https://my-project.pages.dev/
https://username.github.io/project/
https://my-function.azurewebsites.net/api/health
```

**Pass**: verdict = benign for all 8. These are legitimate use of shared-hosting platforms.

---

### Category 12 — Cloud Storage / Hosting Platform Phishing

Same platforms as above, but these are phishing pages. The domain guard does not catch these (the apex is allowlisted as a legitimate platform). The op model must catch them via content signals.

From the existing OpenPhish feed (already in `fresh_openphish.txt`):
```bash
grep -i "netlify\|vercel\|pages.dev\|github.io\|web.app\|firebaseapp" \
    /path/to/cybersiren/fusion_export/fresh_openphish.txt | head -20
```
Score all matching URLs and report detection rate.

---

### Category 13 — Credentials in URL / Data URI / Non-HTTP Schemes

```
https://user:password@evil-site.com/login
ftp://malicious.xyz/payload.exe
data:text/html,<script>alert('xss')</script>
javascript:void(0)
file:///etc/passwd
```

These are unusual input types. Record what the sidecar returns for each — it may error, return benign, or return phishing. The sidecar should not crash on any of these. **Pass criterion**: no 5xx responses, no exceptions in sidecar stdout.

---

### Category 14 — Open Redirect Exploitation

Legitimate domains used as open redirectors to forward to phishing pages. The sidecar resolves redirects — it must score the final destination, not the entry point.

```
https://www.google.com/url?q=http%3A%2F%2Fevil-phishing-site.xyz%2Flogin&sa=D
https://l.facebook.com/l.php?u=http%3A%2F%2Fmalicious-domain.tk%2Fverify&h=abc123
https://t.co/redirecttophish
```

**Expected behavior**: if the redirect destination is phishing, verdict = phishing (destination's op_p drives it). If the redirect resolver follows to a phishing domain, the enrichment of that domain should produce high op_p.

---

### Category 15 — URL Parameter Obfuscation Patterns

Common phishing obfuscation techniques in query strings:

```
http://evil.tk/?url=https://paypal.com&verify=1&token=XXXXXXXXXXXXXXXXXXX
http://phish.xyz/redirect?to=https%3A%2F%2Famazon.com%2Flogin&ref=secure
http://malicious.ru/?next=https%3A%2F%2Fgoogle.com%2F&auth=false&session=abc123def456
https://legitimate-looking.xyz/portal?email=victim@gmail.com&token=AAABBBCCC&step=verify-account
```

These use legitimate brand names and URLs as parameter values. The structural model will fire on the query string contents. With op_only, only the actual domain's enrichment matters.

---

## Exhaustion Loop — Keep Going Until You Run Out of Ideas

After completing all seed categories above, enter the exhaustion loop:

```
WHILE (you can think of a new failure mode):
    1. Write a short description of the new category
    2. Collect 5-15 representative URLs
    3. Score them against the live sidecar
    4. Record results in a table (url | url_p | op_p | deploy_p | verdict | pass/fail)
    5. If any fail: diagnose root cause, fix code, restart sidecar, re-run ALL categories from the top
    6. If all pass: go back to step 1
```

Suggested angles that may or may not be covered by the time you reach them — use these as inspiration, not a checklist:

- **Google AMP URLs**: `https://amp.dev/documentation/...`, `https://google.com/amp/s/...`
- **Pastebin / Gist / GitHub Raw**: legitimate data sharing vs phishing payload hosting
- **URL with base64 payload in query param**: `?data=aHR0cHM6Ly9ldmlsLmNvbQ==` — does the model score the encoded string?
- **Very long URLs** (> 500 chars): do they cause the sidecar to error or time out?
- **Unicode in path** (percent-encoded): `https://github.com/search?q=%F0%9F%94%90+security`
- **Double-encoded URLs**: `https://evil.com/path%2520encoded`
- **Subdomain depth attacks**: `a.b.c.d.e.paypal.evil.com` — multiple levels
- **New gTLDs as legitimacy signal**: `.app`, `.dev`, `.io` are commonly used by legitimate developers; `.tk`, `.ml`, `.cf`, `.ga` are free and heavily abused
- **Certificate transparency fresh domains**: domains registered < 24 hours ago with Let's Encrypt cert
- **Legitimate API endpoints**: `https://api.stripe.com/v1/charges`, `https://graph.facebook.com/me`
- **Password reset flows**: `https://accounts.google.com/signin/v2/challenge/pwd`
- **Error pages on legitimate sites**: `https://github.com/this-page-does-not-exist`
- **Legitimate sites with no HTTPS**: `http://www.bbc.co.uk/` (rare but exists)
- **Phishing on legitimate cloud functions**: `https://us-central1-project-id.cloudfunctions.net/phish`
- **Lookalike TLDs**: `google.cm`, `paypal.com.co`, `amazon.co` (not `.co.uk`)
- **Hex / octal IP encoding**: `http://0xC0A80101/admin` = `http://192.168.1.1/admin`

Stop the loop when you have run 3 consecutive brainstorming rounds and could not produce a new category that would test a different failure mode from one already covered.

---

## Iteration Protocol

1. **Record all results** in a single Markdown table: `URL | url_p | op_p | deploy_p | verdict | expected | pass/fail`
2. **For each failure**: identify whether root cause is in `fusion()`, threshold logic, op model calibration, or enrichment failure handling. Fix the root cause — do not tune the threshold globally to paper over individual failures.
3. **After every fix**: restart the sidecar and re-run ALL categories. Not just the one you fixed.
4. **Known limitations** (document, do not attempt to fix):
   - Fresh phishing domains with clean infrastructure (new domain, valid cert, clean ASN): op_p will be low → missed. This is a fundamental blind spot of enrichment-based systems. The domain guard catches brand impersonation; pure infrastructure-clean phishing is out of scope.
   - Unresolved shortener redirects: if redirect cannot be followed, verdict reflects the shortener domain (benign). This is a pre-existing limitation.
   - op_p miscalibration on very sparse enrichment (partial NaN rows): training-data gap, not a code bug.

---

## Commit and PR Update

Once the exhaustion loop is complete and all non-known-limitation tests pass:

```bash
git add fusion_export/fusion_kit/scoring.py fusion_export/scripts/serve.py

git commit -m "$(cat <<'EOF'
refactor(sidecar): op_only fusion — url_p is routing gate, not verdict

url_p (structural LightGBM) scores deep legitimate OAuth and login URLs at
≥ 0.9 because path-entropy, path-depth, and sensitive-word features fire on
any login flow regardless of domain legitimacy. Fusing url_p into deploy_p
produced false positives on paypal.com/signin, github.com/login, and all
OAuth redirect flows even with asymmetric weighting.

deploy_p = op_p. url_p remains in the response for observability only.
Enrichment failure → fail open (deploy_p = 0.0, verdict = benign).
Threshold condition changed from >= to > so NaN-path op_p ≈ 0.5 does not
trigger a phishing verdict.

Sanity battery: <N> categories, <M> total URLs, <K>/<M> pass. OpenPhish
detection rate: <X>%. FP rate on benign file: 0/<60>.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"

git push origin feat/svc-03-domain-guard-v2
```

Then comment on PR #140 with the full results table:

```bash
gh pr comment 140 --body "$(cat <<'EOF'
## Sidecar refactor: op_only fusion — battery results

**Change**: `deploy_p = op_p`. url_p drives zero weight in verdict.

**Why**: structural LightGBM scores deep legitimate OAuth/login paths at ≥ 0.9.
Asymmetric fusion was a patch; op-only is the correct architecture.

**Fail-open**: enrichment failure → deploy_p = 0.0 → verdict = benign.
Threshold changed from `>=` to `>` to prevent NaN-path op_p ≈ 0.5 from triggering phishing.

### Results

| Category | URLs tested | Pass | Fail | Notes |
|---|---|---|---|---|
| Obvious benign | 15 | | | |
| Deep OAuth / login path | 15 | | | |
| Long / high-entropy path | 13 | | | |
| Adversarial benign (sensitive words) | 12 | | | |
| Shortened URLs | 5 | | | |
| OpenPhish live feed | N | | | detection rate: X% |
| Existing live_benign_urls.txt | 60 | | | |
| Enrichment failure / degraded | 7 | | | |
| IP-based | 5 | | | |
| Homograph / IDN | 5 | | | |
| CDN / hosting platform benign | 8 | | | |
| Hosting platform phishing | N | | | |
| Unusual schemes / credentials in URL | 5 | | | |
| Open redirect | 3 | | | |
| URL param obfuscation | 4 | | | |
| [additional categories from exhaustion loop] | | | | |

### Known limitations (not bugs)
- Fresh domains with clean infra: op_p low, missed by op model. Domain guard catches brand impersonation.
- Unresolved shortener redirects: scored on shortener domain, not destination.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```
