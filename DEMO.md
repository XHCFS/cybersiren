# CyberSiren URL Scanner — Demo Guide

## Overview

This demo runs **svc-03-url-analysis**, the CyberSiren URL analysis service.
Paste any URL and get an instant phishing risk assessment powered by:

| Engine | How it works |
|--------|-------------|
| **ML model** | A LightGBM classifier scores the URL (0–100) based on 28 lexical/structural features extracted from the URL itself — no network requests needed. |
| **Threat Intelligence** | The URL's domain is checked against a Valkey (Redis-compatible) cache populated from the `ti_indicators` Postgres table. Matches return the threat type and risk score. |

Both checks run **in parallel**; results are merged into a single verdict
(`legitimate` / `suspicious` / `phishing`) and displayed in a web UI or returned
via the JSON API.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **Docker** + **Docker Compose v2** | `docker compose version` should print v2.x |
| **~2 GB disk** | Python ML dependencies (NumPy, LightGBM, joblib) + model file |
| **Free ports** | `5432` (Postgres), `6379` (Valkey), `8083` (svc-03 HTTP), `9090` (metrics) |

---

## Quick Start

```bash
# 1. Clone the repo and cd into it
git clone https://github.com/saif/cybersiren.git
cd cybersiren

# 2. Start the demo stack (Postgres + Valkey + demo-seed + svc-03)
#    The Postgres container defaults to user "postgres", but the demo services
#    connect as "cybersiren", so we pass the matching credentials:
POSTGRES_USER=cybersiren POSTGRES_PASSWORD=cybersiren \
  docker compose -f deploy/compose/docker-compose.yml --profile demo up --build
```

> **Tip:** To avoid typing the env vars every time, create
> `deploy/compose/.env` with:
>
> ```env
> POSTGRES_USER=cybersiren
> POSTGRES_PASSWORD=cybersiren
> ```

### What happens on startup

1. **postgres** and **valkey** start and pass their health-checks.
2. **demo-seed** runs all SQL migrations, seeds four TI feed definitions, and
   inserts 20 fictional threat-indicator domains. Look for
   `Demo seed complete.` in the logs.
3. **svc-03-url-analysis** builds (Go binary + Python ML environment), connects
   to Postgres and Valkey, refreshes the TI domain cache, spawns 2 Python
   inference workers, and starts listening. Look for:
   ```
   svc-03-url-analysis started  port=8083  metrics_port=9090
   ```
4. Open **<http://localhost:8083>** in your browser.

The first build takes 2–4 minutes (downloading Go/Python deps). Subsequent
starts reuse the Docker layer cache and are much faster.

---

## Using the Web UI

1. **Enter a URL** in the input field (e.g. `https://google.com` or
   `https://login-paypal-secure.com/account`).
2. Click **Scan** (or press Enter).
3. Results appear in three sections:

### ML Analysis

| Field | Meaning |
|-------|---------|
| **Score** | 0–100 phishing risk score (0 = safe, 100 = certain phishing). Shown with a color bar. |
| **Probability** | Raw model probability (0.0–1.0). |
| **Label** | `legitimate` (score < 40), `suspicious` (40–69), or `phishing` (≥ 70). |

### Threat Intelligence

| Field | Meaning |
|-------|---------|
| **TI Match** | `Yes` (red) if the domain was found in the TI cache, `No` (green) otherwise. |
| **Threat Type** | Category from the TI feed — `phishing`, `malware`, or `botnet_cc`. |
| **TI Risk Score** | 0–100 risk score assigned by the feed. |

### Combined Verdict

The final badge merges both signals:

| Color | Verdict | Rule |
|-------|---------|------|
| 🟢 Green | **LEGITIMATE** | ML score < 40 and no high-risk TI match |
| 🟡 Yellow | **SUSPICIOUS** | ML score 40–69 |
| 🔴 Red | **PHISHING** | ML score ≥ 70 **or** TI match with risk ≥ 80 |

### What does "degraded" mean?

If the ML Python subprocess crashes or times out, the service returns a neutral
score of 50 / 0.5 and sets `"degraded": true`. A yellow warning banner appears
in the UI:

> ⚠️ Some analysis components were unavailable. Results may be incomplete.

TI lookup still runs, so known-bad domains are still flagged even in degraded
mode.

---

## Understanding the Logs

The demo runs with `CYBERSIREN_LOG__PRETTY=true`, so svc-03 emits
human-readable, color-coded logs via zerolog's `ConsoleWriter`. Every line
carries a `service=cybersiren` field automatically.

### Viewing logs in real-time

```bash
# Follow svc-03 logs only
docker compose -f deploy/compose/docker-compose.yml --profile demo \
  logs -f svc-03-url-analysis
```

```bash
# Follow ALL demo containers (postgres, valkey, demo-seed, svc-03)
docker compose -f deploy/compose/docker-compose.yml --profile demo logs -f
```

### Startup logs

A healthy boot prints the following sequence (timestamps will differ):

```
# ── Python model workers loading (printed to stderr by inference_script.py) ──
INFO: model loaded from /app/ml/inference_script.py
READY
INFO: model loaded from /app/ml/inference_script.py
READY

# ── zerolog structured output (pretty mode) ──────────────────────────────────
10:32:01 INF connected to postgres db_host=postgres service=cybersiren
10:32:01 INF connected to valkey valkey_addr=valkey:6379 service=cybersiren
10:32:01 INF svc-03-url-analysis started metrics_port=9090 port=8083 service=cybersiren
```

| Log line | What it means |
|----------|---------------|
| `connected to postgres` | pgx pool opened and ping succeeded |
| `connected to valkey` | Valkey client connected |
| `svc-03-url-analysis started` | HTTP server listening; the service is ready for requests |

If the TI cache refresh fails (e.g. empty `ti_indicators` table), you'll also
see:

```
10:32:01 ERR initial TI domain cache refresh failed error="..." service=cybersiren
```

This is non-fatal — the service still starts, but all TI lookups return
`ti_match: false` until the cache is populated.

### Request logs

Each scan produces two kinds of log output:

**1. Gin access log** — printed by Gin's built-in `Logger()` middleware:

```
[GIN] 2025/06/15 - 10:33:45 | 200 |   48.291ms |    172.17.0.1 | POST     "/scan"
```

This shows the HTTP status, latency, client IP, and route. A `400` here means
the request body was rejected (missing/invalid URL).

**2. zerolog application logs** — emitted by the scan handler, TI checker, or
ML model when something noteworthy happens:

```
# Feature extraction failed (ML falls back to neutral 50/0.5)
10:33:45 WRN feature extraction failed error="..." url=https://example.com service=cybersiren

# Domain couldn't be parsed for TI lookup
10:33:45 WRN failed to extract domain for TI check error="..." url=not-a-url service=cybersiren

# Valkey lookup error (TI check still returns no-match gracefully)
10:33:45 WRN TI cache lookup failed domain=example.com error="..." service=cybersiren

# Python subprocess crashed (worker is auto-respawned)
10:33:45 ERR url model: write to worker stdin error="broken pipe" component=url_model service=cybersiren

# Inference timed out (5s deadline exceeded)
10:33:45 ERR url model: inference timeout error="context deadline exceeded" component=url_model service=cybersiren
```

> **Note:** Successful scans produce only the Gin access log line — the
> application logs at `debug`/`warn`/`error` level only when something goes
> wrong or needs attention.

### Filtering logs

Pipe through `grep` to isolate specific events:

```bash
# Only TI-related messages (matches & lookup errors)
docker compose -f deploy/compose/docker-compose.yml --profile demo \
  logs -f svc-03-url-analysis 2>&1 | grep -E "TI|ti_"

# Only errors and warnings
docker compose -f deploy/compose/docker-compose.yml --profile demo \
  logs -f svc-03-url-analysis 2>&1 | grep -E "ERR|WRN"

# Only Gin access logs for /scan requests
docker compose -f deploy/compose/docker-compose.yml --profile demo \
  logs -f svc-03-url-analysis 2>&1 | grep 'POST.*"/scan"'

# ML model issues only
docker compose -f deploy/compose/docker-compose.yml --profile demo \
  logs -f svc-03-url-analysis 2>&1 | grep "url_model\|url model"

# Startup sequence (connection messages)
docker compose -f deploy/compose/docker-compose.yml --profile demo \
  logs svc-03-url-analysis 2>&1 | grep -E "connected to|started"
```

### Log levels

Control verbosity by changing `CYBERSIREN_LOG__LEVEL` in the svc-03 environment
block of `docker-compose.yml` (or pass it as an override):

| Level | What it shows | Use when… |
|-------|---------------|-----------|
| `debug` | Everything — including internal detail | Investigating a specific bug |
| `info` | Startup, connections, operational events | **Day-to-day demo use (default)** |
| `warn` | Graceful degradation events (feature extraction failures, TI lookup errors) | Monitoring for partial failures |
| `error` | ML subprocess crashes, cache command failures, shutdown errors | Alerting on things that need fixing |

To change the level without editing the compose file:

```bash
# Override for a single run (sets log level to warn)
POSTGRES_USER=cybersiren POSTGRES_PASSWORD=cybersiren \
CYBERSIREN_LOG__LEVEL=warn \
  docker compose -f deploy/compose/docker-compose.yml --profile demo up
```

> **Tip:** Gin's access logger is independent of zerolog and always prints
> regardless of the `CYBERSIREN_LOG__LEVEL` setting. To silence Gin, set
> `GIN_MODE=release` in the environment.

### Shutdown logs

When you press `Ctrl-C` or run `docker compose down`, svc-03 logs a clean
shutdown sequence:

```
10:45:00 INF shutting down... service=cybersiren
10:45:00 INF shutdown complete service=cybersiren
```

If shutdown takes longer than 10 seconds (e.g. in-flight requests still
draining), you may see timeout errors before the final message.

---

## API Reference

### `POST /scan`

Analyse a single URL.

**Request:**

```json
{
  "url": "https://example.com/path"
}
```

**Response (success):**

```json
{
  "success": true,
  "data": {
    "url": "https://example.com/path",
    "score": 12,
    "probability": 0.1234,
    "label": "legitimate",
    "ti_match": false,
    "ti_threat_type": "",
    "ti_risk_score": 0,
    "degraded": false
  }
}
```

**Response (error):**

```json
{
  "success": false,
  "error": {
    "status": 400,
    "code": "bad_request",
    "message": "url is required"
  }
}
```

---

### curl Examples

#### 1. Scan a known-good URL

```bash
curl -s http://localhost:8083/scan \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://google.com"}' | jq .
```

Expected output (scores will vary):

```json
{
  "success": true,
  "data": {
    "url": "https://google.com",
    "score": 8,
    "probability": 0.0823,
    "label": "legitimate",
    "ti_match": false,
    "ti_threat_type": "",
    "ti_risk_score": 0,
    "degraded": false
  }
}
```

#### 2. Scan a seeded phishing domain

These domains are loaded by the demo seed and will always trigger a TI match:

```bash
curl -s http://localhost:8083/scan \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://login-paypal-secure.com/account/verify"}' | jq .
```

```json
{
  "success": true,
  "data": {
    "url": "https://login-paypal-secure.com/account/verify",
    "score": 72,
    "probability": 0.7185,
    "label": "phishing",
    "ti_match": true,
    "ti_threat_type": "phishing",
    "ti_risk_score": 95,
    "degraded": false
  }
}
```

#### 3. Scan a seeded malware domain

```bash
curl -s http://localhost:8083/scan \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://update-chrome-now.com/download"}' | jq .
```

```json
{
  "success": true,
  "data": {
    "url": "https://update-chrome-now.com/download",
    "score": 65,
    "probability": 0.6512,
    "label": "phishing",
    "ti_match": true,
    "ti_threat_type": "malware",
    "ti_risk_score": 98,
    "degraded": false
  }
}
```

> **Note:** The `label` is `"phishing"` even for malware TI matches because the
> TI risk score (98) is ≥ 80 — see the verdict rules above.

#### 4. Scan a seeded botnet C2 domain

```bash
curl -s http://localhost:8083/scan \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://cloud-health-monitor.xyz/beacon"}' | jq .
```

```json
{
  "success": true,
  "data": {
    "url": "https://cloud-health-monitor.xyz/beacon",
    "score": 58,
    "probability": 0.5812,
    "label": "phishing",
    "ti_match": true,
    "ti_threat_type": "botnet_cc",
    "ti_risk_score": 95,
    "degraded": false
  }
}
```

#### 5. Invalid URL (error case)

```bash
curl -s http://localhost:8083/scan \
  -H 'Content-Type: application/json' \
  -d '{"url": "not-a-url"}' | jq .
```

```json
{
  "success": false,
  "error": {
    "status": 400,
    "code": "bad_request",
    "message": "invalid URL: ..."
  }
}
```

#### 6. Missing URL (error case)

```bash
curl -s http://localhost:8083/scan \
  -H 'Content-Type: application/json' \
  -d '{}' | jq .
```

```json
{
  "success": false,
  "error": {
    "status": 400,
    "code": "bad_request",
    "message": "url is required"
  }
}
```

---

### All Seeded Domains

For quick copy-paste testing, here is every domain loaded by the demo seed:

| Domain | Threat Type | Risk Score |
|--------|-------------|------------|
| `login-paypal-secure.com` | phishing | 95 |
| `microsoft-verify.net` | phishing | 90 |
| `appleid-confirm.org` | phishing | 92 |
| `secure-banking-login.com` | phishing | 88 |
| `netflix-billing-update.com` | phishing | 85 |
| `amazon-security-alert.net` | phishing | 93 |
| `google-drive-share.org` | phishing | 87 |
| `dropbox-verify-account.com` | phishing | 89 |
| `facebook-confirm-identity.com` | phishing | 100 |
| `instagram-verify-now.com` | phishing | 86 |
| `free-software-download.net` | malware | 95 |
| `update-chrome-now.com` | malware | 98 |
| `flash-player-update.org` | malware | 92 |
| `java-update-required.com` | malware | 90 |
| `windows-defender-alert.net` | malware | 100 |
| `cdn-static-content.xyz` | botnet\_cc | 90 |
| `api-metrics-collector.com` | botnet\_cc | 85 |
| `telemetry-service-node.net` | botnet\_cc | 80 |
| `data-sync-endpoint.org` | botnet\_cc | 88 |
| `cloud-health-monitor.xyz` | botnet\_cc | 95 |

---

## Testing with Real Threat Intelligence

The demo seed provides 20 fictional domains. To test against **real-world**
phishing/malware indicators, you can also run **svc-11-ti-sync** which fetches
data from four public feeds:

| Feed | Source | Auth |
|------|--------|------|
| [PhishTank](https://phishtank.org/) | Community-verified phishing URLs | API key required |
| [OpenPhish](https://openphish.com/) | Curated phishing feed | None |
| [URLhaus](https://urlhaus.abuse.ch/) | abuse.ch malware URL feed | None |
| [ThreatFox](https://threatfox.abuse.ch/) | abuse.ch IOC feed | None |

### Steps

```bash
# 1. Make sure Postgres + Valkey are running (the demo profile already starts them)
POSTGRES_USER=cybersiren POSTGRES_PASSWORD=cybersiren \
  docker compose -f deploy/compose/docker-compose.yml --profile demo up -d

# 2. Run svc-11-ti-sync natively (requires Go 1.25+)
#    Copy and adjust the env file first:
cp services/svc-11-ti-sync/configs/.env.example services/svc-11-ti-sync/configs/.env
#    Edit .env — at minimum set CYBERSIREN_DB__* and CYBERSIREN_VALKEY__ADDR
#    For PhishTank, also set CYBERSIREN_FEEDS__PHISHTANK_API_KEY

go run ./services/svc-11-ti-sync/cmd/ti-sync/
```

svc-11 will:

1. Fetch each enabled feed.
2. Parse and upsert indicators into `ti_indicators` in Postgres.
3. Log a summary of new/updated rows per feed.

svc-03 refreshes its Valkey domain cache **at startup** from Postgres, so
**restart svc-03** after svc-11 finishes to pick up the new indicators:

```bash
docker compose -f deploy/compose/docker-compose.yml restart svc-03-url-analysis
```

Now scanning URLs from real phishing campaigns will produce TI matches.

---

## Architecture

```
┌──────────┐
│ Browser  │
└────┬─────┘
     │  POST /scan  { "url": "..." }
     ▼
┌──────────────────────────────────────┐
│         svc-03-url-analysis          │
│           (Go + Gin HTTP)            │
│                                      │
│  ┌─────────────┐  ┌──────────────┐  │
│  │ ML Scoring   │  │ TI Checker   │  │  ◄── parallel goroutines
│  │              │  │              │  │
│  │  Extract 28  │  │ Domain from  │  │
│  │  URL features│  │ normalized   │  │
│  │  → Python    │  │ URL → Valkey │  │
│  │  subprocess  │  │ HGET lookup  │  │
│  └──────┬───────┘  └──────┬───────┘  │
│         │                 │          │
│         ▼                 ▼          │
│    score + prob      matched?        │
│    (0-100)           threat_type     │
│                      risk_score      │
│                                      │
│   ─── merge into verdict ────────►   │
│   label: legitimate/suspicious/      │
│          phishing                    │
└──────────────────────────────────────┘
     │                          │
     ▼                          ▼
┌──────────┐            ┌────────────┐
│  Python  │            │   Valkey   │
│ LightGBM │            │  TI cache  │
│ (subproc)│            │ (HSET/HGET)│
└──────────┘            └─────┬──────┘
                              │ populated at svc-03 startup
                              ▼
                        ┌────────────┐
                        │ PostgreSQL │
                        │ti_indicators│
                        └─────┬──────┘
                              │ seeded by
                    ┌─────────┴──────────┐
                    │                    │
              ┌─────┴─────┐    ┌─────────┴──────┐
              │ demo-seed  │    │ svc-11-ti-sync │
              │ (20 fake   │    │ (real feeds:   │
              │  domains)  │    │  PhishTank,    │
              └────────────┘    │  URLhaus, etc.)│
                                └────────────────┘
```

### Data flow summary

1. **Browser** sends `POST /scan` with a URL.
2. **svc-03** normalizes the URL and launches two goroutines in parallel:
   - **ML scoring** — extracts 28 lexical features from the URL string and sends
     them to a pre-spawned Python subprocess running a LightGBM model. Returns a
     0–100 score and probability.
   - **TI lookup** — extracts the domain, queries the Valkey hash
     (`ti:domains`). If the domain exists, returns the threat type and risk
     score.
3. Results are merged: a TI match with risk ≥ 80 **or** an ML score ≥ 70
   overrides the label to `"phishing"`.
4. JSON response is returned in the standard CyberSiren envelope.

---

## Configuration

All config is via environment variables prefixed with `CYBERSIREN_`. Double
underscores map to struct nesting (e.g. `CYBERSIREN_DB__HOST` → `config.DB.Host`).

See the full reference in
[`services/svc-03-url-analysis/configs/.env.example`](services/svc-03-url-analysis/configs/.env.example).

### Key variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CYBERSIREN_SERVER__PORT` | `8083` | HTTP port for the scan API and web UI |
| `CYBERSIREN_DB__HOST` | `localhost` | Postgres host |
| `CYBERSIREN_DB__PORT` | `5432` | Postgres port |
| `CYBERSIREN_DB__NAME` | `cybersiren` | Database name |
| `CYBERSIREN_DB__USER` | `cybersiren` | Database user |
| `CYBERSIREN_DB__PASSWORD` | `cybersiren` | Database password |
| `CYBERSIREN_DB__SSL_MODE` | `disable` | Postgres SSL mode |
| `CYBERSIREN_VALKEY__ADDR` | `localhost:6379` | Valkey address |
| `CYBERSIREN_ML__URL_MODEL_PATH` | `./ml/inference_script.py` | Path to the Python inference script |
| `CYBERSIREN_METRICS_PORT` | `9090` | Prometheus metrics port |
| `CYBERSIREN_JAEGER_ENDPOINT` | *(empty)* | OTLP endpoint; leave empty to disable tracing |
| `CYBERSIREN_LOG__LEVEL` | `debug` | Log level (`debug`, `info`, `warn`, `error`) |
| `CYBERSIREN_LOG__PRETTY` | `true` | Human-readable log output |

---

## Other Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Serves the web UI (`static/index.html`) |
| `/healthz` | GET | Returns `200 ok` — useful for readiness probes |
| `/metrics` | GET | Prometheus metrics (on the metrics port, default `9090`) |

---

## Troubleshooting

### Port conflicts

```
Error starting userland proxy: listen tcp4 0.0.0.0:5432: bind: address already in use
```

Another process is using the port. Either stop it or override the port:

```bash
POSTGRES_PORT=5433 POSTGRES_USER=cybersiren POSTGRES_PASSWORD=cybersiren \
  docker compose -f deploy/compose/docker-compose.yml --profile demo up --build
```

For svc-03 itself, change `CYBERSIREN_SERVER__PORT` in the compose file.

### Docker build failures (Python deps)

If `pip3 install lightgbm` fails, it's usually a platform/arch issue. Make sure
you're on `linux/amd64` or `linux/arm64`. If building on Apple Silicon, Docker
Desktop's Rosetta emulation handles it.

### "connection refused" errors

```
failed to load config  error="dial tcp 127.0.0.1:5432: connect: connection refused"
```

The service started before Postgres or Valkey were ready. The `depends_on` +
`condition: service_healthy` in docker-compose handles this automatically. If
you see it, just wait a few seconds and restart:

```bash
docker compose -f deploy/compose/docker-compose.yml restart svc-03-url-analysis
```

### Empty TI results (every domain returns `ti_match: false`)

The Valkey TI cache is populated at svc-03 startup. If the demo-seed hasn't
finished or svc-03 started before the seed completed, the cache is empty.

**Fix:** check the logs for `Demo seed complete.`, then restart svc-03:

```bash
docker compose -f deploy/compose/docker-compose.yml restart svc-03-url-analysis
```

### ML model always returns score 50 / probability 0.5

This means the Python subprocess failed or timed out. Check the logs for:

```
url model: spawn worker 0: worker readiness: ...
```

Common causes:

- **Missing model file** — `model.joblib` must exist at
  `services/svc-03-url-analysis/ml/model.joblib` before building the Docker
  image.
- **Python dependency mismatch** — the model was trained with a different
  `lightgbm` or `scikit-learn` version. Rebuild with `--no-cache`:
  ```bash
  docker compose -f deploy/compose/docker-compose.yml --profile demo build --no-cache svc-03-url-analysis
  ```

### Postgres authentication failure

```
FATAL: password authentication failed for user "cybersiren"
```

The Postgres container was created with a different user. Either set the env vars
as shown in [Quick Start](#quick-start), or reset the volume:

```bash
docker compose -f deploy/compose/docker-compose.yml --profile demo down -v
POSTGRES_USER=cybersiren POSTGRES_PASSWORD=cybersiren \
  docker compose -f deploy/compose/docker-compose.yml --profile demo up --build
```

---

## Stopping the Demo

```bash
# Stop containers (preserves database volume for next run)
docker compose -f deploy/compose/docker-compose.yml --profile demo down

# Stop and remove all data (fresh start next time)
docker compose -f deploy/compose/docker-compose.yml --profile demo down -v
```
