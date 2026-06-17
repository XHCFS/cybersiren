# CyberSiren — Viva Demo Runbook

Everything needed to demo CyberSiren live, plus the offline fallback. The system
runs on a VPS behind one shared Caddy (`*.cie21grad.systems`); a laptop bundle
exists in case the VPS is unreachable.

---

## 1. Public URLs

All HTTPS, auto-TLS via Caddy. Only ports 22/80/443 are open; every app is on
`127.0.0.1` reached through Caddy.

| URL | What | Auth |
|---|---|---|
| https://cs-demo.cie21grad.systems | Inbox scanner / interactive demo | open |
| https://cs-analyst.cie21grad.systems | Analyst console (DB-backed SOC view) | `analyst@demo.cybersiren` / `analyst-demo-2026` |
| https://cs-trace.cie21grad.systems | Jaeger — distributed trace across all services | open |
| https://cs-grafana.cie21grad.systems | Grafana — per-service metrics (12 dashboards) | anon viewer; `admin`/`admin` to edit |

cs-analyst → Monitoring tab links to all of the above + every Grafana board.

ntfy push topic (notifications, §3): subscribe to **`cybersiren-cie21-alerts`** in the
ntfy app (or https://ntfy.sh/cybersiren-cie21-alerts).

---

## 2. Offline / emergency bundle (if the VPS is down)

One command on your laptop, full stack from prebuilt images — see
[`deploy/offline-bundle/README.md`](deploy/offline-bundle/README.md).

```bash
bash deploy/offline-bundle/START.sh        # pull (cached → offline) + up, no build
```

Local URLs: scanner `:18090`, analyst `:18089`, Jaeger `:16686`, Grafana `:3001`.
Images are kept fresh by CI (`.github/workflows/demo-images.yml` → GHCR on every
merge to `main`). **Pre-pull the night before** while you have internet.

---

## 3. Notification service (svc-09) → ntfy

svc-09 is complete: it consumes `emails.verdict`, gates on `risk ≥ org threshold OR
label ∈ {phishing, malware}`, rate-limits one alert per (org, campaign) per hour, and
dispatches over **email (SMTP)** and **webhook**. The webhook is wired to ntfy:

- `.env`: `NOTIFY_WEBHOOK_ENABLED=true`, `NOTIFY_WEBHOOK_URL=https://ntfy.sh/cybersiren-cie21-alerts`
- The demo org already lists `webhook` in `notification_channels`.

**Demo it:** subscribe to `cybersiren-cie21-alerts` in the ntfy phone app, then scan a
phishing sample on cs-demo → a push arrives within ~1 s. The body is the alert JSON
(`verdict_label`, `risk_score`, `email_id`, `campaign_id`). Verify without a phone:

```bash
curl -s "https://ntfy.sh/cybersiren-cie21-alerts/json?poll=1&since=10m"
```

(A 15-line adapter could prettify the JSON into a titled message — optional.)

---

## 4. Gmail → live server (optional; controlled audience only)

The OAuth app is **unverified**, so only Google accounts you add as *test users* can
authorize it — fine for you/examiners, not the public.

1. Google Cloud Console → a project → **Enable the Gmail API**.
2. **OAuth consent screen**: User type *External*; add your (and examiners') Google
   addresses under **Test users**; scope `.../auth/gmail.readonly`. Leave it in
   *Testing* (no verification needed for test users).
3. **Credentials → Create OAuth client ID → Web application**. Authorized redirect URI:
   `https://cs-demo.cie21grad.systems/oauth/callback` (already the portal's default).
4. Put the client id/secret in `deploy/compose/.env`:
   ```
   GOOGLE_CLIENT_ID=...
   GOOGLE_CLIENT_SECRET=...
   ```
5. Recreate the portal: `cd deploy/compose && docker compose --profile full up -d portal`.
6. On cs-demo a **Sign in with Google** button appears → authorize → the inbox is
   polled (`GMAIL_POLL_INTERVAL`, default 1 m) and new mail is scanned automatically.

Notes: read-only; the refresh token is in memory (re-auth after a portal restart unless
`GMAIL_TOKEN_FILE` is set on a volume); revoke anytime in the Google account settings.

---

## 5. Where Gmail-scanned mail shows up (the "DB-backed dashboard")

You already have a DB-backed view: **the analyst console (cs-analyst)** reads
`emails`/`verdicts` from Postgres via svc-10-api. Any Gmail mail flows
`portal → svc-01 → pipeline → Postgres`, so it appears in cs-analyst automatically and
**persists across restarts**.

The cs-demo *portal* itself is intentionally a lightweight, Kafka-fed live view (its
local `.scans.json` is ephemeral). It already reflects Gmail mail in real time, but it
is not the system of record. Recommendation for the viva: **use cs-analyst as the
durable/DB view and cs-demo as the interactive scanner.** (Converting the portal's
storage to the DB is possible but a non-trivial rewrite — not worth the risk pre-viva;
ask if you want it as a follow-up.)

---

## 6. Screenshots to capture (last-resort fallback)

If even the laptop bundle fails, have these ready as slides.

| # | Screen | What it proves |
|---|---|---|
| 1 | cs-demo — benign sample verdict | benign classified correctly (score ~1) |
| 2 | cs-demo — phishing sample + per-module breakdown | URL ML + NLP + header signals → phishing |
| 3 | cs-demo — malware sample (attachment) | malicious attachment → **malware** verdict |
| 4 | cs-demo — TI sample | TI blocklist hit (C2 domain) drives the verdict |
| 5 | cs-analyst — scan list | DB-backed SOC view of all scans |
| 6 | cs-analyst — scan detail | full per-email evidence trail from the DB |
| 7 | cs-analyst — stats dashboard | aggregate threat/campaign/feed stats |
| 8 | cs-analyst — Monitoring tab | links to every dashboard |
| 9 | Jaeger — one trace across ~11 services | distributed tracing through the whole pipeline |
| 10 | Grafana — svc-07 aggregator + svc-08 decision | live pipeline metrics |
| 11 | Grafana — dashboard list (12 boards) | per-service observability coverage |
| 12 | ntfy phone push on a phishing verdict | svc-09 alerting end-to-end |
| 13 | `docker ps` on the VPS | full stack healthy |
| 14 | Terminal: `START.sh` bringing the stack up | the one-command offline fallback works |

---

## 7. Suggested viva demo flow (~10 min)

1. **Frame it (30 s).** "Phishing-detection pipeline: ingestion → parse → URL/NLP/
   header/attachment scoring → fusion decision → notification, fully traced and
   observable, behind one hardened reverse proxy."
2. **cs-demo, benign (1 min).** Load the benign sample → *benign*. Show the per-module
   breakdown: every channel low.
3. **cs-demo, phishing (2 min).** Load the phishing sample → *phishing*. Walk the
   breakdown: URL ML p≈0.94, NLP=100 (credential-harvesting), header rules. Mention the
   **calibrated-OR fusion** — one strong channel is enough (a weighted average would
   wrongly say "suspicious").
4. **cs-demo, malware (1 min).** Load the malware sample → *malware* (known-bad
   attachment hash). Mention the TI sample too (C2 domain blocklist hit).
5. **ntfy (30 s).** Show the push that just landed on your phone for the phishing/malware
   verdicts — svc-09 alerting.
6. **cs-analyst (2 min).** Log in. Scan list (DB-backed) → open the phishing scan detail
   (full evidence trail) → stats dashboard. This is the SOC/analyst view of the same data.
7. **Jaeger (1 min).** Open the trace for one email → one trace spanning ~11 services →
   proves the W3C traceparent propagates across every Kafka hop.
8. **Grafana (1 min).** Monitoring tab → svc-08 decision board (verdicts, latency) and
   the 12-board list → per-service observability.
9. **Architecture/security (1 min).** One Caddy front door, every container on loopback,
   ufw + Docker-bypass lockdown; CI-built images and a one-command offline laptop bundle
   as a fallback.

If the network drops: switch to `START.sh` on the laptop (same flow, `localhost`), or
the screenshot deck (§6).
