# CyberSiren — Demo Dashboard

A **standalone, throwaway** demo UI for the CyberSiren pipeline. It is a stand-in for the eventual
svc-10 dashboard and is intentionally decoupled from the services — it talks to the pipeline only from
the outside:

- **Forwards** `.eml` uploads and Gmail messages to svc-01's `POST /api/v1/scan` (it holds the demo API
  key server-side, so your browser never sees it).
- **Consumes** the `emails.scored` and `emails.verdict` Kafka topics to render the **per-module scoring
  breakdown** (URL L1/L2, headers, NLP, attachment, aggregation, final verdict).

It owns no spec responsibility and has **no database**. To remove it entirely: delete the `demo/` folder
and the `demo-dashboard` block in `deploy/compose/docker-compose.yml`.

UI: **http://localhost:8090**

---

## Run it

The dashboard needs the **pipeline running** (svc-01 listening on `:8081`, Kafka up). Bring the pipeline
up the usual way (`make up-infra && make db-setup` then `./scripts/dev/run_pipeline.sh start`, or `make
smoke`). Then start the dashboard:

**Natively (simplest for local dev):**
```bash
go run ./demo/dashboard
# → http://localhost:8090
```

**Via docker-compose (demo profile):**
```bash
cd deploy/compose
docker compose --profile demo up -d demo-dashboard
```

### Config (env, all optional)
| Var | Default | Meaning |
|---|---|---|
| `DEMO_ADDR` | `:8090` | listen address |
| `KAFKA_BROKERS` | `localhost:9092` (`kafka:29092` in compose) | brokers to consume from |
| `SVC01_SCAN_URL` | `http://localhost:8081/api/v1/scan` | svc-01 ingest endpoint |
| `DEMO_API_KEY` | `cs_demokey000000000000000000000DEMO` | seeded demo key used to authenticate to svc-01 |
| `GMAIL_POLL_INTERVAL` | `1m` | how often a connected inbox is polled |
| `GMAIL_TOKEN_FILE` | _(unset)_ | optional path to persist the Gmail refresh token across restarts |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GOOGLE_REDIRECT_URL` | — | enable "Sign in with Google" |

**The `.eml` path needs none of this** — just open the page, click **Load sample phish** (or upload an
`.eml`), and **Scan email**. The breakdown appears as the pipeline scores it.

---

## "Sign in with Google" — 5-minute setup

This lets the dashboard scan your **real Gmail inbox**: you click a button, approve read-only access, and
new inbox mail is scanned automatically. It uses **polling only** — no Pub/Sub, no ngrok, no public URL.

> You only set up a Google OAuth client once. Because the app is unverified, you add **yourself** as a
> "test user" — that's expected and fine for a demo.

### 1. Create a Google Cloud project
Open <https://console.cloud.google.com/projectcreate>, name it (e.g. `cybersiren-demo`), and **Create**.
Make sure it's selected in the top project picker.

### 2. Enable the Gmail API
Go to <https://console.cloud.google.com/apis/library/gmail.googleapis.com> and click **Enable**.

### 3. Configure the OAuth consent screen
Open <https://console.cloud.google.com/apis/credentials/consent>:
1. User type: **External** → **Create**.
2. Fill App name + your email for the support/developer fields → **Save and Continue**.
3. **Scopes** → **Add or remove scopes** → paste `https://www.googleapis.com/auth/gmail.readonly` →
   **Update** → **Save and Continue**.
4. **Test users** → **Add users** → add **your own Gmail address** → **Save and Continue**.

### 4. Create the OAuth client (Web application)
Open <https://console.cloud.google.com/apis/credentials> → **Create Credentials** → **OAuth client ID**:
1. Application type: **Web application**.
2. **Authorized redirect URIs** → **Add URI** → `http://localhost:8090/oauth/callback`.
3. **Create** → copy the **Client ID** and **Client secret**.

### 5. Run with the credentials
```bash
export GOOGLE_CLIENT_ID="<your client id>"
export GOOGLE_CLIENT_SECRET="<your client secret>"
go run ./demo/dashboard          # or: docker compose --profile demo up -d demo-dashboard
```
(With compose, put the two vars in your shell or a `.env` next to the compose file.)

### 6. Connect
Open <http://localhost:8090>, click **Sign in with Google**, pick your account, approve the read-only
prompt (click through the "unverified app" notice — it's your own app), and you'll land back on the
dashboard as **Connected**. The few most-recent inbox messages are scanned immediately; new arrivals are
scanned automatically every minute. Send yourself a test phishing-style email and watch it appear.

> **Token persistence:** set `GMAIL_TOKEN_FILE=./demo/dashboard/.gmail-token` to keep the connection
> across restarts (the file is gitignored). Otherwise you reconnect after each restart.

---

## How it maps to the pipeline
```
 you ── .eml / Gmail ──▶ demo-dashboard ──POST /api/v1/scan──▶ svc-01 ──▶ emails.raw ──▶ … ──▶ svc-07 ──▶ emails.scored
                                  ▲                                                                  └─▶ svc-08 ──▶ emails.verdict
                                  └──────────────── consumes emails.scored + emails.verdict ─────────────────┘
```
The dashboard correlates by the `email_id` svc-01 mints (returned from `/api/v1/scan`), then renders the
breakdown from the two topics as they arrive.

> svc-01 also ships its **own** spec Gmail adapter (operator-configured refresh token + Pub/Sub push) for
> production ingestion — that's separate from this demo's interactive sign-in and is documented in
> `services/svc-01-ingestion/README.md`.
