# CyberSiren API Reference

HTTP surface of the platform: the **ingestion** endpoint (SVC-01) and the
**dashboard API** (SVC-10). All examples use `curl`.

- Ingestion base URL: `http://localhost:8081`
- Dashboard API base URL: `http://localhost:8080`

## Authentication

Two schemes:

| Scheme | Used by | Header |
|--------|---------|--------|
| **API key** | `/ingest` (machine clients) | `X-API-Key: <key>` or `Authorization: Bearer <key>` |
| **JWT** | dashboard `/api/v1/*` (users) | `Authorization: Bearer <jwt>` |

API keys are minted with the `cs_` prefix and stored only as a SHA-256 hash; the
plaintext is shown once at creation. JWTs are obtained from `POST /api/v1/auth/login`
and carry the caller's `org_id` + `user_id`; every dashboard read is scoped to
that org.

---

## SVC-01 — Ingestion

### `POST /ingest`
Accepts an email and publishes it to the pipeline. `org_id` is derived from the
API key (any `org_id` in the body is ignored). Rate limited to 100 req/min/org;
a repeated `(org, message_id)` within 7 days is acknowledged as a duplicate and
not re-published.

**JSON (base64 RFC-822):**
```bash
curl -sS -X POST http://localhost:8081/ingest \
  -H "X-API-Key: cs_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "message_id": "<abc@example.com>",
    "source_adapter": "http",
    "raw_message_b64": "'"$(base64 -w0 sample.eml)"'"
  }'
```

**Multipart upload (raw .eml file):**
```bash
curl -sS -X POST http://localhost:8081/ingest \
  -H "X-API-Key: cs_your_key" \
  -F "email=@sample.eml" \
  -F "message_id=<abc@example.com>" \
  -F "source_adapter=upload"
```

Responses: `202 {"status":"accepted","email_id":…}`, `200 {"status":"duplicate",…}`,
`401` (missing/invalid key), `429` (rate limited).

---

## SVC-10 — Dashboard API

### `POST /api/v1/auth/login` (public)
```bash
curl -sS -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@acme.test","password":"••••••"}'
# → {"token":"<jwt>","user":{"id":1,"email":"admin@acme.test","role":"admin","org_id":1}}
```
`401` on bad credentials. Save the token:
```bash
TOKEN=$(curl -sS -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@acme.test","password":"pw"}' | jq -r .token)
```

### `GET /healthz` (public)
```bash
curl -sS http://localhost:8080/healthz   # → {"status":"ok"}
```

### `GET /api/v1/emails` (JWT)
Paged scan list for the caller's org. Query params: `page` (1-based), `page_size` (≤100).
```bash
curl -sS "http://localhost:8080/api/v1/emails?page=1&page_size=25" \
  -H "Authorization: Bearer $TOKEN"
```

### `GET /api/v1/emails/:id` (JWT)
Full detail: header, URLs (joined with enrichment), attachments, recipients, verdict history.
```bash
curl -sS http://localhost:8080/api/v1/emails/123 -H "Authorization: Bearer $TOKEN"
```
`404` if the email doesn't exist for the caller's org.

### `GET /api/v1/stats` (JWT)
```bash
curl -sS http://localhost:8080/api/v1/stats -H "Authorization: Bearer $TOKEN"
# → {"total":…,"phishing":…,"suspicious":…,"high_risk":…,"last_24h":…}
```

### `GET /api/v1/campaigns` (JWT)
```bash
curl -sS http://localhost:8080/api/v1/campaigns -H "Authorization: Bearer $TOKEN"
```

### `GET /api/v1/verdicts/recent` (JWT)
Most-recent verdicts from the in-memory feed (newest first).
```bash
curl -sS http://localhost:8080/api/v1/verdicts/recent -H "Authorization: Bearer $TOKEN"
```

Protected routes return `401` without a valid JWT.

---

## Notes
- The WebSocket live feed (`/ws/verdicts`) is not yet implemented; poll
  `GET /api/v1/verdicts/recent` instead.
- Rules/API-key CRUD and the analyst verdict-override endpoint are planned
  follow-ups and not documented here yet.
