# SVC-01 — Ingestion Service

The pipeline entry point. It exposes two `EmailSource` adapters that share one
ingestion core (auth → dedup → quota → UUIDv7 mint → publish `emails.raw`):

| Adapter | Transport | Auth | Trigger |
|---------|-----------|------|---------|
| **API-upload** | `POST /api/v1/scan` | API key (org bound from the key) | on demand |
| **Gmail** | Gmail API v1 over HTTPS | OAuth2 offline (`gmail.readonly`) | Pub/Sub **push** → `POST /gmail/push`, plus a 5-min fallback poll |

Scope is **API-upload + Gmail only** (decision D2/G2); IMAP and Outlook are
deferred. svc-01 never writes the `emails` table — svc-02 is the sole writer.
Both adapters mint the logical `email_id` as a **UUIDv7** and bind `org_id`
from config/key, never the request body (G10/RLS).

> **Want to demo scanning a real inbox? Don't use this adapter.** The easiest
> "Sign in with Google" demo lives in the standalone dashboard — see
> **[`demo/dashboard/README.md`](../../demo/dashboard/README.md)** for a 5-minute,
> poll-only setup (no Pub/Sub, no ngrok). The section below is the **production
> operator** path for svc-01's own Gmail adapter.

---

## Gmail adapter — operator configuration (production path)

svc-01's built-in Gmail adapter uses the spec's full path: OAuth2-offline + a
Google **Pub/Sub push** webhook (`POST /gmail/push`), with a `history.list` poll
loop as the fallback. It is configured entirely from env (single mailbox, single
org); the mailbox's `org_id` is bound from config, never a request (G10).

**Setup outline** (full Google Cloud walkthrough is in the demo README, steps 1–4):
1. Enable the **Gmail API** + **Cloud Pub/Sub API** in a Google Cloud project.
2. OAuth consent screen (External) + scope `gmail.readonly` + add the mailbox as
   a **Test user**; create an OAuth client and obtain an offline **refresh token**.
3. Create a Pub/Sub topic and grant `gmail-api-push@system.gserviceaccount.com`
   the **Pub/Sub Publisher** role on it (without this, `watch()` 403s).
4. Create a **push subscription** whose endpoint is svc-01's public
   `/gmail/push?token=<PUSH_TOKEN>` URL (expose svc-01 with ngrok for a laptop demo).

**Minimum `.env`** (annotated full set in `.env.example`):
```bash
CYBERSIREN_GMAIL__ENABLED=true
CYBERSIREN_GMAIL__CLIENT_ID=...
CYBERSIREN_GMAIL__CLIENT_SECRET=...
CYBERSIREN_GMAIL__REFRESH_TOKEN=...
CYBERSIREN_GMAIL__USER=me
CYBERSIREN_GMAIL__ORG_ID=1                     # an existing organisations.id
CYBERSIREN_GMAIL__WATCH_TOPIC=projects/<proj>/topics/gmail-push
CYBERSIREN_GMAIL__PUSH_ENABLED=true
CYBERSIREN_GMAIL__PUSH_TOKEN=<shared secret in the subscription endpoint>
CYBERSIREN_GMAIL__POLL_ENABLED=true
CYBERSIREN_GMAIL__POLL_INTERVAL=5m
```

On boot svc-01 calls `users.watch()`, seeds the Valkey history cursor
(`gmail:history_id:{org}`), and starts the 24h watch renewer (a Gmail watch
expires after 7 days) + the fallback poll loop. Push and poll both call the same
mutex-serialised `syncHistory`; every message goes through the shared dedup
(`dedup:{org}:{message_id}`, 7-day TTL + `email_identities` DB fallback), so a
push/poll overlap or a Pub/Sub redelivery publishes `emails.raw` once.
`/gmail/push` acks `204` even on a sync error (logged; poll recovers), and
`401/400` only on a failed token/audience check or unparseable envelope.

### Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `gmail watch: ... status 403` on boot | Topic missing the `gmail-api-push@system.gserviceaccount.com` **Publisher** binding. |
| Pushes never arrive | ngrok URL rotated → update the subscription's push endpoint; or `PUSH_TOKEN` mismatch (handler 401s). |
| `oauth token error ... invalid_grant` | Refresh token revoked/expired, or the account isn't in **Test users**. |
| Mail seen but `status=1` (duplicate) | Already ingested within the 7-day dedup window — expected on re-sends. |
| Nothing ingested, no errors | No `historyId` cursor yet (a `watch()` must seed it) — confirm `PUSH_ENABLED=true`. |
