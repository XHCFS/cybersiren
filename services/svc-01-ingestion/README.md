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

---

## Gmail live setup (end-to-end runbook)

This is everything needed to drive a **live Gmail → CyberSiren** demo. The
adapter uses the spec's full path: OAuth2-offline + Google Pub/Sub push, with a
`history.list` poll loop as the fallback.

### 0. Prerequisites

- A Google account whose inbox you'll watch (the "demo mailbox").
- A Google Cloud project (free tier is fine).
- `svc-01` reachable from the public internet at a stable HTTPS URL for the
  push webhook. For a laptop demo, [ngrok](https://ngrok.com) is the easiest:
  ```bash
  ngrok http 8081
  # → forwards https://<random>.ngrok-free.app  →  http://localhost:8081
  ```
  Note the `https://…ngrok-free.app` URL; the push subscription will POST to
  `https://…ngrok-free.app/gmail/push`.

### 1. Google Cloud project + enable APIs

1. Console → create (or pick) a project, e.g. `cybersiren-demo`.
2. **APIs & Services → Library** → enable **Gmail API** and **Cloud Pub/Sub API**.

### 2. OAuth consent screen + client (offline access)

1. **APIs & Services → OAuth consent screen** → User type **External** →
   fill app name / support email.
2. **Scopes** → add `https://www.googleapis.com/auth/gmail.readonly`.
3. **Test users** → add the demo-mailbox Google account (an app in "Testing"
   only issues tokens to listed test users — that is fine for a demo and keeps
   you out of Google's verification review).
4. **Credentials → Create credentials → OAuth client ID** → application type
   **Desktop app** (simplest for obtaining a refresh token) → download the
   client. You now have a **Client ID** and **Client secret**.

### 3. Obtain the offline refresh token

You need a one-time consent that returns a long-lived `refresh_token`. Use
Google's OAuth Playground (no code) or any OAuth client:

**OAuth Playground route**
1. Go to <https://developers.google.com/oauthplayground>.
2. Gear icon (top-right) → tick **Use your own OAuth credentials** → paste the
   Client ID + secret.
3. Left panel → input the scope `https://www.googleapis.com/auth/gmail.readonly`
   → **Authorize APIs** → sign in as the demo mailbox → allow.
4. **Exchange authorization code for tokens** → copy the **Refresh token**.

   > To get a refresh token the consent request must use
   > `access_type=offline` and `prompt=consent` — the Playground does this for
   > you. If you build the consent URL yourself, include both.

Set the three secrets:
```bash
CYBERSIREN_GMAIL__CLIENT_ID=<client id>
CYBERSIREN_GMAIL__CLIENT_SECRET=<client secret>
CYBERSIREN_GMAIL__REFRESH_TOKEN=<refresh token>
```

### 4. Create the Pub/Sub topic + push subscription

1. **Pub/Sub → Topics → Create topic**, e.g. `gmail-push`. Its full name is
   `projects/<project-id>/topics/gmail-push` — this is `WATCH_TOPIC`.
2. **Grant Gmail permission to publish to the topic.** Gmail publishes as
   `gmail-api-push@system.gserviceaccount.com`. On the topic → **Permissions /
   Add principal** → principal
   `gmail-api-push@system.gserviceaccount.com`, role **Pub/Sub Publisher**
   (`roles/pubsub.publisher`). *Without this, `watch()` fails.*
   ```bash
   # CLI equivalent:
   gcloud pubsub topics add-iam-policy-binding gmail-push \
     --member="serviceAccount:gmail-api-push@system.gserviceaccount.com" \
     --role="roles/pubsub.publisher"
   ```
3. **Create a PUSH subscription** on that topic whose endpoint is svc-01's
   public `/gmail/push` URL, with the shared token in the query string:
   ```bash
   gcloud pubsub subscriptions create gmail-push-sub \
     --topic=gmail-push \
     --push-endpoint="https://<your-ngrok>.ngrok-free.app/gmail/push?token=<PUSH_TOKEN>" \
     --ack-deadline=10
   ```
   Pick any strong random `<PUSH_TOKEN>` and set it as
   `CYBERSIREN_GMAIL__PUSH_TOKEN`; the `/gmail/push` handler rejects any request
   whose `?token=` does not match (constant-time compare).

   > Hardening (optional): instead of / in addition to the token, configure the
   > subscription with a service-account OIDC identity and set
   > `CYBERSIREN_GMAIL__PUSH_AUDIENCE` to the expected `aud`. The handler checks
   > the audience claim as defence-in-depth (full JWT signature verification
   > against Google's JWKS is a documented follow-up, not wired for the demo).

### 5. Configure svc-01 and start it

Minimum `.env` (see `.env.example` for the annotated full set):
```bash
CYBERSIREN_GMAIL__ENABLED=true
CYBERSIREN_GMAIL__CLIENT_ID=...
CYBERSIREN_GMAIL__CLIENT_SECRET=...
CYBERSIREN_GMAIL__REFRESH_TOKEN=...
CYBERSIREN_GMAIL__USER=me
CYBERSIREN_GMAIL__ORG_ID=1            # the tenant the mailbox belongs to
CYBERSIREN_GMAIL__WATCH_TOPIC=projects/cybersiren-demo/topics/gmail-push
CYBERSIREN_GMAIL__PUSH_ENABLED=true
CYBERSIREN_GMAIL__PUSH_TOKEN=<the same token used in the subscription endpoint>
CYBERSIREN_GMAIL__POLL_ENABLED=true
CYBERSIREN_GMAIL__POLL_INTERVAL=5m
```

`ORG_ID` must be an existing `organisations.id`. Push mail carries no API key,
so it is bound to this org (still config-driven, never request-driven — G10).

Start svc-01 (it calls `users.watch()` automatically on boot once the adapter
is enabled, seeds the history cursor, and starts the renewal + poll loops):
```bash
make build-svc svc=svc-01-ingestion && ./bin/svc-01-ingestion
# or: docker compose up svc-01-ingestion
```

You should see logs like:
```
gmail push endpoint registered at POST /gmail/push
gmail watch registered (renew within 7 days)   history_id=... expiration_epoch_ms=...
gmail: fallback poll loop started   interval=5m0s
```

### 6. Trigger and verify

Send (or move into the watched label) an email to the demo mailbox. Within
seconds the push subscription POSTs to `/gmail/push`; the adapter pulls the new
message via `history.list` + `messages.get?format=raw`, decodes the RFC-822, and
publishes `emails.raw`. Verify the flow:
```
gmail: push notification received      mailbox=demo@gmail.com notified_history_id=...
gmail: message ingested                gmail_message_id=... email_id=<uuidv7> status=0
ingested email; published emails.raw   email_id=<uuidv7> org_id=1 source_adapter=gmail
```
Downstream (svc-02 parser → analysers → svc-08 verdict) then runs unchanged —
the dashboard shows the scored Gmail message.

### 7. The 7-day watch renewal

A Gmail `watch()` registration **expires after 7 days** (ARCH-SPEC §2.1). svc-01
re-issues `watch()` every 24 hours automatically (`RunWatchRenewer`), so a
single missed renewal still leaves several days of slack. If svc-01 is down past
the 7-day window, the watch lapses and pushes stop; the next startup re-registers
it, and the fallback poll loop covers the gap in the meantime. For a multi-day
demo just leave svc-01 running — no manual action needed.

### Delivery semantics / safety

- **Push is primary, poll is the safety net.** Both call the same
  `syncHistory`, serialised by a mutex; the persisted `historyId` cursor (in
  Valkey, key `gmail:history_id:{org}`) is the delta-sync watermark and survives
  restarts.
- **Idempotent.** Every fetched message goes through the shared dedup
  (`dedup:{org}:{message_id}`, 7-day TTL, with the `email_identities` DB
  fallback). A push + a poll seeing the same message, or a Pub/Sub redelivery,
  publishes `emails.raw` once.
- **Acks are generous.** `/gmail/push` returns `204` even when the triggered
  sync errors (logged), so Pub/Sub does not hammer the endpoint with
  redeliveries; the poll loop recovers any gap. It returns `401/400` only for a
  failed token/audience check or an unparseable envelope.

### Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `gmail watch: ... status 403` on boot | Topic missing the `gmail-api-push@system.gserviceaccount.com` **Publisher** binding (step 4.2). |
| Pushes never arrive | ngrok URL changed (free URLs rotate on restart) → update the subscription's push endpoint; or `PUSH_TOKEN` mismatch (handler 401s). |
| `oauth token error ... invalid_grant` | Refresh token revoked/expired, or the consenting account isn't in **Test users**. Re-run step 3. |
| Mail seen but `status=1` (duplicate) | Already ingested within the 7-day dedup window — expected on re-sends. |
| Nothing ingested, no errors | No `historyId` cursor yet (a `watch()` must seed it) — confirm `PUSH_ENABLED=true` so boot calls `watch()`. |
