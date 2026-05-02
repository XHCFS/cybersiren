#!/usr/bin/env bash
# =============================================================================
# inject_fake_email.sh — Smoke an Infrastructure Spine v0 pipeline.
# =============================================================================
# Posts a synthetic /ingest request to svc-01-ingestion (default port 8081),
# then waits up to N seconds for emails.verdict to receive a record keyed by
# the same email_id. Uses `rpk topic consume` inside the redpanda container.
# =============================================================================

set -euo pipefail

INGEST_URL="${INGEST_URL:-http://localhost:8081/ingest}"
TIMEOUT="${TIMEOUT:-30}"
COMPOSE="${COMPOSE:-docker compose -f deploy/compose/docker-compose.yml --env-file deploy/compose/.env}"

EMAIL_ID="${EMAIL_ID:-smoke-$(date +%s)-$RANDOM}"
ORG_ID="${ORG_ID:-org-smoke}"

echo "==> POST $INGEST_URL  email_id=$EMAIL_ID"
resp="$(curl -fsS -X POST "$INGEST_URL" \
  -H 'Content-Type: application/json' \
  -d "{\"email_id\":\"$EMAIL_ID\",\"org_id\":\"$ORG_ID\",\"raw_message_b64\":\"Zm9v\",\"headers\":{\"From\":\"smoke@example.com\"}}")"
echo "    $resp"

echo "==> Waiting up to ${TIMEOUT}s for emails.verdict for $EMAIL_ID"
# rpk topic consume has no per-call deadline flag, so we wrap each poll in
# `timeout` — it scans from --offset start and is killed after 2 s. The outer
# loop bounds the total wait to $TIMEOUT.
deadline=$(( $(date +%s) + TIMEOUT ))
match=""
while [[ $(date +%s) -lt $deadline ]]; do
  out="$(timeout 2s $COMPOSE exec -T kafka rpk topic consume emails.verdict \
    -X brokers=localhost:9092 \
    --offset start --num 100 \
    --format '%v\n' 2>/dev/null || true)"
  if grep -q "\"email_id\":\"$EMAIL_ID\"" <<<"$out"; then
    match="$(grep "\"email_id\":\"$EMAIL_ID\"" <<<"$out" | head -1)"
    break
  fi
  sleep 1
done

if [[ -z "$match" ]]; then
  echo "FAIL: no emails.verdict record for $EMAIL_ID within ${TIMEOUT}s" >&2
  exit 1
fi

echo "==> PASS"
echo "$match"
