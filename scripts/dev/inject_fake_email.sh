#!/usr/bin/env bash
# =============================================================================
# inject_fake_email.sh — Smoke an Infrastructure Spine v0 pipeline.
# =============================================================================
# Posts a realistic phishing-flavoured RFC-822 email to svc-01-ingestion
# (default port 8081), then waits up to N seconds for emails.verdict to
# receive a record keyed by the same email_id.
#
# The email payload is intentionally "phishy" so the real models (svc-03
# URL XGBoost, svc-04 header analyser, svc-06 NLP DistilBERT) all have
# something meaningful to score. Override SAMPLE_EML to use a different
# fixture.
# =============================================================================

set -euo pipefail

INGEST_URL="${INGEST_URL:-http://localhost:8081/ingest}"
TIMEOUT="${TIMEOUT:-60}"
COMPOSE="${COMPOSE:-docker compose -f deploy/compose/docker-compose.yml --env-file deploy/compose/.env}"

EMAIL_ID="${EMAIL_ID:-$(date +%s%N | head -c 16)}"
ORG_ID="${ORG_ID:-1}"

# Default sample EML. Crafted to trigger SPF/DKIM/DMARC mis-alignment
# (svc-04), a suspicious URL (svc-03), and urgency / credential-prompt
# language (svc-06). It is base64-encoded so it survives the JSON
# transport without escaping problems.
DEFAULT_EML=$(cat <<'EML_END'
Received: from mx-out.attacker-cdn.tk (mx-out.attacker-cdn.tk [185.220.101.42])
	by inbound-mx-01.example.com (Postfix) with ESMTP id 4Gz7Yt2X1z
	for <victim@example.com>; Mon, 02 May 2026 12:30:00 +0000 (UTC)
Authentication-Results: inbound-mx-01.example.com;
	spf=fail (sender IP is 185.220.101.42)
	    smtp.mailfrom=billing@paypa1-secure.tk;
	dkim=none (no signature);
	dmarc=fail action=none header.from=paypal.com
From: PayPal Billing <billing@paypa1-secure.tk>
Reply-To: noreply@paypa1-secure.tk
To: victim@example.com
Subject: URGENT: Your PayPal account will be suspended in 24 hours
Date: Mon, 02 May 2026 12:30:00 +0000
Message-ID: <20260502123000.smoke@paypa1-secure.tk>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Dear Customer,

We have detected unusual activity on your PayPal account. To prevent
permanent suspension, you must verify your identity within the next
24 hours.

Click here to confirm your account: http://paypa1-secure.tk/login/verify?token=8a3c9
Alternative link: https://192.0.2.55/paypal/secure-login.html

Failure to verify will result in immediate account closure and forfeit
of pending transfers.

Thank you,
PayPal Security Team
EML_END
)

EML="${SAMPLE_EML:-$DEFAULT_EML}"
EML_B64="$(printf '%s' "$EML" | base64 -w0)"

# Build JSON safely with python3 (avoids escaping headaches).
PAYLOAD=$(python3 - "$EMAIL_ID" "$ORG_ID" "$EML_B64" <<'PY'
import json, sys
email_id = int(sys.argv[1])
org_id = int(sys.argv[2])
eml_b64 = sys.argv[3]
print(json.dumps({
    "email_id": email_id,
    "org_id": org_id,
    "source_adapter": "smoke-http",
    "message_id": f"<{email_id}@smoke>",
    "raw_message_b64": eml_b64,
    "headers": {
        "From": "PayPal Billing <billing@paypa1-secure.tk>",
        "Subject": "URGENT: Your PayPal account will be suspended in 24 hours",
    },
}))
PY
)

echo "==> POST $INGEST_URL  email_id=$EMAIL_ID"
resp="$(curl -fsS -X POST "$INGEST_URL" -H 'Content-Type: application/json' --data-raw "$PAYLOAD")"
echo "    $resp"

echo "==> Waiting up to ${TIMEOUT}s for emails.verdict for $EMAIL_ID"
# rpk topic consume has no per-call deadline flag, so each poll runs under
# `timeout`. The outer loop bounds the total wait.
deadline=$(( $(date +%s) + TIMEOUT ))
match=""
while [[ $(date +%s) -lt $deadline ]]; do
  out="$(timeout 2s $COMPOSE exec -T kafka rpk topic consume emails.verdict \
    -X brokers=localhost:9092 \
    --offset start --num 100 \
    --format '%v\n' 2>/dev/null || true)"
  if grep -q "\"email_id\":${EMAIL_ID}\b" <<<"$out"; then
    match="$(grep "\"email_id\":${EMAIL_ID}\b" <<<"$out" | head -1)"
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
