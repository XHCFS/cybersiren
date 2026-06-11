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
# =============================================================================
# INJECTION A — unified superset fixture. multipart/mixed (outer) wrapping a
# multipart/alternative (empty text + phishy HTML) PLUS one base64 attachment.
# Proves, in one shot:
#   svc-04 auth      — spf=fail / dkim=none / dmarc=fail
#   svc-04 reputation— originating IP 185.220.101.42 (seeded TI indicator)
#   svc-04 structural— D9 html_only + has_form + has_hidden_text
#   svc-03 URL       — both URLs reach the URL XGBoost via the HTML part
#   svc-05 attachment— invoice.pdf.exe (dangerous + double ext + seeded bad hash)
#   svc-06 NLP       — urgency Subject
# The attachment body is the base64 of the FIXED payload
# "CYBERSIREN-SMOKE-MALWARE-FIXTURE-V1\n"; its decoded-bytes sha256 is
#   ed8ac563a8b03e42b728cb322892d906d9b7da618704d13a1aeaa1f3551b00f4
# which db/seeds/attachment_demo_seed.sql pins as the malicious hash. If you
# change the payload bytes, recompute BOTH the base64 below and that seed hash
# (printf '...' | sha256sum) or the hash-lookup silently misses.
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
Content-Type: multipart/mixed; boundary="OUTER-MIX-8a3c9"

--OUTER-MIX-8a3c9
Content-Type: multipart/alternative; boundary="ALT-PART-8a3c9"

--ALT-PART-8a3c9
Content-Type: text/plain; charset=utf-8


--ALT-PART-8a3c9
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear Customer,</p>
<p>We have detected unusual activity on your PayPal account. To prevent
permanent suspension, you must verify your identity within the next
24 hours.</p>
<div style="display:none">verify account now</div>
<form action="http://paypa1-secure.tk/login/verify"><input name="pw"></form>
<p>Click here to confirm your account:
<a href="http://paypa1-secure.tk/login/verify?token=8a3c9">verify</a></p>
<p>Alternative link:
<a href="https://192.0.2.55/paypal/secure-login.html">secure login</a></p>
<p>Failure to verify will result in immediate account closure and forfeit
of pending transfers.</p>
<p>Thank you,<br>PayPal Security Team</p>
</body></html>
--ALT-PART-8a3c9--
--OUTER-MIX-8a3c9
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Disposition: attachment; filename="invoice.pdf.exe"
Content-Transfer-Encoding: base64

Q1lCRVJTSVJFTi1TTU9LRS1NQUxXQVJFLUZJWFRVUkUtVjEK
--OUTER-MIX-8a3c9--
EML_END
)

# =============================================================================
# INJECTION B — minimal real-domain fixture. Its only job is to make svc-04's
# WHOIS-backed reputation.domain_age_days snapshot key appear (and let
# svc04.reputation.young_domain fire), which the synthetic .tk sender in
# Injection A can never do (LookupWHOIS times out on .tk → DomainAgeDays nil →
# key omitted, signals.go:58). The sender domain must be a REAL, WHOIS-
# resolvable domain. Override with SAMPLE_EML_B to use a domain you control.
# No attachment / no HTML body needed — this fixture exists solely for the
# domain-age signal. WHOIS is an external best-effort lookup, so assertion 7 is
# a SOFT (warn-not-fail) check.
DEFAULT_EML_B=$(cat <<'EML_END'
Received: from mail.iana.org (mail.iana.org [192.0.43.10])
	by inbound-mx-01.example.com (Postfix) with ESMTP id 4Gz7Yt2X2y
	for <victim@example.com>; Mon, 02 May 2026 12:31:00 +0000 (UTC)
From: Notifications <noreply@example.com>
Reply-To: noreply@example.com
To: victim@example.com
Subject: Account notice
Date: Mon, 02 May 2026 12:31:00 +0000
Message-ID: <20260502123100.smokeb@iana.org>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

This is a routine account notice. Please review your settings at
https://www.iana.org/domains/example
EML_END
)

# Container names + per-attachment seeded hash (kept in lock-step with the
# fixture base64 above and db/seeds/attachment_demo_seed.sql).
RPK_CONTAINER="${RPK_CONTAINER:-cybersiren-redpanda}"
PG_CONTAINER="${PG_CONTAINER:-cybersiren-postgres}"
VALKEY_CONTAINER="${VALKEY_CONTAINER:-cybersiren-valkey}"
SEEDED_ATTACHMENT_SHA256="ed8ac563a8b03e42b728cb322892d906d9b7da618704d13a1aeaa1f3551b00f4"
WEBHOOK_SINK="${WEBHOOK_SINK:-.smoke-logs/webhook-sink.jsonl}"

# --- helpers ---------------------------------------------------------------

# psql runs a query in the postgres container and prints the unaligned,
# tuples-only result so callers can grep/compare it directly.
pg_query() {
  docker exec -e PGPASSWORD=postgres "$PG_CONTAINER" \
    psql -U postgres -d cybersiren -tAc "$1" 2>/dev/null
}

# inject posts one fixture and returns the matched emails.verdict record (JSON)
# on stdout, or exits non-zero if no verdict arrives within $TIMEOUT.
#   $1 = email_id   $2 = base64-encoded RFC822   $3 = From header  $4 = Subject
inject_and_wait() {
  local email_id="$1" eml_b64="$2" from_hdr="$3" subject="$4"
  local payload resp out match

  payload=$(python3 - "$email_id" "$ORG_ID" "$eml_b64" "$from_hdr" "$subject" <<'PY'
import json, sys
email_id = int(sys.argv[1])
org_id = int(sys.argv[2])
eml_b64 = sys.argv[3]
from_hdr = sys.argv[4]
subject = sys.argv[5]
print(json.dumps({
    "email_id": email_id,
    "org_id": org_id,
    "source_adapter": "smoke-http",
    "message_id": f"<{email_id}@smoke>",
    "raw_message_b64": eml_b64,
    "headers": {"From": from_hdr, "Subject": subject},
}))
PY
)

  echo "==> POST $INGEST_URL  email_id=$email_id" >&2
  resp="$(curl -fsS -X POST "$INGEST_URL" -H 'Content-Type: application/json' --data-raw "$payload")"
  echo "    $resp" >&2

  echo "==> Waiting up to ${TIMEOUT}s for emails.verdict for $email_id" >&2
  # rpk topic consume has no per-call deadline flag, so each poll runs under
  # `timeout`. We use `docker exec` (not `docker compose exec`) to skip the
  # compose-CLI startup cost (~300 ms per call) and a 200 ms cadence so we
  # don't sit on the verdict for an extra second.
  local deadline
  deadline=$(( $(date +%s) + TIMEOUT ))
  match=""
  while [[ $(date +%s) -lt $deadline ]]; do
    out="$(timeout 0.5s docker exec "$RPK_CONTAINER" rpk topic consume emails.verdict \
      -X brokers=localhost:9092 \
      --offset start --num 100 \
      --format '%v\n' 2>/dev/null || true)"
    if grep -q "\"email_id\":${email_id}\b" <<<"$out"; then
      match="$(grep "\"email_id\":${email_id}\b" <<<"$out" | head -1)"
      break
    fi
    sleep 0.2
  done

  if [[ -z "$match" ]]; then
    echo "FAIL: no emails.verdict record for $email_id within ${TIMEOUT}s" >&2
    exit 1
  fi
  printf '%s\n' "$match"
}

# json_field extracts a top-level scalar field from a one-line JSON record.
json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1"
}

fail() { echo "FAIL: $*" >&2; exit 1; }

# =============================================================================
# INJECTION A — superset fixture. All 2a features asserted HARD below.
# =============================================================================
EML_A="${SAMPLE_EML:-$DEFAULT_EML}"
EML_A_B64="$(printf '%s' "$EML_A" | base64 -w0)"

# The compose demo-seed service applies the TI + attachment seeds asynchronously
# during `make smoke` bring-up. Wait until they are committed before injecting,
# so the first (cold) email cannot race the seed and silently drop ti_ip_match
# (svc-04 Postgres TI fallback) or the svc-05 attachment write-back.
echo "==> Waiting for demo seeds (TI ip + attachment hash) to commit"
seed_deadline=$(( $(date +%s) + 60 ))
while :; do
  ti_ready="$(pg_query "SELECT 1 FROM ti_indicators WHERE indicator_type::text='ip' AND indicator_value='185.220.101.42' AND is_active=TRUE LIMIT 1;")"
  att_ready="$(pg_query "SELECT 1 FROM attachment_library WHERE sha256='${SEEDED_ATTACHMENT_SHA256}' AND is_malicious LIMIT 1;")"
  [[ "$ti_ready" == "1" && "$att_ready" == "1" ]] && { echo "  seeds ready"; break; }
  [[ $(date +%s) -ge $seed_deadline ]] && fail "demo seeds not committed within 60s (ti_ip=${ti_ready:-0} attachment=${att_ready:-0})"
  sleep 0.5
done

match="$(inject_and_wait "$EMAIL_ID" "$EML_A_B64" \
  "PayPal Billing <billing@paypa1-secure.tk>" \
  "URGENT: Your PayPal account will be suspended in 24 hours")"

echo "==> verdict PASS (Injection A)"
echo "$match"

# Resolve the surrogate internal_id straight off the verdict record — it is a
# top-level field (shared/contracts/kafka/emails.go EmailsVerdict.InternalID).
# svc-04/05 key rule_hits / email_attachments on this internal_id.
INTERNAL_ID="$(json_field internal_id <<<"$match")"
[[ "$INTERNAL_ID" =~ ^[0-9]+$ && "$INTERNAL_ID" -gt 0 ]] \
  || fail "could not resolve internal_id from verdict (got '$INTERNAL_ID')"
echo "==> internal_id=$INTERNAL_ID"

echo "==> 2a assertions (hard) for internal_id=$INTERNAL_ID"

# --- Assertion 1: svc-05 per-attachment risk_score write-back --------------
row="$(pg_query "SELECT risk_score || '|' || COALESCE(analysis_metadata->>'source','') \
  FROM email_attachments WHERE email_id=${INTERNAL_ID} \
  ORDER BY risk_score DESC NULLS LAST LIMIT 1;")"
a1_score="${row%%|*}"; a1_src="${row#*|}"
[[ -n "$a1_score" ]] || fail "A1: no email_attachments row for internal_id=${INTERNAL_ID}"
[[ "$a1_score" =~ ^[0-9]+$ && "$a1_score" -gt 0 ]] \
  || fail "A1: email_attachments.risk_score not > 0 (got '$a1_score')"
[[ "$a1_src" == "svc-05-attachment-analysis" ]] \
  || fail "A1: analysis_metadata.source != svc-05-attachment-analysis (got '$a1_src')"
echo "  A1 OK: email_attachments.risk_score=${a1_score} source=${a1_src}"

# --- Assertion 2: attachment_library malware flag --------------------------
row="$(pg_query "SELECT is_malicious || '|' || COALESCE(risk_score::text,'') || '|' || \
  (('malware' = ANY(threat_tags)))::text \
  FROM attachment_library WHERE sha256='${SEEDED_ATTACHMENT_SHA256}';")"
IFS='|' read -r a2_mal a2_score a2_tag <<<"$row"
[[ "$a2_mal" == "t" || "$a2_mal" == "true" ]] || fail "A2: attachment_library.is_malicious != true (got '$a2_mal')"
[[ "$a2_score" == "90" ]] || fail "A2: attachment_library.risk_score != 90 (got '$a2_score')"
[[ "$a2_tag" == "t" || "$a2_tag" == "true" ]] || fail "A2: 'malware' not in attachment_library.threat_tags"
echo "  A2 OK: is_malicious=t risk_score=90 threat_tags⊇{malware}"

# --- Assertion 3: scores.attachment payload --------------------------------
a3=""
deadline=$(( $(date +%s) + 20 ))
while [[ $(date +%s) -lt $deadline ]]; do
  out="$(timeout 0.5s docker exec "$RPK_CONTAINER" rpk topic consume scores.attachment \
    -X brokers=localhost:9092 --offset start --num 200 --format '%v\n' 2>/dev/null || true)"
  a3="$(grep "\"email_id\":${EMAIL_ID}\b" <<<"$out" | head -1 || true)"
  [[ -n "$a3" ]] && break
  sleep 0.2
done
[[ -n "$a3" ]] || fail "A3: no scores.attachment record for email_id=${EMAIL_ID}"
a3_count="$(json_field attachment_count <<<"$a3")"
a3_score="$(json_field score <<<"$a3")"
[[ "$a3_count" =~ ^[0-9]+$ && "$a3_count" -ge 1 ]] \
  || fail "A3: attachment_count < 1 (got '$a3_count')"
[[ "$a3_score" =~ ^[0-9]+$ && "$a3_score" -gt 0 ]] \
  || fail "A3: scores.attachment score not > 0 (got '$a3_score')"
echo "  A3 OK: scores.attachment attachment_count=${a3_count} score=${a3_score}"

# --- Assertion 4: svc-04 new structural + IP-TI rule_hits ------------------
hits="$(pg_query "SELECT r.name FROM rule_hits rh JOIN rules r ON r.id = rh.rule_id \
  WHERE rh.entity_id=${INTERNAL_ID};")"
for want in svc04.structural.embedded_form svc04.structural.html_only \
            svc04.structural.hidden_text svc04.reputation.ti_ip_match; do
  grep -qx "$want" <<<"$hits" || fail "A4: rule_hit '$want' missing (got: $(tr '\n' ' ' <<<"$hits"))"
done
echo "  A4 OK: rule_hits ⊇ {embedded_form, html_only, hidden_text, ti_ip_match}"

# --- Assertion 5: svc-09 webhook DELIVERY ----------------------------------
# The recorder (run_pipeline.sh) appends one JSON line per POST. Require at
# least one POST whose body carries our email_id AND an X-Signature header
# (a secret is set in SVC_09_ENV).
[[ -f "$WEBHOOK_SINK" ]] || fail "A5: webhook sink file $WEBHOOK_SINK not found"
a5_hit="$(python3 - "$WEBHOOK_SINK" "$EMAIL_ID" <<'PY'
import json, sys
path, eid = sys.argv[1], sys.argv[2]
ok = False
with open(path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        body = rec.get("body", "")
        hdrs = {k.lower(): v for k, v in rec.get("headers", {}).items()}
        if f'"email_id":{eid}' in body.replace(" ", "") and "x-signature" in hdrs:
            ok = True
            break
print("yes" if ok else "no")
PY
)"
[[ "$a5_hit" == "yes" ]] \
  || fail "A5: no webhook POST referencing email_id=${EMAIL_ID} with X-Signature in $WEBHOOK_SINK"
# Metric cross-check: gated message + webhook sent.
m09="$(curl -fsS http://localhost:9109/metrics 2>/dev/null || true)"
gated="$(grep -E '^notification_messages_total\{[^}]*outcome="gated"[^}]*\}' <<<"$m09" | awk '{print $2}' | head -1)"
sent="$(grep -E '^notification_alerts_total\{[^}]*channel="webhook"[^}]*result="sent"[^}]*\}' <<<"$m09" | awk '{print $2}' | head -1)"
awk -v v="${gated:-0}" 'BEGIN{exit !(v+0 >= 1)}' \
  || fail "A5: notification_messages_total{outcome=gated} < 1 (got '${gated:-unset}')"
awk -v v="${sent:-0}" 'BEGIN{exit !(v+0 >= 1)}' \
  || fail "A5: notification_alerts_total{channel=webhook,result=sent} < 1 (got '${sent:-unset}')"
echo "  A5 OK: webhook POST recorded (X-Signature present); gated=${gated} sent=${sent}"

# --- Assertion 6: svc-09 Redis rate-limit key ------------------------------
rkey="$(docker exec "$VALKEY_CONTAINER" redis-cli --no-raw KEYS 'notif:1:*' 2>/dev/null \
  | sed -E 's/^[0-9]+\) "?//; s/"?$//' | grep -E '^notif:1:' | head -1 || true)"
[[ -n "$rkey" ]] || fail "A6: no Redis rate-limit key matching notif:1:* in $VALKEY_CONTAINER"
rttl="$(docker exec "$VALKEY_CONTAINER" redis-cli TTL "$rkey" 2>/dev/null | tr -dc '0-9-')"
[[ "$rttl" =~ ^[0-9]+$ ]] || fail "A6: TTL of $rkey not numeric (got '$rttl')"
[[ "$rttl" -ge 1 && "$rttl" -le 3600 ]] \
  || fail "A6: TTL of $rkey not in [1,3600] (got '$rttl')"
echo "  A6 OK: rate-limit key=${rkey} ttl=${rttl}s"

# =============================================================================
# INJECTION B — real-domain fixture. SOFT-assert domain-age (WHOIS external).
# =============================================================================
EMAIL_ID_B="${EMAIL_ID_B:-$(( EMAIL_ID + 1 ))}"
EML_B="${SAMPLE_EML_B:-$DEFAULT_EML_B}"
EML_B_B64="$(printf '%s' "$EML_B" | base64 -w0)"

match_b="$(inject_and_wait "$EMAIL_ID_B" "$EML_B_B64" \
  "Notifications <noreply@example.com>" "Account notice")"

echo "==> verdict PASS (Injection B)"
INTERNAL_ID_B="$(json_field internal_id <<<"$match_b")"

# --- Assertion 7 (SOFT): svc-04 domain-age SIGNAL via live WHOIS ------------
# Injection B uses a real, WHOIS-resolvable sender (example.com), so svc-04's
# WHOIS domain-age lookup should populate reputation.domain_age_days on
# scores.header. We prove the FEATURE at the signal level: an old domain won't
# trip the young_domain rule (that rule is unit-tested separately), but a
# non-null domain_age_days proves the WHOIS lookup + parse ran end-to-end.
# WHOIS is an external dependency, so this stays soft (warn, not fail).
dah=""
deadline=$(( $(date +%s) + 20 ))
while [[ $(date +%s) -lt $deadline ]]; do
  out="$(timeout 0.5s docker exec "$RPK_CONTAINER" rpk topic consume scores.header \
    -X brokers=localhost:9092 --offset start --num 400 --format '%v\n' 2>/dev/null || true)"
  dah="$(grep "\"email_id\":${EMAIL_ID_B}\b" <<<"$out" | head -1 || true)"
  [[ -n "$dah" ]] && break
  sleep 0.2
done
da_age="$(python3 -c "import sys,json
try:
    d=json.loads(sys.stdin.read()); v=d.get('signals',{}).get('domain_age_days')
    print('' if v is None else v)
except Exception:
    print('')" <<<"$dah")"
if [[ "$da_age" =~ ^[0-9]+$ ]]; then
  echo "  A7 OK: scores.header signals.domain_age_days=${da_age} for Injection B (live WHOIS resolved)"
else
  echo "  A7 WARN: domain_age_days not populated (got '${da_age:-unset}') — depends on a live" >&2
  echo "           external WHOIS lookup (best-effort). Not failing smoke." >&2
fi

echo "==> PASS (all hard 2a assertions cleared)"
