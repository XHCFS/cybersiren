#!/usr/bin/env bash
# End-to-end test for svc-03-url-analysis /scan: guard short-circuits,
# L2 escalation, and TI re-invitation paths. Uses a stdlib stub sidecar
# (no .joblib models) and a JSON-fixture TI override (no Valkey/Postgres
# TI feed needed).
#
# Postgres IS required (svc-03 pool.MustNew at startup). Provide a DSN
# via CYBERSIREN_DB__* env or let the GH Actions service container do it.
#
# Usage:
#   make e2e-svc-03         # from repo root
#   bash services/svc-03-url-analysis/tests/e2e/run.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../../.." && pwd)"
FIXTURE_FILE="$HERE/fixtures/scan_cases.json"
TI_FIXTURE="${TI_FIXTURE:-/tmp/cybersiren-e2e-ti-fixture.json}"
SVC_BIN="${SVC_BIN:-/tmp/cybersiren-svc-03-e2e}"

# Default to free loopback ports so the e2e never collides with a running
# stack: Prometheus owns host :19090, the smoke pipeline owns 9101-9110, and
# the fusion-sidecar container owns :8765. Override any of these via env.
pick_free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}
STUB_PORT="${STUB_PORT:-$(pick_free_port)}"
SVC_PORT="${SVC_PORT:-$(pick_free_port)}"
SVC_METRICS_PORT="${SVC_METRICS_PORT:-$(pick_free_port)}"
SVC_BASE="http://127.0.0.1:${SVC_PORT}"
STUB_BASE="http://127.0.0.1:${STUB_PORT}"
STUB_PID=""
SVC_PID=""

cleanup() {
  local code=$?
  if [[ -n "$STUB_PID" ]] && kill -0 "$STUB_PID" 2>/dev/null; then
    kill "$STUB_PID" 2>/dev/null || true
    wait "$STUB_PID" 2>/dev/null || true
  fi
  if [[ -n "$SVC_PID" ]] && kill -0 "$SVC_PID" 2>/dev/null; then
    kill "$SVC_PID" 2>/dev/null || true
    wait "$SVC_PID" 2>/dev/null || true
  fi
  rm -f "$TI_FIXTURE"
  exit "$code"
}
trap cleanup EXIT INT TERM

require() {
  command -v "$1" >/dev/null 2>&1 || { echo "[e2e] missing required tool: $1" >&2; exit 2; }
}
require go
require python3
require jq
require curl

cd "$REPO_ROOT"

echo "[e2e] building svc-03 -> $SVC_BIN"
go build -trimpath -o "$SVC_BIN" ./services/svc-03-url-analysis/cmd/url-analysis/

echo "[e2e] starting stub sidecar on :$STUB_PORT"
python3 "$HERE/stub_sidecar.py" --port "$STUB_PORT" >/tmp/cybersiren-e2e-stub.log 2>&1 &
STUB_PID=$!

# Wait for stub sidecar /health (max ~15s).
for _ in $(seq 1 30); do
  if curl -fsS "$STUB_BASE/health" >/dev/null 2>&1; then
    echo "[e2e] stub sidecar ready"
    break
  fi
  sleep 0.5
done
curl -fsS "$STUB_BASE/health" >/dev/null

# Build TI override fixture from cases.
jq '[.cases[] | select(.ti_inject != null) | {(.url): .ti_inject}] | add // {}' \
   "$FIXTURE_FILE" > "$TI_FIXTURE"

echo "[e2e] TI override fixture: $TI_FIXTURE ($(jq 'length' "$TI_FIXTURE") entries)"

echo "[e2e] starting svc-03 on :$SVC_PORT"
CYBERSIREN_ENV=development \
CYBERSIREN_LOG__LEVEL=warn \
CYBERSIREN_LOG__PRETTY=false \
CYBERSIREN_SERVER__PORT="$SVC_PORT" \
CYBERSIREN_METRICS_PORT="$SVC_METRICS_PORT" \
CYBERSIREN_AUTH__JWT_SECRET="e2e-secret-not-for-production-use!!" \
CYBERSIREN_ML__URL_MODEL_PATH="$REPO_ROOT/services/svc-03-url-analysis/ml/inference_script.py" \
CYBERSIREN_PHISHING__SIDECAR_URL="$STUB_BASE" \
CYBERSIREN_PHISHING__THRESHOLD=0.50 \
CYBERSIREN_VALKEY__ADDR="${CYBERSIREN_VALKEY__ADDR:-127.0.0.1:1}" \
CYBERSIREN_DEV_MODE=true \
CYBERSIREN_TI__OVERRIDE_JSON="$TI_FIXTURE" \
  "$SVC_BIN" >/tmp/cybersiren-e2e-svc.log 2>&1 &
SVC_PID=$!

# Wait for svc-03 /healthz (max ~20s).
for _ in $(seq 1 40); do
  if curl -fsS "$SVC_BASE/healthz" >/dev/null 2>&1; then
    echo "[e2e] svc-03 ready"
    break
  fi
  sleep 0.5
done
if ! curl -fsS "$SVC_BASE/healthz" >/dev/null 2>&1; then
  echo "[e2e] svc-03 failed to come up. Last 40 lines of log:" >&2
  tail -40 /tmp/cybersiren-e2e-svc.log >&2
  exit 1
fi

pass=0
fail=0

mapfile -t case_blob_lines < <(jq -c '.cases[]' "$FIXTURE_FILE")
for blob in "${case_blob_lines[@]}"; do
  name=$(echo "$blob" | jq -r '.name')
  url=$(echo "$blob" | jq -r '.url')
  expect=$(echo "$blob" | jq -c '.expect')

  resp=$(curl -sS -X POST -H "Content-Type: application/json" \
              --max-time 30 \
              -d "$(jq -nc --arg u "$url" '{url: $u}')" \
              "$SVC_BASE/scan" || echo '{"_curl_failed":true}')
  # Shared HTTP server wraps the handler result as {"success":true,"data":{...}};
  # unwrap once so case assertions can address the scan envelope directly.
  data=$(echo "$resp" | jq -c '.data // .')

  ok=true
  msg=""

  exp_label=$(echo "$expect" | jq -r '.label // empty')
  if [[ -n "$exp_label" ]]; then
    got_label=$(echo "$data" | jq -r '.label // empty')
    if [[ "$got_label" != "$exp_label" ]]; then
      ok=false; msg+=" label=$got_label (want=$exp_label)"
    fi
  fi

  exp_guard=$(echo "$expect" | jq -r '.guard_hit // empty')
  if [[ -n "$exp_guard" ]]; then
    got_guard=$(echo "$data" | jq -r '.guard_hit // empty')
    if [[ "$got_guard" != "$exp_guard" ]]; then
      ok=false; msg+=" guard_hit=$got_guard (want=$exp_guard)"
    fi
  fi

  exp_guard_prefix=$(echo "$expect" | jq -r '.guard_hit_prefix // empty')
  if [[ -n "$exp_guard_prefix" ]]; then
    got_guard=$(echo "$data" | jq -r '.guard_hit // empty')
    case "$got_guard" in
      "$exp_guard_prefix"*) ;;
      *) ok=false; msg+=" guard_hit=$got_guard (want prefix=$exp_guard_prefix)";;
    esac
  fi

  exp_ml=$(echo "$expect" | jq -r '.ml_verdict // empty')
  if [[ -n "$exp_ml" ]]; then
    got_ml=$(echo "$data" | jq -r '.ml_verdict // empty')
    if [[ "$got_ml" != "$exp_ml" ]]; then
      ok=false; msg+=" ml_verdict=$got_ml (want=$exp_ml)"
    fi
  fi

  if $ok; then
    pass=$((pass+1))
    printf "[e2e] PASS  %s\n" "$name"
  else
    fail=$((fail+1))
    printf "[e2e] FAIL  %s  ==>%s\n" "$name" "$msg" >&2
    printf "[e2e]       response: %s\n" "$resp" >&2
  fi
done

printf "\n[e2e] summary: %d passed / %d failed\n" "$pass" "$fail"
if [[ "$fail" -gt 0 ]]; then
  echo "[e2e] svc-03 log tail:" >&2
  tail -30 /tmp/cybersiren-e2e-svc.log >&2
  exit 1
fi
