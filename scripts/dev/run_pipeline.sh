#!/usr/bin/env bash
# =============================================================================
# run_pipeline.sh — Boot every Infrastructure Spine v0 stub natively.
# =============================================================================
# Each stub binds its metrics/healthz port to a distinct host port (9101..9110)
# so Prometheus can scrape them concurrently without collisions. Logs are
# written under .smoke-logs/. The script exits as soon as every healthz
# returns 200, leaving the stubs running in the background.
#
# Usage:
#   scripts/dev/run_pipeline.sh start   # default
#   scripts/dev/run_pipeline.sh stop    # kill everything started here
# =============================================================================

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

LOGDIR=".smoke-logs"
PIDDIR=".smoke-logs/pids"
mkdir -p "$LOGDIR" "$PIDDIR"

# Common env: every stub needs at minimum the same DB/auth values to satisfy
# config validation. The ML.* values point svc-03 at the real URL inference
# script and svc-06 at the FastAPI nlp-inference container (started by the
# `make smoke` target via the smoke compose profile).
COMMON_ENV=(
  CYBERSIREN_ENV=development
  CYBERSIREN_LOG__LEVEL=info
  CYBERSIREN_LOG__PRETTY=true
  CYBERSIREN_DB__HOST=localhost
  CYBERSIREN_DB__PORT=5432
  CYBERSIREN_DB__NAME=cybersiren
  CYBERSIREN_DB__USER=postgres
  CYBERSIREN_DB__PASSWORD=postgres
  CYBERSIREN_DB__SSL_MODE=disable
  CYBERSIREN_VALKEY__ADDR=localhost:6379
  CYBERSIREN_AUTH__JWT_SECRET=demo-secret-not-for-production-use!!
  CYBERSIREN_KAFKA__BROKERS=localhost:9092
  CYBERSIREN_JAEGER_ENDPOINT=http://localhost:4318
  # Real-model wiring (used by svc-03 url-pipeline and svc-06 nlp-pipeline).
  CYBERSIREN_ML__URL_MODEL_PATH=services/svc-03-url-analysis/ml/inference_script.py
  CYBERSIREN_ML__URL_MODEL_POOL_SIZE=2
  CYBERSIREN_ML__NLP_SERVICE_URL=http://localhost:8001
)

# Per-service overrides (svc-04 header analyser needs its own block).
SVC_04_ENV=(
  CYBERSIREN_HEADER__CONSUME_TOPIC=analysis.headers
  CYBERSIREN_HEADER__PRODUCE_TOPIC=scores.header
  CYBERSIREN_HEADER__CONSUMER_GROUP=cg-header-analysis
)

# Service spec rows: name | go-package | metrics_port | http_port (0 = none)
SERVICES=(
  "svc-01-ingestion|./services/svc-01-ingestion/cmd/ingestion|9101|8081"
  "svc-02-parser|./services/svc-02-parser/cmd/parser|9102|0"
  "svc-03-url-pipeline|./services/svc-03-url-analysis/cmd/url-pipeline|9103|0"
  "svc-04-header-analysis|./services/svc-04-header-analysis/cmd/header-analysis|9104|0"
  "svc-05-attachment-analysis|./services/svc-05-attachment-analysis/cmd/attachment-analysis|9105|0"
  "svc-06-nlp-pipeline|./services/svc-06-nlp/cmd/nlp-pipeline|9106|0"
  "svc-07-aggregator|./services/svc-07-aggregator/cmd/aggregator|9107|0"
  "svc-08-decision|./services/svc-08-decision/cmd/decision|9108|0"
  "svc-09-notification|./services/svc-09-notification/cmd/notification|9109|0"
  "svc-10-api-dashboard|./services/svc-10-api-dashboard/cmd/api|9110|0"
)

preflight() {
  # svc-03 url-pipeline spawns python3 inference_script.py — verify the
  # required wheels are importable before we start it. The error message
  # is what the smoke target surfaces if any are missing.
  echo "==> Preflight: Python deps for URL inference"
  if ! command -v python3 >/dev/null 2>&1; then
    echo "  python3 not on PATH — install Python 3.10+ and retry" >&2
    return 1
  fi
  local missing=""
  for mod in joblib numpy xgboost sklearn tldextract; do
    if ! python3 -c "import ${mod}" >/dev/null 2>&1; then
      missing="${missing} ${mod}"
    fi
  done
  if [[ -n "$missing" ]]; then
    echo "  Missing Python packages:${missing}" >&2
    echo "  Install locally with:  pip install --user joblib numpy xgboost scikit-learn tldextract" >&2
    return 1
  fi
  echo "  OK"

  # svc-06 nlp-pipeline expects the FastAPI nlp-inference container on :8001.
  echo "==> Preflight: NLP inference service on http://localhost:8001"
  for i in $(seq 1 60); do
    if curl -fsS http://localhost:8001/healthz >/dev/null 2>&1; then
      ready=$(curl -fsS http://localhost:8001/healthz | python3 -c "import sys,json; print(json.load(sys.stdin).get('model_ready'))" 2>/dev/null || echo "false")
      if [[ "$ready" == "True" || "$ready" == "true" ]]; then
        echo "  OK (model_ready=true)"
        return 0
      fi
    fi
    sleep 2
  done
  echo "  NLP inference not ready after 120s. Start it with:" >&2
  echo "  docker compose -f deploy/compose/docker-compose.yml --env-file deploy/compose/.env --profile nlp-inference up -d --wait" >&2
  return 1
}

start() {
  preflight

  echo "==> Building binaries"
  go build -o "$LOGDIR/bin/" ./services/svc-01-ingestion/cmd/ingestion \
                              ./services/svc-02-parser/cmd/parser \
                              ./services/svc-03-url-analysis/cmd/url-pipeline \
                              ./services/svc-04-header-analysis/cmd/header-analysis \
                              ./services/svc-05-attachment-analysis/cmd/attachment-analysis \
                              ./services/svc-06-nlp/cmd/nlp-pipeline \
                              ./services/svc-07-aggregator/cmd/aggregator \
                              ./services/svc-08-decision/cmd/decision \
                              ./services/svc-09-notification/cmd/notification \
                              ./services/svc-10-api-dashboard/cmd/api

  echo "==> Starting stubs"
  for spec in "${SERVICES[@]}"; do
    IFS='|' read -r name pkg mport hport <<<"$spec"
    bin_name="$(basename "$pkg")"
    binary="$LOGDIR/bin/$bin_name"
    log="$LOGDIR/$name.log"
    pidfile="$PIDDIR/$name.pid"

    if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
      echo "  $name already running (pid $(cat "$pidfile"))"
      continue
    fi

    env_args=("${COMMON_ENV[@]}" "CYBERSIREN_METRICS_PORT=$mport")
    if [[ "$hport" != "0" ]]; then
      env_args+=("CYBERSIREN_SERVER__PORT=$hport")
    fi
    if [[ "$name" == "svc-04-header-analysis" ]]; then
      env_args+=("${SVC_04_ENV[@]}")
    fi

    echo "  $name (metrics=$mport http=$hport) → $log"
    env "${env_args[@]}" "$binary" >"$log" 2>&1 &
    echo $! > "$pidfile"
  done

  echo "==> Waiting for healthz"
  for spec in "${SERVICES[@]}"; do
    IFS='|' read -r name pkg mport hport <<<"$spec"
    for i in $(seq 1 30); do
      if curl -fsS "http://localhost:$mport/healthz" >/dev/null 2>&1; then
        echo "  $name OK"
        break
      fi
      sleep 0.5
      if [[ $i -eq 30 ]]; then
        echo "  $name FAILED (no /healthz after 15s) — see $LOGDIR/$name.log" >&2
        exit 1
      fi
    done
  done
  echo "==> Pipeline stubs running"
}

stop() {
  echo "==> Stopping stubs"
  if [[ ! -d "$PIDDIR" ]]; then
    echo "  (no pid dir)"
    return 0
  fi
  for pidfile in "$PIDDIR"/*.pid; do
    [[ -e "$pidfile" ]] || continue
    pid="$(cat "$pidfile")"
    if kill -0 "$pid" 2>/dev/null; then
      echo "  killing pid=$pid ($(basename "$pidfile" .pid))"
      kill "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  done
}

case "${1:-start}" in
  start) start ;;
  stop)  stop ;;
  *) echo "usage: $0 {start|stop}" >&2; exit 2 ;;
esac
