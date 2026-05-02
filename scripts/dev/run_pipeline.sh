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
# config validation. They are *not* used at runtime beyond pool.Ping().
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

start() {
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
