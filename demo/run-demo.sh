#!/usr/bin/env bash
#
# run-demo.sh — one-command bring-up / tear-down of the FULL CyberSiren pipeline
# plus the standalone demo dashboard (http://localhost:8090).
#
#   ./demo/run-demo.sh up        # (or: make demo-up)    bring everything up
#   ./demo/run-demo.sh down      # (or: make demo-down)  stop everything
#   ./demo/run-demo.sh restart
#
# `up` resets the DB volume each time so it never trips the "type already exists"
# migration error, brings up infra + the NLP sidecar, seeds the demo API key,
# starts the native pipeline (svc-01..09), then launches the dashboard.
#
# Throwaway demo tooling: to remove the demo entirely, delete demo/, the
# demo-dashboard block in deploy/compose/docker-compose.yml, and the demo-up /
# demo-down targets in the Makefile.
#
# Optional Gmail "Sign in with Google": export GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
# before `up` (see demo/dashboard/README.md). They are inherited by the dashboard.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DC="docker compose -f deploy/compose/docker-compose.yml --env-file deploy/compose/.env"
LOGDIR=".smoke-logs"
DEMO_BIN="$LOGDIR/bin/demo-dashboard"
DEMO_LOG="$LOGDIR/demo-dashboard.log"
DEMO_PID="$LOGDIR/demo-dashboard.pid"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

# wait_healthy blocks until a container reports healthy (or running, if it has no
# healthcheck), up to N seconds.
wait_healthy() {
  local name="$1" tries="${2:-90}" st
  for ((i = 0; i < tries; i++)); do
    st=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$name" 2>/dev/null || echo "")
    case "$st" in healthy | running) return 0 ;; esac
    sleep 1
  done
  echo "timed out waiting for $name to be healthy (status: ${st:-unknown})" >&2
  return 1
}

up() {
  mkdir -p "$LOGDIR/bin"

  step "[1/6] Checking ML models (NLP + URL fusion) are present"
  make check-nlp-model
  make check-fusion-models

  step "[2/6] Resetting volumes for a clean database"
  make down-v >/dev/null 2>&1 || true

  step "[3/6] Starting infra + NLP sidecar (~30s)"
  # No `--wait`: the one-shot redpanda-init/kafka-init containers exit(0), and
  # `up --wait` treats that as a failure (the reason `make smoke` drops it too).
  # We wait for postgres ourselves (db-setup needs it); run_pipeline's preflight
  # blocks on broker/NLP/DB readiness for the rest.
  $DC --profile postgres --profile valkey --profile kafka --profile nlp-inference up -d
  wait_healthy cybersiren-postgres 90

  step "[4/6] Starting the L2 URL fusion-sidecar (built on first run)"
  $DC --profile svc-03 up -d fusion-sidecar
  for _ in $(seq 1 40); do curl -fsS http://localhost:8765/health >/dev/null 2>&1 && break; sleep 2; done

  step "[5/6] Migrating + seeding the database"
  make db-setup

  step "[6/6] Starting the native pipeline + demo dashboard"
  # Point svc-03 at the fusion-sidecar via the fast in-process Go enricher so L2
  # ML URL scoring works and doesn't time out on un-resolvable demo domains.
  export CYBERSIREN_PHISHING__GEOIP_DIR=fusion_export/fusion_kit
  ./scripts/dev/run_pipeline.sh start
  go build -o "$DEMO_BIN" ./demo/dashboard
  "$DEMO_BIN" >"$DEMO_LOG" 2>&1 &
  echo $! >"$DEMO_PID"
  sleep 2

  printf '\n\033[1;32m  ✅ Demo ready  →  http://localhost:8090\033[0m\n'
  if [ -n "${GOOGLE_CLIENT_ID:-}" ]; then
    printf '     Gmail sign-in: ENABLED\n'
  else
    printf '     Gmail sign-in: OFF (export GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET to enable)\n'
  fi
  printf '     Dashboard log: %s\n     Stop everything:  make demo-down\n\n' "$DEMO_LOG"
}

down() {
  step "Stopping the demo dashboard"
  if [ -f "$DEMO_PID" ]; then
    kill "$(cat "$DEMO_PID")" 2>/dev/null || true
    rm -f "$DEMO_PID"
  fi

  step "Stopping the native pipeline"
  ./scripts/dev/run_pipeline.sh stop || true

  step "Stopping infra"
  $DC down --remove-orphans || true

  printf '\n  ✅ Stopped.\n\n'
}

case "${1:-up}" in
up) up ;;
down) down ;;
restart)
  down
  up
  ;;
*)
  echo "usage: $0 {up|down|restart}" >&2
  exit 1
  ;;
esac
