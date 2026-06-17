#!/usr/bin/env bash
# =============================================================================
# CyberSiren — one-command demo launcher (laptop / emergency fallback)
# =============================================================================
# Brings up the ENTIRE stack from prebuilt GHCR images — no local build, no VPS.
#
#   bash deploy/offline-bundle/START.sh
#
# Images are pulled from GHCR (kept fresh by .github/workflows/demo-images.yml).
# Pull ONCE while you have internet; Docker caches them locally, so it then runs
# fully OFFLINE at the venue. For zero-internet, see save-images.sh / a *.tar.gz
# next to this script (auto-loaded below).
#
# Env toggles:
#   CS_IMAGE_TAG=latest      image tag to run (default: latest; or a commit sha)
#   WITH_MONITORING=1        include Grafana+Prometheus (default 1; 0 saves ~2GB)
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"
export CS_IMAGE_TAG="${CS_IMAGE_TAG:-latest}"

PROFILES=(--profile full)
[ "${WITH_MONITORING:-1}" = "1" ] && PROFILES+=(--profile monitoring)
COMPOSE=(docker compose
  -f deploy/compose/docker-compose.yml
  -f deploy/offline-bundle/images.override.yml
  -p cybersiren "${PROFILES[@]}")

# A .env is required for compose interpolation; fall back to the committed example.
[ -f deploy/compose/.env ] || { echo "[setup] no .env — copying .env.example"; cp deploy/compose/.env.example deploy/compose/.env; }

# Zero-internet path: if an images tarball is shipped next to this script, load it.
TARBALL="$(dirname "${BASH_SOURCE[0]}")/cybersiren-images.tar.gz"
if [ -f "$TARBALL" ]; then
  echo "[load] found $TARBALL — loading images (offline mode)…"
  gunzip -c "$TARBALL" | docker load
else
  echo "[pull] fetching images from GHCR (needs internet; cached afterwards)…"
  "${COMPOSE[@]}" pull || echo "  pull failed — assuming images are already cached locally; continuing"
fi

echo "[up] starting the stack (no local build)…"
"${COMPOSE[@]}" up -d --no-build

echo "[wait] waiting for the dashboards to come up…"
ready() { curl -fsS -o /dev/null --max-time 3 "$1" 2>/dev/null; }
for _ in $(seq 1 90); do
  if ready http://localhost:18090/ && ready http://localhost:18089/; then break; fi
  sleep 2
done

cat <<EOF

  ✅ CyberSiren demo is up (local, offline-capable). Open:

     Inbox scanner / demo  →  http://localhost:18090
     Analyst console       →  http://localhost:18089   (analyst@demo.cybersiren / analyst-demo-2026)
     Jaeger tracing        →  http://localhost:16686
     Grafana metrics       →  http://localhost:3001    (admin / admin)

  Seed data (TI domains, malicious attachment hash, demo API key, analyst login)
  loads automatically. Submit a sample on the inbox scanner to see a verdict.

  Stop:   docker compose -f deploy/compose/docker-compose.yml -f deploy/offline-bundle/images.override.yml -p cybersiren --profile full --profile monitoring down
EOF
