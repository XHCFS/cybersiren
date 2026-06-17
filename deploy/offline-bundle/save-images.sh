#!/usr/bin/env bash
# =============================================================================
# Zero-internet fallback: snapshot the full image set to a single tarball.
# =============================================================================
# Run on ANY machine that already has the images (this VPS, or your laptop after
# one online `START.sh`). Produces deploy/offline-bundle/cybersiren-images.tar.gz,
# which START.sh auto-loads when present — so the laptop needs NO network at all.
#
#   bash deploy/offline-bundle/save-images.sh            # uses :latest
#   CS_IMAGE_TAG=<sha> bash deploy/offline-bundle/save-images.sh
# =============================================================================
set -euo pipefail
TAG="${CS_IMAGE_TAG:-latest}"
OUT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/cybersiren-images.tar.gz"

# Built service images (GHCR refs from images.override.yml) + the base images the
# full+monitoring profiles need. Keep this list in sync with images.override.yml.
SVCS=(svc-01-ingestion svc-02-parser svc-03-url-pipeline svc-04-header-analysis
  svc-05-attachment-analysis svc-06-nlp-pipeline svc-07-aggregator svc-08-decision
  svc-09-notification svc-10-api svc-10-web portal fusion-sidecar nlp-inference svc-11-ti-sync)
IMAGES=()
for s in "${SVCS[@]}"; do IMAGES+=("ghcr.io/xhcfs/cybersiren-${s}:${TAG}"); done
IMAGES+=(
  postgres:15-alpine
  valkey/valkey:7-alpine
  redpandadata/redpanda:v24.2.7
  minio/minio:RELEASE.2025-04-08T15-41-24Z
  minio/mc:RELEASE.2025-04-08T15-39-49Z
  jaegertracing/all-in-one:latest
  prom/prometheus:latest
  grafana/grafana:latest
  caddy:2-alpine
  python:3.12-alpine
)

echo "[save] writing ${#IMAGES[@]} images → $OUT (this is several GB; takes a few minutes)…"
docker save "${IMAGES[@]}" | gzip > "$OUT"
echo "[done] $(du -h "$OUT" | cut -f1)  $OUT"
echo "Copy the whole deploy/offline-bundle/ (incl. this tarball) to the laptop, then run START.sh — it loads the tarball with no network."
