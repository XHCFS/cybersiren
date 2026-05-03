#!/usr/bin/env bash
# =============================================================================
# kafka-init.sh — Create CyberSiren pipeline topics on Redpanda (idempotent)
# =============================================================================
# Run by the kafka-init container after Redpanda is healthy. Uses `rpk topic
# create` with per-topic retention/cleanup/compression. Re-running is safe.
# =============================================================================

set -euo pipefail

BOOTSTRAP_SERVER="${BOOTSTRAP_SERVER:-kafka:29092}"
RPK=(rpk -X "brokers=${BOOTSTRAP_SERVER}")
MAX_WAIT=60
INTERVAL=3
ELAPSED=0

echo "=== CyberSiren Redpanda Topic Initializer ==="
echo "Bootstrap server: ${BOOTSTRAP_SERVER}"
echo ""

echo "Waiting for Redpanda to be ready (max ${MAX_WAIT}s)..."
until "${RPK[@]}" cluster info >/dev/null 2>&1; do
  ELAPSED=$((ELAPSED + INTERVAL))
  if [ "${ELAPSED}" -ge "${MAX_WAIT}" ]; then
    echo "ERROR: Redpanda did not become ready within ${MAX_WAIT}s"
    exit 1
  fi
  echo "  ...not ready yet (${ELAPSED}s elapsed), retrying in ${INTERVAL}s"
  sleep "${INTERVAL}"
done
echo "Redpanda is ready."
echo ""

H24="$((24 * 60 * 60 * 1000))"
H48="$((48 * 60 * 60 * 1000))"
D7="$((7 * 24 * 60 * 60 * 1000))"

# Format: topic_name:partitions:retention_ms
TOPICS=(
  "emails.raw:6:${H48}"
  "analysis.urls:6:${H24}"
  "analysis.headers:6:${H24}"
  "analysis.attachments:3:${H24}"
  "analysis.text:6:${H24}"
  "analysis.plans:6:${H24}"
  "scores.url:6:${H24}"
  "scores.header:6:${H24}"
  "scores.attachment:3:${H24}"
  "scores.nlp:6:${H24}"
  "emails.scored:6:${H48}"
  "emails.verdict:6:${D7}"
)

REPLICATION_FACTOR=1

echo "Creating ${#TOPICS[@]} topics..."
for entry in "${TOPICS[@]}"; do
  IFS=':' read -r TOPIC PARTITIONS RETENTION <<<"${entry}"
  echo -n "  ${TOPIC} (parts=${PARTITIONS}, retention.ms=${RETENTION}) ... "

  if "${RPK[@]}" topic describe "${TOPIC}" >/dev/null 2>&1; then
    "${RPK[@]}" topic alter-config "${TOPIC}" \
      --set "retention.ms=${RETENTION}" \
      --set "cleanup.policy=delete" \
      --set "compression.type=zstd" >/dev/null
    echo "exists (config updated)"
  else
    "${RPK[@]}" topic create "${TOPIC}" \
      --partitions "${PARTITIONS}" \
      --replicas "${REPLICATION_FACTOR}" \
      --topic-config "retention.ms=${RETENTION}" \
      --topic-config "cleanup.policy=delete" \
      --topic-config "compression.type=zstd" >/dev/null
    echo "created"
  fi
done

echo ""
echo "=== ${#TOPICS[@]} topics ready ==="
echo ""
echo "Current topics:"
"${RPK[@]}" topic list

exit 0
