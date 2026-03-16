#!/usr/bin/env bash
# =============================================================================
# kafka-init.sh — Create all CyberSiren Kafka topics (idempotent)
# =============================================================================
# Run by the kafka-init container after Kafka is healthy.
# Creates 12 pipeline topics with specified partition counts.
# Uses --if-not-exists so it is safe to re-run.
# =============================================================================

set -euo pipefail

BOOTSTRAP_SERVER="${BOOTSTRAP_SERVER:-kafka:29092}"
MAX_WAIT=60
INTERVAL=3
ELAPSED=0

echo "=== CyberSiren Kafka Topic Initializer ==="
echo "Bootstrap server: ${BOOTSTRAP_SERVER}"
echo ""

# ── Wait for Kafka to be ready ───────────────────────────────────────────────
echo "Waiting for Kafka to be ready (max ${MAX_WAIT}s)..."
until kafka-broker-api-versions --bootstrap-server "${BOOTSTRAP_SERVER}" > /dev/null 2>&1; do
  ELAPSED=$((ELAPSED + INTERVAL))
  if [ "${ELAPSED}" -ge "${MAX_WAIT}" ]; then
    echo "ERROR: Kafka did not become ready within ${MAX_WAIT}s"
    exit 1
  fi
  echo "  ...not ready yet (${ELAPSED}s elapsed), retrying in ${INTERVAL}s"
  sleep "${INTERVAL}"
done
echo "Kafka is ready."
echo ""

# ── Topic definitions ────────────────────────────────────────────────────────
# Format: topic_name:partitions
TOPICS=(
  "emails.raw:6"
  "analysis.urls:6"
  "analysis.headers:6"
  "analysis.attachments:3"
  "analysis.text:6"
  "analysis.plans:6"
  "scores.url:6"
  "scores.header:6"
  "scores.attachment:3"
  "scores.nlp:6"
  "emails.scored:6"
  "emails.verdict:6"
)

REPLICATION_FACTOR=1

# ── Create topics ────────────────────────────────────────────────────────────
echo "Creating ${#TOPICS[@]} topics..."
echo ""

for entry in "${TOPICS[@]}"; do
  TOPIC="${entry%%:*}"
  PARTITIONS="${entry##*:}"

  echo -n "  ${TOPIC} (${PARTITIONS} partitions) ... "
  kafka-topics \
    --bootstrap-server "${BOOTSTRAP_SERVER}" \
    --create \
    --if-not-exists \
    --topic "${TOPIC}" \
    --partitions "${PARTITIONS}" \
    --replication-factor "${REPLICATION_FACTOR}" \
    2>&1

  echo "OK"
done

echo ""
echo "=== All ${#TOPICS[@]} topics created successfully ==="

# ── List topics for verification ─────────────────────────────────────────────
echo ""
echo "Current topics:"
kafka-topics --bootstrap-server "${BOOTSTRAP_SERVER}" --list

exit 0
