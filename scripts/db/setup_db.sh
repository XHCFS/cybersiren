#!/usr/bin/env bash
# ============================================================
#  setup_db.sh - Database setup and migration script
# ============================================================

set -e  # Exit on error

# Default values
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
DB_PASSWORD="${DB_PASSWORD:-postgres}"
DB_NAME="${DB_NAME:-cybersiren}"
REPO_ROOT="${REPO_ROOT:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}"
MIGRATIONS_DIR="${MIGRATIONS_DIR:-${REPO_ROOT}/db/migrations}"
FEEDS_SEED_FILE="${FEEDS_SEED_FILE:-${REPO_ROOT}/db/seeds/feeds.sql}"

# Construct database URL
DB_URL="postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=disable"

# Check if migrate is installed
if ! command -v migrate &> /dev/null && ! [ -f ~/go/bin/migrate ]; then
    echo "Error: golang-migrate not found. Installing..."
    go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
fi

# Use migrate from go/bin if not in PATH
if ! command -v migrate &> /dev/null; then
    MIGRATE_CMD=~/go/bin/migrate
else
    MIGRATE_CMD=migrate
fi

echo "============================================================"
echo "  CyberSiren Database Setup"
echo "============================================================"
echo "Database: ${DB_NAME}"
echo "Host: ${DB_HOST}:${DB_PORT}"
echo "Migrations directory: ${MIGRATIONS_DIR}"
echo "============================================================"
echo ""

# Create database if it doesn't exist (requires connection to postgres database)
echo "Creating database if it doesn't exist..."
PGPASSWORD="${DB_PASSWORD}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres -tc \
    "SELECT 1 FROM pg_database WHERE datname = '${DB_NAME}'" | grep -q 1 || \
    PGPASSWORD="${DB_PASSWORD}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres \
    -c "CREATE DATABASE ${DB_NAME};"

echo "Database ready."
echo ""

# Run migrations
echo "Running migrations..."
$MIGRATE_CMD -path "${MIGRATIONS_DIR}" -database "${DB_URL}" up

# Seed feeds table (idempotent: each INSERT uses ON CONFLICT on feeds.name)
echo "Seeding feeds table (idempotent)..."
if [ ! -f "${FEEDS_SEED_FILE}" ]; then
    echo "Error: feeds seed file not found at ${FEEDS_SEED_FILE}"
    exit 1
fi

PGPASSWORD="${DB_PASSWORD}" psql \
    -h "${DB_HOST}" \
    -p "${DB_PORT}" \
    -U "${DB_USER}" \
    -d "${DB_NAME}" \
    -v ON_ERROR_STOP=1 \
    -f "${FEEDS_SEED_FILE}"

echo "Feeds seed complete."

echo ""
echo "============================================================"
echo "  Migration complete!"
echo "============================================================"

# Show current migration version
echo ""
echo "Current migration version:"
$MIGRATE_CMD -path "${MIGRATIONS_DIR}" -database "${DB_URL}" version
