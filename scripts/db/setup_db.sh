#!/usr/bin/env bash
# ============================================================
#  setup_db.sh — Database setup and migration script
# ============================================================
# Usage:
#   ./setup_db.sh              — create DB, run migrations, seed
#   ./setup_db.sh migrate-only — create DB, run migrations only
#   ./setup_db.sh seed-only    — seed only (DB and migrations must exist)
# ============================================================

set -e  # Exit on error

MODE="${1:-all}"  # all | migrate-only | seed-only

# Default values
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
DB_PASSWORD="${DB_PASSWORD:-postgres}"
DB_NAME="${DB_NAME:-cybersiren}"
REPO_ROOT="${REPO_ROOT:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}"
MIGRATIONS_DIR="${MIGRATIONS_DIR:-${REPO_ROOT}/db/migrations}"
FEEDS_SEED_FILE="${FEEDS_SEED_FILE:-${REPO_ROOT}/db/seeds/feeds.sql}"

# Docker compose container name for postgres
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-cybersiren-postgres}"

# Construct database URL
DB_URL="postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=disable"

# ── psql helper — local binary or docker exec ────────────────────────────────
run_psql() {
    if command -v psql &> /dev/null; then
        PGPASSWORD="${DB_PASSWORD}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" "$@"
    else
        docker exec -e PGPASSWORD="${DB_PASSWORD}" "${POSTGRES_CONTAINER}" \
            psql -U "${DB_USER}" "$@"
    fi
}

# Check if migrate is installed (only needed for migrate modes)
if [ "${MODE}" != "seed-only" ]; then
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
fi

echo "============================================================"
echo "  CyberSiren Database Setup (mode: ${MODE})"
echo "============================================================"
echo "Database: ${DB_NAME}"
echo "Host: ${DB_HOST}:${DB_PORT}"
echo "Migrations directory: ${MIGRATIONS_DIR}"
echo "============================================================"
echo ""

# ── Create database & run migrations ────────────────────────────────────────
if [ "${MODE}" != "seed-only" ]; then
    # Create database if it doesn't exist
    echo "Creating database if it doesn't exist..."
    run_psql -d postgres -tc \
        "SELECT 1 FROM pg_database WHERE datname = '${DB_NAME}'" | grep -q 1 || \
        run_psql -d postgres -c "CREATE DATABASE ${DB_NAME};"

    echo "Database ready."
    echo ""

    # Run migrations
    echo "Running migrations..."
    $MIGRATE_CMD -path "${MIGRATIONS_DIR}" -database "${DB_URL}" up

    echo ""
    echo "Current migration version:"
    $MIGRATE_CMD -path "${MIGRATIONS_DIR}" -database "${DB_URL}" version
    echo ""
fi

# ── Seed ─────────────────────────────────────────────────────────────────────
if [ "${MODE}" != "migrate-only" ]; then
    # Seed feeds table (idempotent: each INSERT uses ON CONFLICT on feeds.name)
    echo "Seeding feeds table (idempotent)..."
    if [ ! -f "${FEEDS_SEED_FILE}" ]; then
        echo "Error: feeds seed file not found at ${FEEDS_SEED_FILE}"
        exit 1
    fi

    if command -v psql &> /dev/null; then
        PGPASSWORD="${DB_PASSWORD}" psql \
            -h "${DB_HOST}" \
            -p "${DB_PORT}" \
            -U "${DB_USER}" \
            -d "${DB_NAME}" \
            -v ON_ERROR_STOP=1 \
            -f "${FEEDS_SEED_FILE}"
    else
        # When psql is not local, pipe the seed file into docker exec
        docker exec -i -e PGPASSWORD="${DB_PASSWORD}" "${POSTGRES_CONTAINER}" \
            psql -U "${DB_USER}" -d "${DB_NAME}" -v ON_ERROR_STOP=1 \
            < "${FEEDS_SEED_FILE}"
    fi

    echo "Feeds seed complete."
fi

echo ""
echo "============================================================"
echo "  Database setup complete! (mode: ${MODE})"
echo "============================================================"
