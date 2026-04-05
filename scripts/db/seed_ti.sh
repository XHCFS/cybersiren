#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "Seeding feeds..."
psql -f "$REPO_ROOT/db/seeds/feeds.sql"

echo "Seeding TI demo indicators..."
psql -f "$REPO_ROOT/db/seeds/ti_demo_seed.sql"

echo "TI seed complete."
