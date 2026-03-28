#!/usr/bin/env bash
# =============================================================================
# check_tools.sh — Verify all required development tools are installed
# =============================================================================
# Checks: go, sqlc, golangci-lint, godotenv, docker, docker compose (v2)
# Exit 0 if all present, 1 if any missing.
# Respects NO_COLOR env var.
# =============================================================================

set -euo pipefail

# ── Color support ────────────────────────────────────────────────────────────
if [ -z "${NO_COLOR:-}" ] && [ -t 1 ]; then
  GREEN='\033[0;32m'
  RED='\033[0;31m'
  YELLOW='\033[0;33m'
  BOLD='\033[1m'
  RESET='\033[0m'
else
  GREEN=''
  RED=''
  YELLOW=''
  BOLD=''
  RESET=''
fi

MISSING=0

# ── Helper ───────────────────────────────────────────────────────────────────
check_tool() {
  local name="$1"
  local check_cmd="$2"
  local version_cmd="$3"
  local install_hint="$4"

  printf "  %-20s" "${name}"

  if eval "${check_cmd}" > /dev/null 2>&1; then
    local version
    version=$(eval "${version_cmd}" 2>&1 | head -1)
    printf "${GREEN}✓${RESET}  %s\n" "${version}"
  else
    printf "${RED}✗  MISSING${RESET}\n"
    printf "    ${YELLOW}Install:${RESET} %s\n" "${install_hint}"
    MISSING=1
  fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}CyberSiren — Development Tool Check${RESET}"
echo "============================================"
echo ""

check_tool \
  "go" \
  "command -v go" \
  "go version" \
  "https://go.dev/dl/"

check_tool \
  "sqlc" \
  "command -v sqlc" \
  "sqlc version" \
  "go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest"

check_tool \
  "golangci-lint" \
  "command -v golangci-lint" \
  "golangci-lint --version" \
  "https://golangci-lint.run/welcome/install/#local-installation"

check_tool \
  "godotenv" \
  "command -v godotenv" \
  "echo godotenv installed" \
  "go install github.com/joho/godotenv/cmd/godotenv@latest"

check_tool \
  "docker" \
  "command -v docker" \
  "docker --version" \
  "https://docs.docker.com/get-docker/"

check_tool \
  "docker compose" \
  "docker compose version" \
  "docker compose version" \
  "Docker Compose v2 is included with Docker Desktop. For Linux: https://docs.docker.com/compose/install/linux/"

echo ""

if [ "${MISSING}" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}All tools present.${RESET}"
  echo ""
  echo -e "${BOLD}Web UIs available after infra is running:${RESET}"
  echo "  pgAdmin    — make open-pgadmin   (http://localhost:5050)"
  echo "  Kafka UI   — make open-kafka-ui   (http://localhost:8080)"
  echo "  Jaeger     — make open-jaeger     (http://localhost:16686)"
  echo "  Open all   — make open"
  echo ""
  exit 0
else
  echo -e "${RED}${BOLD}Some tools are missing — install them before continuing.${RESET}"
  echo ""
  exit 1
fi
