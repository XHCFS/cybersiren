# =============================================================================
# CyberSiren — Makefile
# =============================================================================
# Run `make help` to see all available targets with descriptions.
# =============================================================================

# Load .env if present — makes env vars available to targets that need them.
# NOTE: We do NOT `export` here to avoid leaking CYBERSIREN_* vars into
# `go test` subprocesses, which would break config tests that expect a clean
# environment. Targets needing .env vars use godotenv or source .env explicitly.
ifneq (,$(wildcard .env))
  include .env
endif

DOCKER_COMPOSE := docker compose -f deploy/compose/docker-compose.yml \
                  --env-file deploy/compose/.env

# Git SHA for image tagging — short SHA, falls back to "dev" if not in a git repo
GIT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")

# Image registry — override via: make docker-push REGISTRY=ghcr.io/myorg
REGISTRY ?= ghcr.io/cybersiren

# ── Service dependency map ───────────────────────────────────────────────────
# Profiles to start per service. Defined once here, referenced everywhere.
SVC_DEPS_SVC_11_TI_SYNC             := postgres valkey
SVC_DEPS_SVC_01_INGESTION           := postgres kafka
SVC_DEPS_SVC_02_PARSER              := postgres kafka
SVC_DEPS_SVC_03_URL_ANALYSIS        := postgres valkey kafka
SVC_DEPS_SVC_04_HEADER_ANALYSIS     := postgres valkey kafka
SVC_DEPS_SVC_05_ATTACHMENT_ANALYSIS := postgres valkey kafka
SVC_DEPS_SVC_06_NLP                 := kafka
SVC_DEPS_SVC_07_AGGREGATOR          := valkey kafka
SVC_DEPS_SVC_08_DECISION            := postgres valkey kafka
SVC_DEPS_SVC_09_NOTIFICATION        := postgres valkey kafka
SVC_DEPS_SVC_10_API_DASHBOARD       := postgres valkey kafka

# ── Helpers ──────────────────────────────────────────────────────────────────
# Convert svc-name to the Makefile variable form: svc-11-ti-sync → SVC_11_TI_SYNC
svc-name-to-var  = $(subst -,_,$(shell echo $(1) | tr '[:lower:]' '[:upper:]'))
# Build --profile flags from the dependency map
svc-profiles     = $(foreach p,$(SVC_DEPS_$(call svc-name-to-var,$(1))),--profile $(p))
# Derive binary name from cmd/ subdirectory (e.g., svc-10-api-dashboard → api)
svc-binary-name  = $(shell ls services/$(1)/cmd/ 2>/dev/null | head -1)
# Derive Dockerfile suffix: strip svc-XX- prefix, replace - with _
dockerfile-name  = $(shell echo $(1) | sed 's/svc-[0-9]*-//' | sed 's/-/_/g')

# =============================================================================
# ── CI ───────────────────────────────────────────────────────────────────────
# =============================================================================

## ci: Full CI pipeline requiring no infra (check-tidy → generate-check → vet → lint → test-short → build)
ci: check-tidy generate-check vet lint test-short build

## ci-integration: Integration tests requiring infra (starts infra, sets up DB, runs tests, tears down)
ci-integration:
	$(MAKE) up-infra
	$(MAKE) db-setup
	$(MAKE) test
	$(MAKE) down

## check-tidy: Verify go.mod and go.sum are tidy
check-tidy:
	go mod tidy
	git diff --exit-code go.mod go.sum || \
		(echo "go.mod or go.sum is out of sync — run 'go mod tidy' and commit"; exit 1)

## generate-check: Verify sqlc generated files are in sync with query files
generate-check:
	sqlc generate
	git diff --exit-code db/sqlc/ || \
		(echo "sqlc generated files are out of sync — run 'make generate' and commit"; exit 1)

# =============================================================================
# ── Docker: build and publish images ─────────────────────────────────────────
# =============================================================================

## docker-build: Build Docker image for a service. Usage: make docker-build svc=svc-11-ti-sync
docker-build: check-docker
	@[ "$(svc)" ] || (echo "Usage: make docker-build svc=<service-name>"; exit 1)
	docker build \
		-f deploy/docker/Dockerfile.$(call dockerfile-name,$(svc)) \
		-t $(REGISTRY)/$(svc):$(GIT_SHA) \
		-t $(REGISTRY)/$(svc):latest \
		.
	@echo "Built: $(REGISTRY)/$(svc):$(GIT_SHA)"

## docker-push: Push built image to registry. Usage: make docker-push svc=svc-11-ti-sync
docker-push: docker-build
	docker push $(REGISTRY)/$(svc):$(GIT_SHA)
	docker push $(REGISTRY)/$(svc):latest

## docker-build-all: Build images for all services
docker-build-all: check-docker
	@for svc in svc-01-ingestion svc-02-parser svc-03-url-analysis \
	            svc-04-header-analysis svc-05-attachment-analysis svc-06-nlp \
	            svc-07-aggregator svc-08-decision svc-09-notification \
	            svc-10-api-dashboard svc-11-ti-sync; do \
		$(MAKE) docker-build svc=$$svc || exit 1; \
	done

# =============================================================================
# ── Dev: run a service with its required infra ───────────────────────────────
# =============================================================================

## dev: Start required infra for a service then run it natively.
##      Usage: make dev svc=svc-11-ti-sync
##             make dev svc=svc-11-ti-sync observability=true
##      Pass observability=true to also start Jaeger.
dev: check-docker
	@[ "$(svc)" ] || (echo "Usage: make dev svc=<service-name>"; exit 1)
	@echo "→ Starting infra for $(svc): $(SVC_DEPS_$(call svc-name-to-var,$(svc)))"
	$(DOCKER_COMPOSE) $(call svc-profiles,$(svc)) \
		$(if $(filter true,$(observability)),--profile observability,) \
		up -d --wait
	@$(MAKE) _db-setup-if-needed svc=$(svc)
	@echo "→ Running $(svc) (Ctrl+C to stop)"
	godotenv -f .env go run ./services/$(svc)/cmd/$(call svc-binary-name,$(svc))/

_db-setup-if-needed:
	@if echo "$(SVC_DEPS_$(call svc-name-to-var,$(svc)))" | grep -q postgres; then \
		$(MAKE) db-setup; \
	fi

# =============================================================================
# ── Dev environment (full infra) ─────────────────────────────────────────────
# =============================================================================

## up: Start all infra (postgres, valkey, kafka, jaeger)
up: check-docker
	$(DOCKER_COMPOSE) --profile postgres --profile valkey \
	                  --profile kafka --profile observability up -d --wait

## up-infra: Start core infra without observability
up-infra: check-docker
	$(DOCKER_COMPOSE) --profile postgres --profile valkey --profile kafka up -d --wait

## down: Stop all infra containers (preserves volumes)
down: check-docker
	$(DOCKER_COMPOSE) --profile postgres --profile valkey \
	                  --profile kafka --profile observability down

## down-v: Stop all infra and destroy volumes — WARNING: destroys all data
down-v: check-docker
	$(DOCKER_COMPOSE) --profile postgres --profile valkey \
	                  --profile kafka --profile observability down -v

## logs: Tail logs. Usage: make logs  OR  make logs svc=postgres
logs: check-docker
	$(DOCKER_COMPOSE) logs -f $(svc)

## ps: Show infra container status
ps: check-docker
	$(DOCKER_COMPOSE) ps

# =============================================================================
# ── Database ─────────────────────────────────────────────────────────────────
# =============================================================================

## db-setup: Run migrations then seeds (idempotent)
db-setup:
	@./scripts/db/setup_db.sh

## db-migrate: Run migrations only
db-migrate:
	@./scripts/db/setup_db.sh migrate-only

## db-seed: Run seeds only
db-seed:
	@./scripts/db/setup_db.sh seed-only

## db-reset: Full local DB reset — destroys volumes, restarts infra, reruns setup
db-reset: down-v up-infra db-setup

## db-shell: Open psql shell (local psql if available, otherwise docker exec)
db-shell:
	@if command -v psql > /dev/null; then \
		psql "postgres://$(CYBERSIREN_DB__USER):$(CYBERSIREN_DB__PASSWORD)@$(CYBERSIREN_DB__HOST):$(CYBERSIREN_DB__PORT)/$(CYBERSIREN_DB__NAME)?sslmode=disable"; \
	else \
		$(DOCKER_COMPOSE) --profile postgres exec postgres psql -U "$(CYBERSIREN_DB__USER)" -d "$(CYBERSIREN_DB__NAME)"; \
	fi

# =============================================================================
# ── Code generation ──────────────────────────────────────────────────────────
# =============================================================================

## generate: Run sqlc generate and go generate
generate:
	sqlc generate
	go generate ./...

# =============================================================================
# ── Build ────────────────────────────────────────────────────────────────────
# =============================================================================

## build: Build all packages
build:
	go build ./...

## build-svc: Build a specific service binary into bin/. Usage: make build-svc svc=svc-11-ti-sync
build-svc:
	@[ "$(svc)" ] || (echo "Usage: make build-svc svc=<service-name>"; exit 1)
	@mkdir -p bin
	go build -o bin/$(svc) \
		./services/$(svc)/cmd/$(call svc-binary-name,$(svc))/

# =============================================================================
# ── Test ─────────────────────────────────────────────────────────────────────
# =============================================================================

## test: Run all tests with race detector (requires infra for integration tests)
test:
	go test -race ./...

## test-svc: Run tests for a specific service. Usage: make test-svc svc=svc-11-ti-sync
test-svc:
	@[ "$(svc)" ] || (echo "Usage: make test-svc svc=<service-name>"; exit 1)
	go test -v -race ./services/$(svc)/...

## test-shared: Run tests for all shared packages
test-shared:
	go test -v -race ./shared/...

## test-short: Run tests skipping integration tests (no infra required)
test-short:
	go test -race -short ./...

## test-cover: Run all tests and open HTML coverage report
test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

# =============================================================================
# ── Lint / vet ───────────────────────────────────────────────────────────────
# =============================================================================

## vet: Run go vet across all packages
vet:
	go vet ./...

## lint: Run golangci-lint
lint:
	golangci-lint run ./...

## lint-fix: Run golangci-lint with auto-fix
lint-fix:
	golangci-lint run --fix ./...

# =============================================================================
# ── Utilities ────────────────────────────────────────────────────────────────
# =============================================================================

## tidy: Run go mod tidy
tidy:
	go mod tidy

## valkey-cli: Open valkey-cli shell
valkey-cli:
	@if command -v valkey-cli > /dev/null; then \
		valkey-cli -h localhost -p $${VALKEY_PORT:-6379}; \
	elif command -v redis-cli > /dev/null; then \
		redis-cli -h localhost -p $${VALKEY_PORT:-6379}; \
	else \
		$(DOCKER_COMPOSE) --profile valkey exec valkey valkey-cli; \
	fi

## kafka-topics: List all topics on local Kafka
kafka-topics:
	$(DOCKER_COMPOSE) --profile kafka exec kafka \
		kafka-topics --bootstrap-server localhost:9092 --list

## check-tools: Verify all required development tools are installed
check-tools:
	@./scripts/dev/check_tools.sh

# ── Service profile short-names ──────────────────────────────────────────────
# Maps full service name to its docker-compose profile short-name.
# Example: svc-03-url-analysis → svc-03, svc-11-ti-sync → svc-11
svc-short-profile = $(shell echo $(1) | sed 's/^\(svc-[0-9]*\).*/\1/')

# =============================================================================
# ── Observability ────────────────────────────────────────────────────────────
# =============================================================================

## demo: Run a service with full observability stack (Prometheus, Grafana, Jaeger).
##       Uses cached images — fast on repeat runs. Force a rebuild with: make demo-build svc=<name>
##       Usage: make demo svc=svc-03-url-analysis
##              make demo svc=svc-11-ti-sync
demo: check-docker
	@[ "$(svc)" ] || (echo "Usage: make demo svc=<service-name>"; exit 1)
	$(DOCKER_COMPOSE) --profile postgres --profile valkey \
	    --profile monitoring --profile observability \
	    --profile $(call svc-short-profile,$(svc)) up -d --wait
	@echo ""
	@echo "  Service:     $(svc)"
	@echo "  Grafana:     http://localhost:3001"
	@echo "  Prometheus:  http://localhost:9092"
	@echo "  Jaeger:      http://localhost:16686"
	@echo ""

## demo-build: Like demo but force-rebuilds the service image first.
##             Use after code changes. Usage: make demo-build svc=svc-11-ti-sync
demo-build: check-docker
	@[ "$(svc)" ] || (echo "Usage: make demo-build svc=<service-name>"; exit 1)
	$(DOCKER_COMPOSE) --profile postgres --profile valkey \
	    --profile monitoring --profile observability \
	    --profile $(call svc-short-profile,$(svc)) up -d --wait --build
	@echo ""
	@echo "  Service:     $(svc)"
	@echo "  Grafana:     http://localhost:3001"
	@echo "  Prometheus:  http://localhost:9092"
	@echo "  Jaeger:      http://localhost:16686"
	@echo ""

## demo-all: Run ALL services with full observability stack.
##           Uses cached images — fast on repeat runs. Force a rebuild with: make demo-all-build
demo-all: check-docker
	$(DOCKER_COMPOSE) --profile postgres --profile valkey \
	    --profile monitoring --profile observability \
	    --profile svc-03 --profile svc-11 up -d --wait
	@echo ""
	@echo "  Services:    svc-03-url-analysis, svc-11-ti-sync"
	@echo "  Grafana:     http://localhost:3001"
	@echo "  Prometheus:  http://localhost:9092"
	@echo "  Jaeger:      http://localhost:16686"
	@echo ""

## demo-all-build: Like demo-all but force-rebuilds all service images first.
##                 Use after code changes.
demo-all-build: check-docker
	$(DOCKER_COMPOSE) --profile postgres --profile valkey \
	    --profile monitoring --profile observability \
	    --profile svc-03 --profile svc-11 up -d --wait --build
	@echo ""
	@echo "  Services:    svc-03-url-analysis, svc-11-ti-sync"
	@echo "  Grafana:     http://localhost:3001"
	@echo "  Prometheus:  http://localhost:9092"
	@echo "  Jaeger:      http://localhost:16686"
	@echo ""

## jaeger: Start Jaeger standalone (use when already running infra separately)
jaeger: check-docker
	$(DOCKER_COMPOSE) --profile observability up -d --wait
	@echo "Jaeger UI: http://localhost:16686"

## open: Open all available web UIs in the default browser
open:
	@$(MAKE) _open-url url=http://localhost:16686
	@$(MAKE) _open-url url=http://localhost:8080
	@$(MAKE) _open-url url=http://localhost:5050
	@echo "Metrics endpoint (not a UI): http://localhost:$(METRICS_PORT)/metrics"

## open-grafana: Open Grafana dashboards
open-grafana:
	@$(MAKE) _open-url url=http://localhost:3001

## open-prometheus: Open Prometheus query UI
open-prometheus:
	@$(MAKE) _open-url url=http://localhost:9092

## open-jaeger: Open Jaeger tracing UI
open-jaeger:
	@$(MAKE) _open-url url=http://localhost:16686

## open-kafka-ui: Open Kafka UI
open-kafka-ui:
	@$(MAKE) _open-url url=http://localhost:8080

## open-pgadmin: Open pgAdmin
open-pgadmin:
	@$(MAKE) _open-url url=http://localhost:5050

# Internal: cross-platform open URL
_open-url:
	@if [ "$(shell uname)" = "Darwin" ]; then \
		open $(url); \
	elif command -v xdg-open > /dev/null; then \
		xdg-open $(url); \
	else \
		echo "Open manually: $(url)"; \
	fi

## help: Print all targets with descriptions
help:
	@grep -E '^##' Makefile | sed 's/^## //' | column -t -s ':'

# =============================================================================
# ── Internal ─────────────────────────────────────────────────────────────────
# =============================================================================

check-docker:
	@docker info > /dev/null 2>&1 || \
		(echo "Docker is not running — start Docker and retry"; exit 1)

.PHONY: ci ci-integration check-tidy generate-check \
        docker-build docker-push docker-build-all \
        dev _db-setup-if-needed \
        up up-infra down down-v logs ps \
        db-setup db-migrate db-seed db-reset db-shell \
        generate build build-svc \
        test test-svc test-shared test-short test-cover \
        vet lint lint-fix tidy \
        valkey-cli kafka-topics check-tools \
        demo demo-build demo-all demo-all-build jaeger \
        open open-grafana open-prometheus open-jaeger open-kafka-ui open-pgadmin _open-url \
        help check-docker

.DEFAULT_GOAL := help
