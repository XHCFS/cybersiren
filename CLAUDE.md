# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CyberSiren is a phishing defense platform using a microservices monorepo architecture. The detection pipeline combines threat intelligence (TI) feeds, ML models, and NLP to score and classify phishing emails.

**Tech stack:** Go 1.25 (backend services), Python (ML/NLP), React (dashboard), PostgreSQL + Redis

## Common Commands

```bash
# Development
make dev-api          # Run API server
make dev-worker       # Run aggregator/worker
make dev-ti-sync      # Run TI sync service
make web-dev          # Run React dashboard (npm run dev)

# Build
make build            # Build all Go binaries
make docker-build     # Build Docker images
make docker-up        # Start all services

# Testing
make test             # All tests with coverage (outputs coverage.html)
make test-short       # Short tests only

# Code quality
make lint             # golangci-lint (5min timeout)
make lint-fix         # Lint with auto-fix
make fmt              # gofmt
make vet              # go vet

# Database
make migrate-up       # Run migrations
make migrate-down     # Rollback last migration
make migrate-create NAME=create_table  # New migration
make seed-ti          # Seed TI database

# ML
make ml-install       # Install Python ML dependencies
make ml-train-url     # Train URL detection model
make ml-train-nlp     # Train NLP model

# Setup
make setup            # Full dev setup (deps + migrations + seed)
make install-tools    # Install golangci-lint, migrate
```

## Architecture

### Service Pipeline

Emails flow through 11 services in sequence:

```
Email Input → svc-01-ingestion → svc-02-parser →
  ├─ svc-03-url-analysis   [TI feeds + LightGBM ML]
  ├─ svc-04-header-analysis
  ├─ svc-05-attachment-analysis
  └─ svc-06-nlp            [DistilBERT via FastAPI]
    → svc-07-aggregator    [combines scores, orchestrates]
      → svc-08-decision    [typosquatting + domain reputation]
        → svc-09-notification
          → svc-10-api-dashboard
```

`svc-11-ti-sync` runs independently on a 6-hour cycle to sync threat intelligence feeds.

### Directory Layout

```
services/svc-XX-*/     # Go microservices
python/svc-06-nlp/     # NLP FastAPI service (DistilBERT + ONNX)
python/url-ml/         # URL model training code
web/svc-10-dashboard/  # React dashboard
shared/                # Go packages shared across all services
db/                    # Migrations, SQL queries, sqlc-generated code
deploy/                # Docker, docker-compose, Kubernetes
```

### Shared Packages (`shared/`)

All services import from these shared packages:

| Package | Purpose |
|---------|---------|
| `shared/config/` | Koanf-based config (YAML + env vars) |
| `shared/http/` | Gin server abstraction + HTTP client (Resty v3) |
| `shared/logger/` | zerolog wrapper with context enrichment |
| `shared/models/` | Core data types (Email, URL, Verdict, Enrichment) |
| `shared/postgres/` | PGX connection pool + 5 repository interfaces |
| `shared/queue/` | Redis queue wrapper |
| `shared/auth/` | JWT + API key authentication |
| `shared/testkit/` | Test utilities |

### ML Model Integration

**URL Model (LightGBM):** Go spawns a Python subprocess per inference request.
- 28 features, JSON on stdin/stdout, 5-second timeout
- Process pool size configurable (default: 3)
- Model binary: `services/svc-03-url-analysis/internal/url/URL_MODEL/model.joblib`
- Fallback: default risk score of 50 on failure (never hard-fail)

**NLP Model (DistilBERT):** HTTP microservice (FastAPI + ONNX Runtime)
- Endpoint: `CYBERSIREN_ML__NLP_SERVICE_URL` (default: `http://localhost:8001`)
- 10-second timeout

### Configuration

Config loads in this priority order (last wins):
1. Hard-coded defaults
2. `config.yaml` (path via `CYBERSIREN_CONFIG_PATH`)
3. Environment variables (`CYBERSIREN_` prefix, `__` for nesting)

**Required fields (validation enforced):** `db.name`, `db.user`, `db.password`, `auth.jwt_secret`

See `.env.example` for all available variables.

### Database

- PostgreSQL 15+ with pgvector extension
- 25 migration files in `db/migrations/`
- Code generation via sqlc (`sqlc.yaml` → `db/sqlc/`)
- 5 materialized views refreshed concurrently after TI sync: `mv_threat_summary`, `mv_campaign_summary`, `mv_feed_health`, `mv_rule_performance`, `mv_org_ingestion_summary`
- `emails` table is partitioned monthly by `fetched_at`

### HTTP Conventions

- **Success:** `{"success": true, "data": {...}}`
- **Error:** `{"success": false, "error": {"status", "code", "message", "details"}}`

## Key Architectural Decisions

See `DECISIONS.MD` for the full decision log. Critical decisions:

- **LightGBM chosen over XGBoost** for URL model (0.99645 MCC, 1,582 μs latency, 0.8 MB size)
- **Go feature extraction must match Python within 0.001 tolerance** (verified at train time)
- **Max 5 concurrent enrichments** to avoid WHOIS API rate limiting
- **Default risk score 50** on ML failure — system fails gracefully, never hard-fails
- **Campaign fingerprinting** uses deterministic SHA256 + SimHash for near-duplicate detection
- **TI sync** runs every 6 hours; 5-minute stale data is acceptable

## Development Status

Most shared infrastructure is implemented. Service `main.go` files and pipeline orchestration are partially implemented (stubs/TODOs exist). The ML model and training code are complete. CI/CD workflows and Docker Compose config are placeholders.

**Team:**
- ASER [TI]: Threat intel feeds + URL enrichment
- SAIF [LEAD]: Database, ML models, API, orchestration
- OMAR [NLP]: Email content analysis
