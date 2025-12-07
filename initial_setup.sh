#!/bin/bash

# PhishGuard Project Structure Setup Script
# This script creates the complete directory structure for the PhishGuard phishing detection platform

set -e  # Exit on any error

echo "[INFO] Setting up PhishGuard project structure..."

# Root level files
echo "[INFO] Creating root level files..."
touch go.sum
touch Makefile
touch .env.example

if [ ! -f .gitignore ]; then
    touch .gitignore
fi

if [ ! -f .golangci.yml ]; then
    touch .golangci.yml
fi

# cmd/ - Service entry points
echo "[INFO] Creating cmd/ directory structure..."
mkdir -p cmd/api
mkdir -p cmd/worker
mkdir -p cmd/ti_sync

touch cmd/api/main.go
touch cmd/worker/main.go
touch cmd/ti_sync/main.go

# internal/ - Private application code
echo "[INFO] Creating internal/ directory structure..."

# API layer
mkdir -p internal/api/handlers
mkdir -p internal/api/middleware

touch internal/api/handlers/auth.go
touch internal/api/handlers/scans.go
touch internal/api/handlers/api_keys.go
touch internal/api/handlers/stats.go
touch internal/api/middleware/auth.go
touch internal/api/middleware/rate_limit.go
touch internal/api/middleware/logger.go
touch internal/api/middleware/cors.go
touch internal/api/routes.go

# Email processing
mkdir -p internal/email
touch internal/email/parser.go
touch internal/email/sanitizer.go

# Detection modules
mkdir -p internal/detection/url
mkdir -p internal/detection/nlp
mkdir -p internal/detection/domain

touch internal/detection/url/ti_checker.go
touch internal/detection/url/enricher.go
touch internal/detection/url/feature_extractor.go
touch internal/detection/url/model.go
touch internal/detection/url/README.md

touch internal/detection/nlp/preprocessor.go
touch internal/detection/nlp/classifier.go
touch internal/detection/nlp/README.md

touch internal/detection/domain/typosquatting.go
touch internal/detection/domain/reputation.go
touch internal/detection/domain/README.md

touch internal/detection/aggregator.go
touch internal/detection/README.md

# Threat Intelligence
mkdir -p internal/ti
touch internal/ti/feeds.go
touch internal/ti/sync.go
touch internal/ti/README.md

# Storage layer
mkdir -p internal/storage/repository
touch internal/storage/postgres.go
touch internal/storage/repository/email_repo.go
touch internal/storage/repository/url_repo.go
touch internal/storage/repository/ti_repo.go
touch internal/storage/repository/enrichment_repo.go
touch internal/storage/repository/user_repo.go
touch internal/storage/repository/README.md

# Worker
mkdir -p internal/worker
touch internal/worker/jobs.go
touch internal/worker/orchestrator.go
touch internal/worker/README.md

# pkg/ - Public libraries
echo "[INFO] Creating pkg/ directory structure..."
mkdir -p pkg/config
mkdir -p pkg/logger
mkdir -p pkg/queue
mkdir -p pkg/httputil
mkdir -p pkg/models

touch pkg/config/config.go
touch pkg/logger/logger.go
touch pkg/queue/redis.go
touch pkg/httputil/response.go
touch pkg/httputil/request.go
touch pkg/models/email.go
touch pkg/models/url.go
touch pkg/models/verdict.go
touch pkg/models/user.go

# ml/ - Machine learning (Python)
echo "[INFO] Creating ml/ directory structure..."
mkdir -p ml/url_model
mkdir -p ml/nlp_model
mkdir -p ml/datasets

touch ml/url_model/train.py
touch ml/url_model/feature_engineering.py
touch ml/url_model/inference.py
touch ml/url_model/requirements.txt
touch ml/url_model/README.md

touch ml/nlp_model/train.py
touch ml/nlp_model/inference.py
touch ml/nlp_model/app.py
touch ml/nlp_model/requirements.txt
touch ml/nlp_model/README.md

touch ml/datasets/README.md

# web/ - Dashboard frontend
echo "[INFO] Creating web/ directory structure..."
mkdir -p web/public
mkdir -p web/src/components
mkdir -p web/src/services
mkdir -p web/src/context

touch web/public/index.html
touch web/src/components/LoginForm.jsx
touch web/src/components/ScanForm.jsx
touch web/src/components/ScanList.jsx
touch web/src/components/ScanDetail.jsx
touch web/src/components/APIKeyManager.jsx
touch web/src/components/Dashboard.jsx
touch web/src/services/api.js
touch web/src/context/AuthContext.jsx
touch web/src/App.jsx
touch web/src/index.jsx
touch web/src/index.css
touch web/package.json
touch web/vite.config.js
touch web/README.md

# migrations/ - Database migrations
echo "[INFO] Creating migrations/ directory structure..."
mkdir -p migrations

touch migrations/001_initial_schema.sql
touch migrations/002_add_users_orgs.sql
touch migrations/003_add_enrichments.sql
touch migrations/004_add_materialized_view.sql
touch migrations/README.md

# deploy/ - Deployment configurations (update existing)
echo "[INFO] Updating deploy/ directory structure..."
touch deploy/Dockerfile.api
touch deploy/Dockerfile.worker
touch deploy/Dockerfile.ti_sync
touch deploy/Dockerfile.web
touch deploy/README.md

# scripts/ - Utility scripts (update existing)
echo "[INFO] Updating scripts/ directory structure..."
touch scripts/setup_db.sh
touch scripts/seed_ti.sh
touch scripts/enrich_ti_for_training.py
touch scripts/generate_api_key.sh
touch scripts/README.md

# Make scripts executable
chmod +x scripts/*.sh 2>/dev/null || true
chmod +x scripts/*.py 2>/dev/null || true

# docs/ - Documentation (update existing)
echo "[INFO] Updating docs/ directory structure..."
touch docs/api_spec.md
touch docs/database_schema.md
touch docs/deployment_guide.md
touch docs/development_guide.md

if [ ! -d "docs/architecture" ]; then
    mkdir -p docs/architecture
fi
touch docs/architecture.md

# testdata/ - Test fixtures (update existing)
echo "[INFO] Updating testdata/ directory structure..."
mkdir -p testdata/sample_emails
mkdir -p testdata/sample_responses

touch testdata/sample_emails/legitimate_1.eml
touch testdata/sample_emails/phishing_1.eml
touch testdata/sample_emails/phishing_2.eml

# .github/ - CI/CD
echo "[INFO] Creating .github/ directory structure..."
mkdir -p .github/workflows

touch .github/workflows/ci.yml
touch .github/workflows/deploy.yml

# Create or update .gitignore
echo "[INFO] Creating .gitignore..."
cat > .gitignore << 'EOF'
# Binaries
*.exe
*.exe~
*.dll
*.so
*.dylib
cmd/api/api
cmd/worker/worker
cmd/ti_sync/ti_sync
bin/

# Test binary, built with `go test -c`
*.test

# Output of the go coverage tool
*.out
coverage.html

# Go workspace file
go.work

# Dependencies
vendor/

# Environment variables
.env
*.env
!.env.example

# IDE
.idea/
.vscode/
*.swp
*.swo
*~
.project
.classpath
.settings/

# OS
.DS_Store
Thumbs.db
desktop.ini

# ML models (too large for git)
*.pkl
*.h5
*.pt
*.pth
*.onnx
ml/nlp_model/model/
ml/url_model/model.pkl
ml/datasets/*.csv
ml/datasets/*.json
!ml/datasets/README.md

# Logs
*.log
logs/

# Database
*.db
*.sqlite
*.sqlite3
postgres-data/

# Node modules
node_modules/
web/dist/
web/build/
.cache/

# Docker
*.pid
docker-data/

# Temporary files
tmp/
temp/
EOF

# Create .env.example
echo "[INFO] Creating .env.example..."
cat > .env.example << 'EOF'
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=phishguard
DB_PASSWORD=your_secure_password_here
DB_NAME=phishguard
DB_SSLMODE=disable
DB_MAX_CONNECTIONS=25
DB_MAX_IDLE_CONNECTIONS=5

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# API Server Configuration
API_PORT=8080
API_HOST=0.0.0.0
JWT_SECRET=your_jwt_secret_minimum_32_characters
JWT_EXPIRY=24h
API_RATE_LIMIT=100
API_RATE_LIMIT_WINDOW=1m

# TI Feeds Configuration
PHISHTANK_API_KEY=your_phishtank_api_key
OPENPHISH_URL=https://openphish.com/feed.txt
URLHAUS_API_URL=https://urlhaus-api.abuse.ch/v1/
TI_SYNC_INTERVAL=6h
TI_SYNC_BATCH_SIZE=1000

# ML Models Configuration
URL_MODEL_PATH=./ml/url_model/model.pkl
URL_MODEL_PYTHON_PATH=/usr/bin/python3
NLP_MODEL_URL=http://localhost:5000/predict
NLP_MODEL_TIMEOUT=5s

# Enrichment Configuration
ENRICHMENT_SSL_TIMEOUT=10s
ENRICHMENT_WHOIS_TIMEOUT=5s
ENRICHMENT_REDIRECT_MAX_DEPTH=5
ENRICHMENT_CACHE_TTL=24h

# Logging Configuration
LOG_LEVEL=info
LOG_FORMAT=json
LOG_OUTPUT=stdout

# Application Environment
ENVIRONMENT=development
APP_NAME=PhishGuard
APP_VERSION=1.0.0

# Worker Configuration
WORKER_CONCURRENCY=10
WORKER_QUEUE_NAME=phishguard:scans
WORKER_MAX_RETRIES=3

# CORS Configuration
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
CORS_ALLOWED_METHODS=GET,POST,PUT,DELETE,OPTIONS
CORS_ALLOWED_HEADERS=Content-Type,Authorization
EOF

# Create Makefile
echo "[INFO] Creating Makefile..."
cat > Makefile << 'EOF'
.PHONY: help build test lint docker-build docker-up docker-down migrate clean dev-api dev-worker dev-ti-sync install-tools

# Variables
BINARY_DIR=bin
API_BINARY=$(BINARY_DIR)/api
WORKER_BINARY=$(BINARY_DIR)/worker
TI_SYNC_BINARY=$(BINARY_DIR)/ti_sync

help: ## Display this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install-tools: ## Install development tools
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest

build: ## Build all binaries
	@echo "Building binaries..."
	@mkdir -p $(BINARY_DIR)
	go build -o $(API_BINARY) cmd/api/main.go
	go build -o $(WORKER_BINARY) cmd/worker/main.go
	go build -o $(TI_SYNC_BINARY) cmd/ti_sync/main.go
	@echo "Build complete: binaries in $(BINARY_DIR)/"

test: ## Run all tests
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-short: ## Run short tests only
	go test -short -v ./...

lint: ## Run linter
	@echo "Running linter..."
	golangci-lint run --timeout=5m

lint-fix: ## Run linter with auto-fix
	golangci-lint run --fix --timeout=5m

fmt: ## Format code
	@echo "Formatting code..."
	go fmt ./...
	gofmt -s -w .

vet: ## Run go vet
	go vet ./...

docker-build: ## Build all Docker images
	@echo "Building Docker images..."
	docker build -f deploy/Dockerfile.api -t phishguard-api:latest .
	docker build -f deploy/Dockerfile.worker -t phishguard-worker:latest .
	docker build -f deploy/Dockerfile.ti_sync -t phishguard-ti-sync:latest .
	docker build -f deploy/Dockerfile.web -t phishguard-web:latest ./web

docker-up: ## Start all services with docker-compose
	@echo "Starting Docker services..."
	docker-compose -f deploy/docker-compose.yml up -d
	@echo "Services started. Check logs with: make docker-logs"

docker-down: ## Stop all Docker services
	@echo "Stopping Docker services..."
	docker-compose -f deploy/docker-compose.yml down

docker-logs: ## Show Docker service logs
	docker-compose -f deploy/docker-compose.yml logs -f

docker-clean: ## Remove all Docker containers, volumes, and images
	docker-compose -f deploy/docker-compose.yml down -v
	docker rmi phishguard-api phishguard-worker phishguard-ti-sync phishguard-web || true

migrate-up: ## Run database migrations up
	@echo "Running database migrations..."
	./scripts/setup_db.sh

migrate-down: ## Rollback last database migration
	migrate -path migrations -database "${DB_URL}" down 1

migrate-create: ## Create a new migration file (usage: make migrate-create NAME=create_users_table)
	@if [ -z "$(NAME)" ]; then echo "Error: NAME is required. Usage: make migrate-create NAME=create_users_table"; exit 1; fi
	migrate create -ext sql -dir migrations -seq $(NAME)

clean: ## Clean build artifacts and temporary files
	@echo "Cleaning build artifacts..."
	rm -rf $(BINARY_DIR)
	rm -f *.log
	rm -f coverage.out coverage.html
	find . -type f -name '*.test' -delete

deps: ## Download and tidy dependencies
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy
	go mod verify

dev-api: ## Run API server in development mode
	@echo "Starting API server..."
	go run cmd/api/main.go

dev-worker: ## Run worker in development mode
	@echo "Starting worker..."
	go run cmd/worker/main.go

dev-ti-sync: ## Run TI sync service in development mode
	@echo "Starting TI sync service..."
	go run cmd/ti_sync/main.go

seed-ti: ## Seed TI database with initial data
	@echo "Seeding TI database..."
	./scripts/seed_ti.sh

web-install: ## Install web dashboard dependencies
	@echo "Installing web dependencies..."
	cd web && npm install

web-dev: ## Run web dashboard in development mode
	@echo "Starting web development server..."
	cd web && npm run dev

web-build: ## Build web dashboard for production
	@echo "Building web dashboard..."
	cd web && npm run build

ml-install: ## Install Python ML dependencies
	@echo "Installing ML dependencies..."
	pip install -r ml/url_model/requirements.txt
	pip install -r ml/nlp_model/requirements.txt

ml-train-url: ## Train URL detection model
	@echo "Training URL model..."
	cd ml/url_model && python train.py

ml-train-nlp: ## Train NLP model
	@echo "Training NLP model..."
	cd ml/nlp_model && python train.py

all: deps build test lint ## Run deps, build, test, and lint

setup: install-tools deps migrate-up seed-ti ## Complete development setup

.DEFAULT_GOAL := help
EOF

echo "[INFO] Project structure setup complete."
echo ""
echo "Next steps:"
echo "  1. Review .env.example and create your .env file"
echo "  2. Initialize or verify Go module with: go mod tidy"
echo "  3. Install development tools: make install-tools"
echo "  4. Run complete setup: make setup"
echo "  5. Review documentation in docs/ directory"
echo ""
echo "Available commands:"
echo "  make help       - Show all available commands"
echo "  make build      - Build all binaries"
echo "  make test       - Run tests"
echo "  make docker-up  - Start all services"
echo ""
echo "Project structure created successfully."
