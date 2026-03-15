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
	go build -o $(API_BINARY) services/svc-10-api-dashboard/cmd/api/main.go
	go build -o $(WORKER_BINARY) services/svc-07-aggregator/cmd/aggregator/main.go
	go build -o $(TI_SYNC_BINARY) services/svc-11-ti-sync/cmd/ti-sync/main.go
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
	docker build -f services/svc-10-api-dashboard/Dockerfile -t phishguard-api:latest .
	docker build -f services/svc-07-aggregator/Dockerfile -t phishguard-worker:latest .
	docker build -f services/svc-11-ti-sync/Dockerfile -t phishguard-ti-sync:latest .
	docker build -f web/svc-10-dashboard/Dockerfile -t phishguard-web:latest ./web/svc-10-dashboard

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
	./scripts/db/setup_db.sh

migrate-down: ## Rollback last database migration
	migrate -path db/migrations -database "${DB_URL}" down 1

migrate-create: ## Create a new migration file (usage: make migrate-create NAME=create_users_table)
	@if [ -z "$(NAME)" ]; then echo "Error: NAME is required. Usage: make migrate-create NAME=create_users_table"; exit 1; fi
	migrate create -ext sql -dir db/migrations -seq $(NAME)

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
	go run services/svc-10-api-dashboard/cmd/api/main.go

dev-worker: ## Run worker in development mode
	@echo "Starting worker (aggregator)..."
	go run services/svc-07-aggregator/cmd/aggregator/main.go

dev-ti-sync: ## Run TI sync service in development mode
	@echo "Starting TI sync service..."
	go run services/svc-11-ti-sync/cmd/ti-sync/main.go

seed-ti: ## Seed TI database with initial data
	@echo "Seeding TI database..."
	./scripts/db/seed_ti.sh

web-install: ## Install web dashboard dependencies
	@echo "Installing web dependencies..."
	cd web/svc-10-dashboard && npm install

web-dev: ## Run web dashboard in development mode
	@echo "Starting web development server..."
	cd web/svc-10-dashboard && npm run dev

web-build: ## Build web dashboard for production
	@echo "Building web dashboard..."
	cd web/svc-10-dashboard && npm run build

ml-install: ## Install Python ML dependencies
	@echo "Installing ML dependencies..."
	pip install -r python/url-ml/requirements.txt
	pip install -r python/svc-06-nlp/requirements.txt

ml-train-url: ## Train URL detection model
	@echo "Training URL model..."
	cd python/url-ml && python train.py

ml-train-nlp: ## Train NLP model
	@echo "Training NLP model..."
	cd python/svc-06-nlp && python train.py

all: deps build test lint ## Run deps, build, test, and lint

setup: install-tools deps migrate-up seed-ti ## Complete development setup

.DEFAULT_GOAL := help
