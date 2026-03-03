# Quick commands

## Install packages (Arch Linux)
sudo pacman -S go postgresql docker
sudo systemctl enable --now docker
sudo usermod -aG docker $USER

## Install tools
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
go mod tidy

## Clean rerun (drop everything and start fresh)
docker stop cybersiren-db 2>/dev/null || true
docker rm cybersiren-db 2>/dev/null || true
docker run --name cybersiren-db -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=cybersiren -p 5432:5432 -d postgres:15
sleep 5
docker exec cybersiren-db pg_isready -U postgres

## Run migrations
export DB_URL="postgres://postgres:postgres@localhost:5432/cybersiren?sslmode=disable"
psql $DB_URL -f migrations/001_initial_schema.sql
psql $DB_URL -f migrations/002_add_users_orgs.sql
psql $DB_URL -f migrations/003_add_enrichments.sql
psql $DB_URL -f migrations/004_add_materialized_view.sql
psql $DB_URL -f migrations/005_fix_current_verdicts.sql

## Generate models
rm -rf internal/storage/db
sqlc generate

## Verify
psql $DB_URL -c "\dt" | head -20
go build ./internal/storage/db/...
