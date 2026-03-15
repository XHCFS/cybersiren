# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum from repo root
COPY go.mod go.sum ./
RUN go mod download

# Copy full source tree (module root is repo root)
COPY . .

# Build the api binary from the service-local entrypoint
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /app/bin/api \
    ./services/svc-10-api-dashboard/cmd/api/main.go

# ── Runtime stage ───────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12

COPY --from=builder /app/bin/api /api

EXPOSE 8080

ENTRYPOINT ["/api"]
