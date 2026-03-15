# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /app/bin/ti-sync \
    ./services/svc-11-ti-sync/cmd/ti-sync/main.go

# ── Runtime stage ───────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12

COPY --from=builder /app/bin/ti-sync /ti-sync

ENTRYPOINT ["/ti-sync"]
