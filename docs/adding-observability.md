# Adding Observability to a CyberSiren Service

## Overview

Every CyberSiren service ships with three observability pillars:

| Tool | Purpose | Port/URL |
|------|---------|----------|
| **Prometheus** | Metrics (counters, histograms, gauges) | `:9090/metrics` inside container |
| **Grafana** | Dashboards | `http://localhost:3001` |
| **Jaeger** | Distributed tracing (OpenTelemetry) | `http://localhost:16686` |
| **zerolog** | Structured JSON logging | stderr |

The shared packages in `shared/observability/` handle all boilerplate. You just need to make three calls in `main.go` and register your custom metrics.

---

## Step 1: Go Code

### 1a. Wire up metrics + tracing in `main.go`

Add the three key calls after config and logger setup. Here's the pattern from `svc-11-ti-sync`:

```go
import (
    "github.com/saif/cybersiren/shared/observability/metrics"
    "github.com/saif/cybersiren/shared/observability/tracing"
)

func main() {
    // ... config.Load(), logger setup, signal context ...

    // ① Tracing — noop when CYBERSIREN_JAEGER_ENDPOINT is empty.
    tracerShutdown, err := tracing.Init(ctx, "svc-XX-myservice", cfg.JaegerEndpoint)
    if err != nil {
        log.Fatal().Err(err).Msg("failed to initialize tracing")
        return
    }
    defer func() {
        shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        if shutdownErr := tracerShutdown(shutdownCtx); shutdownErr != nil {
            log.Error().Err(shutdownErr).Msg("tracer shutdown error")
        }
    }()

    // ② Metrics registry — registers Go runtime + process collectors.
    reg := metrics.Init("svc-XX-myservice")

    // ③ Metrics HTTP server — serves /metrics and /healthz.
    metricsShutdown := metrics.StartServer(cfg.MetricsPort, reg, log)
    defer func() { _ = metricsShutdown(context.Background()) }()

    // Pass `reg` to any struct that registers custom metrics.
    // ...
}
```

**What these do:**
- `tracing.Init()` — sets up an OTLP HTTP exporter to Jaeger. If the endpoint is empty, it installs a noop tracer so `otel.Tracer()` calls are safe everywhere.
- `metrics.Init()` — creates a new `*prometheus.Registry` with Go runtime and process collectors pre-registered.
- `metrics.StartServer()` — starts a background HTTP server exposing `/metrics` (Prometheus scrape endpoint) and `/healthz` (liveness probe). Returns a shutdown function.

### 1b. Add custom metrics

Register custom Prometheus metrics wherever your business logic lives. Accept the `*prometheus.Registry` from `main.go`:

```go
package mypackage

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/saif/cybersiren/shared/observability/tracing"
)

var myTracer = tracing.Tracer("services/svc-XX-myservice/internal/mypackage")

type Worker struct {
    reqTotal    prometheus.Counter
    reqDuration prometheus.Histogram
}

func NewWorker(reg *prometheus.Registry) *Worker {
    reqTotal := prometheus.NewCounter(prometheus.CounterOpts{
        Name: "myservice_requests_total",
        Help: "Total processed requests.",
    })
    reg.MustRegister(reqTotal)

    reqDuration := prometheus.NewHistogram(prometheus.HistogramOpts{
        Name:    "myservice_request_duration_seconds",
        Help:    "Request processing duration in seconds.",
        Buckets: prometheus.DefBuckets,
    })
    reg.MustRegister(reqDuration)

    return &Worker{reqTotal: reqTotal, reqDuration: reqDuration}
}
```

**Metric naming convention:** `<domain>_<noun>_<unit>` — e.g., `feed_sync_duration_seconds`, `feed_sync_errors_total`.

### 1c. Add trace spans

Use `otel.Tracer()` (or the `tracing.Tracer()` helper) to create spans:

```go
func (w *Worker) Process(ctx context.Context) error {
    ctx, span := myTracer.Start(ctx, "worker.Process")
    defer span.End()

    // Add attributes to the span.
    span.SetAttributes(attribute.String("item_id", id))

    if err := doWork(ctx); err != nil {
        span.RecordError(err)
        span.SetStatus(codes.Error, err.Error())
        return fmt.Errorf("processing item %s: %w", id, err)
    }

    return nil
}
```

### 1d. Structured logging

Use the shared logger — it's already configured in `main.go`. Attach context fields as needed:

```go
log := logger.New(cfg.Log.Level, cfg.Log.Pretty)
logger.SetGlobal(log)

// In request handlers, enrich context:
ctx = logger.WithRequestID(ctx, requestID)
ctx = logger.WithEmailID(ctx, emailID)
```

---

## Step 2: Docker Compose

Add your service to `deploy/compose/docker-compose.yml`. Follow the existing pattern:

```yaml
  # ── svc-XX-myservice ──────────────────────────────────────────────────
  svc-XX-myservice:
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile.myservice
    profiles: ["svc-XX"]                          # ← profile = svc-{number}
    depends_on:
      demo-seed:
        condition: service_completed_successfully
      valkey:
        condition: service_healthy
    ports:
      - "909X:9090"                               # ← unique host port, container always 9090
    environment:
      CYBERSIREN_ENV: development
      CYBERSIREN_LOG__LEVEL: debug
      CYBERSIREN_LOG__PRETTY: "true"
      CYBERSIREN_DB__HOST: postgres
      CYBERSIREN_DB__PORT: "5432"
      CYBERSIREN_DB__NAME: cybersiren
      CYBERSIREN_DB__USER: ${POSTGRES_USER:-postgres}
      CYBERSIREN_DB__PASSWORD: ${POSTGRES_PASSWORD:-postgres}
      CYBERSIREN_DB__SSL_MODE: disable
      CYBERSIREN_VALKEY__ADDR: valkey:6379
      CYBERSIREN_METRICS_PORT: "9090"
      CYBERSIREN_JAEGER_ENDPOINT: http://jaeger:4318
    networks:
      - cybersiren
    restart: unless-stopped
```

**Key points:**
- **Profile name** is the short form: `svc-XX` (e.g., `svc-03`, `svc-11`). The Makefile derives this automatically from the full service name.
- **Metrics port** is always `9090` inside the container. Map it to a unique host port (`909X`) to avoid conflicts.
- **Jaeger endpoint** points to the `jaeger` container on OTLP HTTP port `4318`.
- Add your profile to the `demo-seed` container's profiles list so seed data runs when your service starts:
  ```yaml
  demo-seed:
    profiles: ["demo", "svc-03", "svc-11", "svc-XX"]  # ← add yours
  ```

---

## Step 3: Prometheus Scrape Config

Add a scrape target in `deploy/compose/prometheus/prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "cybersiren-services"
    scrape_timeout: 5s
    static_configs:
      - targets: ["svc-03-url-analysis:9090"]
        labels:
          service: "svc-03-url-analysis"
      - targets: ["svc-11-ti-sync:9090"]
        labels:
          service: "svc-11-ti-sync"
      # ↓ Add your service here
      - targets: ["svc-XX-myservice:9090"]
        labels:
          service: "svc-XX-myservice"
```

The `service` label is used in Grafana queries to filter panels to your service (e.g., `{service="svc-XX-myservice"}`). Services that aren't running show as `down` in Prometheus — this is expected and harmless.

---

## Step 4: Grafana Dashboard

Create a JSON dashboard at `deploy/compose/grafana/dashboards/svc-XX-myservice.json`. Grafana auto-provisions all files in this directory (configured in `deploy/compose/grafana/provisioning/dashboards/dashboards.yml`).

### Dashboard structure

Use the existing `svc-11-ti-sync.json` as a template. Key fields:

```json
{
  "panels": [
    {
      "title": "My Metric — Rate",
      "type": "timeseries",
      "gridPos": { "h": 8, "w": 12, "x": 0, "y": 0 },
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "fieldConfig": {
        "defaults": { "unit": "ops" }
      },
      "targets": [
        {
          "expr": "rate(myservice_requests_total{service=\"svc-XX-myservice\"}[5m])",
          "legendFormat": "req/s",
          "refId": "A"
        }
      ]
    }
  ],
  "schemaVersion": 39,
  "tags": ["cybersiren", "svc-XX"],
  "title": "svc-XX My Service",
  "uid": "cybersiren-svcXX",
  "version": 1
}
```

### Common panel patterns

| Pattern | PromQL |
|---------|--------|
| Counter rate | `rate(metric_total{service="..."}[5m])` |
| Histogram p50/p95/p99 | `histogram_quantile(0.95, rate(metric_bucket{service="..."}[5m]))` |
| Goroutines | `go_goroutines{service="..."}` |
| Memory (MiB) | `go_memstats_alloc_bytes{service="..."} / 1024 / 1024` |
| Open FDs | `process_open_fds{service="..."}` |

**Always include** Go runtime panels (goroutines, memory, open FDs) — they come free from the registry and are useful for debugging. See `svc-11-ti-sync.json` for the full template.

### Important details

- **`datasource.uid`** must be `"prometheus"` — this matches the auto-provisioned datasource in `deploy/compose/grafana/provisioning/datasources/prometheus.yml`.
- **`uid`** must be unique across all dashboards (e.g., `"cybersiren-svcXX"`).
- **`service` label** in every PromQL query — this is how you scope metrics to your service.

---

## Step 5: Makefile

No changes needed. The `make demo` target uses a profile-derivation function that extracts `svc-XX` from the full service name automatically:

```bash
make demo svc=svc-XX-myservice
```

This starts: Postgres, Valkey, Prometheus, Grafana, Jaeger, and your service container. After startup, it prints:

```
  Service:     svc-XX-myservice
  Grafana:     http://localhost:3001
  Prometheus:  http://localhost:9092
  Jaeger:      http://localhost:16686
```

---

## Checklist

Files to create or modify when adding observability to a new service:

- [ ] **`services/svc-XX-name/cmd/.../main.go`** — add `tracing.Init()`, `metrics.Init()`, `metrics.StartServer()`
- [ ] **`services/svc-XX-name/internal/...`** — register custom metrics on the shared `*prometheus.Registry`; create trace spans
- [ ] **`deploy/compose/docker-compose.yml`** — add service block with `svc-XX` profile, expose metrics port, set `CYBERSIREN_JAEGER_ENDPOINT`
- [ ] **`deploy/compose/docker-compose.yml`** — add `svc-XX` to `demo-seed` profiles list
- [ ] **`deploy/compose/prometheus/prometheus.yml`** — add scrape target with `service` label
- [ ] **`deploy/compose/grafana/dashboards/svc-XX-name.json`** — create dashboard JSON (copy `svc-11-ti-sync.json` as a starting point)
- [ ] **Verify** — `make demo svc=svc-XX-name`, then check Grafana, Prometheus targets, and Jaeger traces

### Environment variables reference

| Variable | Purpose | Default |
|----------|---------|---------|
| `CYBERSIREN_METRICS_PORT` | Port for `/metrics` + `/healthz` | (none — must set) |
| `CYBERSIREN_JAEGER_ENDPOINT` | OTLP HTTP endpoint (e.g., `http://jaeger:4318`) | empty = tracing disabled |
| `CYBERSIREN_LOG__LEVEL` | Log level (`debug`, `info`, `warn`, `error`) | `info` |
| `CYBERSIREN_LOG__PRETTY` | Human-readable console logs | `false` |
