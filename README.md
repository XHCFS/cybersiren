# CyberSiren

A commercial-grade phishing defense platform. Ingests raw emails, runs them through a multi-stage detection pipeline combining threat intelligence feeds, an XGBoost URL classifier, and a DistilBERT NLP model, then produces a structured verdict with confidence scores.

**Tech stack:** Go 1.25, Python 3.12, PostgreSQL 15, Valkey, Kafka, React

---

## Pipeline

Emails move through 11 services in sequence:

```
svc-01-ingestion
  svc-02-parser
    svc-03-url-analysis      TI blocklist + XGBoost (30 features)
    svc-04-header-analysis   SPF / DKIM / DMARC / routing hops
    svc-05-attachment-analysis
    svc-06-nlp               DistilBERT via FastAPI + ONNX Runtime
      svc-07-aggregator      combines all scores
        svc-08-decision      typosquatting + domain reputation
          svc-09-notification
            svc-10-api-dashboard

svc-11-ti-sync               runs independently, 6-hour cycle
```

---

## Repository Layout

```
cybersiren/
|
|-- services/                        Go microservices (one directory per service)
|   |-- svc-01-ingestion/
|   |-- svc-02-parser/
|   |-- svc-03-url-analysis/
|   |   |-- cmd/url-analysis/        service entry point
|   |   |-- internal/url/            Go feature extractor, model pool, TI checker
|   |   |-- ml/                      XGBoost model, inference script, config, training notebook
|   |   |   |-- data/top-1m.csv      Cisco Umbrella top-1M domain list
|   |   |   |-- model.joblib         trained champion model (1.1 MB)
|   |   |   |-- inference_script.py  Python subprocess: feature extraction + prediction
|   |   |   `-- config.json          feature names, thresholds, lookup tables
|   |   `-- static/                  demo web UI
|   |-- svc-04-header-analysis/
|   |-- svc-05-attachment-analysis/
|   |-- svc-06-nlp/
|   |   |-- cmd/nlp/                 Go service entry point
|   |   |-- internal/nlp/            Go HTTP client wrapping the Python inference service
|   |   |-- nlp/                     Python FastAPI service (DistilBERT + ONNX Runtime)
|   |   `-- static/                  demo web UI
|   |-- svc-07-aggregator/
|   |-- svc-08-decision/
|   |-- svc-09-notification/
|   |-- svc-10-api-dashboard/
|   `-- svc-11-ti-sync/
|
|-- shared/                          Go packages imported by all services
|   |-- auth/                        JWT + API key authentication
|   |-- config/                      Koanf-based config (YAML + env vars)
|   |-- http/                        Gin server abstraction, Resty HTTP client
|   |-- kafka/                       Kafka producer/consumer wrappers
|   |-- logger/                      zerolog wrapper with context enrichment
|   |-- models/                      core data types: Email, URL, Verdict, Enrichment
|   |-- normalization/               URL normalisation
|   |-- observability/               OpenTelemetry tracing + Prometheus metrics
|   |-- postgres/                    PGX connection pool, 5 repository interfaces
|   |-- queue/                       Redis queue wrapper
|   |-- testkit/                     test utilities
|   `-- valkey/                      Valkey client + TI domain cache
|
|-- python/
|   `-- url-ml/                      URL model training code and experiments
|
|-- db/
|   |-- migrations/                  25 SQL migration files
|   |-- queries/                     sqlc input queries
|   |-- seeds/                       seed data (demo TI indicators)
|   |-- sqlc/                        generated Go database code
|   `-- views/                       5 materialized views (TI, campaign, feed health)
|
|-- deploy/
|   |-- compose/                     Docker Compose stack (demo profile)
|   |   |-- grafana/                 auto-provisioned dashboards
|   |   `-- prometheus/              scrape config
|   |-- docker/                      Dockerfiles (one per service)
|   `-- k8s/                         Kubernetes manifests
|
|-- docs/
|   |-- architecture/                full architecture spec (HTML, source of truth)
|   |-- screenshots/                 demo screenshots
|   `-- ...
|
`-- scripts/                         dev, CI, DB, and data utility scripts
```

---

## Quick Start (Demo)

Runs any service with Postgres, Valkey, Prometheus, Grafana, and Jaeger.

```bash
cp deploy/compose/.env.example deploy/compose/.env  # one-time Docker Compose setup
make demo svc=svc-03-url-analysis   # URL scanner with full observability
make demo svc=svc-06-nlp            # NLP email classifier with full observability
make demo svc=svc-11-ti-sync        # threat-intel sync with full observability
make demo-all                       # demo service bundle (svc-03 + svc-06 + svc-11)
```

Images are cached after the first run — startup is instant. Force a rebuild after code changes:

```bash
make demo-build svc=svc-11-ti-sync  # rebuild + start single service
make demo-all-build                  # rebuild + start demo service bundle
```

**svc-03 and svc-06 have demo web UIs:**

| Service | URL | What it does |
|---------|-----|-------------|
| svc-03-url-analysis | http://localhost:8083 | URL scanner — paste any URL to classify it |
| svc-06-nlp | http://localhost:8086 | NLP email classifier — paste an email to classify it |

Other services have no web UI — use Grafana, Prometheus, and Jaeger below.

| Port | Service |
|------|---------|
| 8083 | URL scanner (web UI + JSON API) |
| 8086 | NLP email classifier (web UI + JSON API) |
| 19090 | Prometheus |
| 3001 | Grafana (admin / admin) |
| 16686 | Jaeger traces |

---

## Development

```bash
make up                              # start infra (postgres, valkey, kafka, jaeger)
make dev svc=svc-03-url-analysis     # run one service natively
make test-short                      # unit tests, no infra required
make test-svc svc=svc-03-url-analysis
make lint
make build
```

Config loads in priority order: defaults < `config.yaml` < environment variables (`CYBERSIREN_` prefix, `__` for nesting).

---

## Observability

Every Go service exposes Prometheus metrics on its `METRICS_PORT` and optionally sends traces to Jaeger via OTLP. The shared package `shared/observability/metrics` provides a reusable metrics HTTP server, and `shared/observability/tracing` handles trace export.

### Docker Compose profiles

Observability infrastructure is split into composable profiles:

| Profile | What it starts |
|---------|---------------|
| `monitoring` | Prometheus + Grafana (with auto-provisioned dashboards) |
| `observability` | Jaeger (OTLP collector + UI) |
| `svc-03` | svc-03-url-analysis container |
| `svc-06` | svc-06-nlp container |
| `svc-11` | svc-11-ti-sync container |

Combine profiles as needed, or use `make demo` which activates all of them:

```bash
make demo svc=svc-11-ti-sync
```

### UIs

| URL | Service | Credentials |
|-----|---------|-------------|
| http://localhost:3001 | Grafana | admin / admin |
| http://localhost:19090 | Prometheus | — |
| http://localhost:16686 | Jaeger | — |

### Makefile targets

```bash
make demo svc=<name>         # start service + full observability stack (cached)
make demo-build svc=<name>   # same but force-rebuilds image first
make demo-all                # start svc-03 + svc-06 + svc-11 + full observability stack (cached)
make demo-all-build          # same but force-rebuilds svc-03 + svc-06 + svc-11 images first
make jaeger              # start Jaeger standalone
make open-grafana        # open Grafana in browser
make open-prometheus     # open Prometheus in browser
make open-jaeger         # open Jaeger in browser
```

### Adding observability to a new service

See [docs/adding-observability.md](docs/adding-observability.md) for a step-by-step guide.

---

## Documentation

Full documentation is published at **https://xhcfs.github.io/cybersiren/**

| Reference | Location |
|-----------|----------|
| Architecture spec (source of truth) | [docs/architecture/architecture-spec-detail.html](docs/architecture/architecture-spec-detail.html) — §16 Changelog records implementation deltas |
| Demo guides index | [DEMO.md](DEMO.md) — URL scanner · NLP classifier · pipeline spine |
| Pipeline spine v0 smoke test | [demo-infra.md](demo-infra.md) |
| URL analysis improvements | [docs/URL_ANALYSIS_IMPROVEMENTS.md](docs/URL_ANALYSIS_IMPROVEMENTS.md) |
| API reference | https://xhcfs.github.io/cybersiren/api |
| Runbooks | https://xhcfs.github.io/cybersiren/runbooks |
