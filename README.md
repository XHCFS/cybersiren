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
|   |-- svc-06-nlp/                  FastAPI service (DistilBERT + ONNX Runtime)
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
|   |-- decisions/DECISIONS.MD       architecture decision log
|   |-- screenshots/                 demo screenshots
|   `-- ...
|
`-- scripts/                         dev, CI, DB, and data utility scripts
```

---

## Quick Start (Demo)

Runs `svc-03-url-analysis` with Postgres, Valkey, Prometheus, Grafana, and Jaeger. No environment variables required.

```bash
docker compose -f deploy/compose/docker-compose.yml --profile demo up --build
```

Open http://localhost:8083 once the service prints `started port=8083`.

| Port | Service |
|------|---------|
| 8083 | URL scanner (web UI + JSON API) |
| 9092 | Prometheus |
| 3001 | Grafana (admin / admin) |
| 16686 | Jaeger traces |

---

## Development

```bash
make up                              # start infra (postgres, valkey, kafka)
make dev svc=svc-03-url-analysis     # run one service natively
make test-short                      # unit tests, no infra required
make test-svc svc=svc-03-url-analysis
make lint
make build
```

Config loads in priority order: defaults < `config.yaml` < environment variables (`CYBERSIREN_` prefix, `__` for nesting).

---

## Documentation

Full documentation is published at **https://xhcfs.github.io/cybersiren/**

| Reference | Location |
|-----------|----------|
| Architecture decisions | [docs/decisions/DECISIONS.MD](docs/decisions/DECISIONS.MD) |
| Demo walkthrough | [DEMO.md](DEMO.md) |
| URL analysis improvements | [docs/URL_ANALYSIS_IMPROVEMENTS.md](docs/URL_ANALYSIS_IMPROVEMENTS.md) |
| API reference | https://xhcfs.github.io/cybersiren/api |
| Runbooks | https://xhcfs.github.io/cybersiren/runbooks |
