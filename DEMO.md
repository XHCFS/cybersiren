# CyberSiren — Demo Guides

This repository ships standalone, self-contained demo stacks for each implemented
service. Every demo requires only Docker + Docker Compose — no manual `.env` file
needed.

---

## Available Demos

| Service | What it demos | Guide |
|---------|--------------|-------|
| **svc-03-url-analysis** | URL phishing scanner — ML model (XGBoost) + Threat-Intelligence lookup | [DEMO-url.md](DEMO-url.md) |
| **svc-06-nlp** | Email content classifier — DistilBERT (ONNX) phishing / spam / legitimate | [DEMO-nlp.md](DEMO-nlp.md) |
| **Pipeline spine v0** | End-to-end Kafka pipeline smoke (10 stub services, fake email → verdict) | [demo-infra.md](demo-infra.md) |

---

## Quick Reference

### Run a single service demo

```bash
make demo svc=svc-03-url-analysis   # URL scanner
make demo svc=svc-06-nlp            # NLP email classifier
```

### Run all demos together

```bash
make demo-all                        # starts svc-03 + svc-06 + svc-11 + observability stack
```

### Rebuild after code changes

```bash
make demo-build svc=svc-03-url-analysis
make demo-build svc=svc-06-nlp
```

### Stop everything

```bash
make demo-stop-all
```

---

## Port Map

| Service | Web UI / API | Metrics |
|---------|-------------|---------|
| svc-03-url-analysis | http://localhost:8083 | http://localhost:9091/metrics |
| svc-06-nlp | http://localhost:8086 | http://localhost:9096/metrics |
| Prometheus | http://localhost:19090 | — |
| Grafana | http://localhost:3001 | — |
| Jaeger | http://localhost:16686 | — |

---

## Common Issues

| Symptom | Fix |
|---------|-----|
| `make: check-compose-env` fails | Copy `deploy/compose/.env.example` → `deploy/compose/.env` |
| Port already in use | `make demo-stop-all` then retry |
| First build is slow | Normal — Docker downloads Go + Python layers (~3–5 min). Subsequent starts are cached. |
| svc-06 returns 503 on first request | The DistilBERT ONNX model needs ~30 s to load. Wait for `model_ready: true` in logs. |
