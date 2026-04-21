#!/bin/sh
set -e

# DEMO ONLY ───────────────────────────────────────────────────────────────────
# Starts both the Python NLP inference service (FastAPI/ONNX) and the Go HTTP
# wrapper in a single container — the same pattern as svc-03-url-analysis.
# In production, these would run as separate microservices.
# ─────────────────────────────────────────────────────────────────────────────

NLP_PORT=${PORT:-8001}

echo "Starting Python NLP inference service on port ${NLP_PORT}..."
(cd /app/nlp && PORT=${NLP_PORT} python app.py) &

# Start the Go wrapper immediately — it serves the demo UI and API right away.
# While the ONNX model is still loading, /predict returns 503 (model_loading)
# and /healthz shows model_ready: false. The Docker healthcheck only checks
# that the Go process is listening on the HTTP port, so `docker compose --wait`
# completes quickly without blocking on model load time.
echo "Starting Go NLP wrapper..."
exec /bin/service
