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

echo "Starting Go NLP wrapper..."
exec /bin/service
