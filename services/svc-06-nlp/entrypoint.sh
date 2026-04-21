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

# Wait for the Python service to be fully ready (model loaded) before starting
# the Go wrapper. This ensures the container becomes healthy immediately after
# Go starts, rather than relying on the Docker healthcheck start_period window.
echo "Waiting for Python NLP service to be ready..."
i=0
while [ $i -lt 120 ]; do
    response=$(python3 -c "
import urllib.request, json, sys
try:
    resp = urllib.request.urlopen('http://127.0.0.1:${NLP_PORT}/healthz', timeout=3)
    body = json.loads(resp.read())
    print('ok' if body.get('model_ready') else 'loading')
except Exception as e:
    print('waiting')
" 2>/dev/null)
    if [ "$response" = "ok" ]; then
        echo "Python NLP service ready."
        break
    fi
    echo "  model not ready yet (${response}), retrying in 5s... [${i}/120]"
    sleep 5
    i=$((i + 5))
done

if [ "$response" != "ok" ]; then
    echo "WARNING: Python NLP service did not become ready within 600s — starting Go wrapper anyway."
fi

echo "Starting Go NLP wrapper..."
exec /bin/service
