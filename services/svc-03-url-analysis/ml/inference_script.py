#!/usr/bin/env python3
"""
CyberSiren — URL Inference Subprocess (svc-03)

Subprocess stdin/stdout protocol for Go process pool.

Protocol (one JSON object per line, newline-delimited):
  stdin:  {"features": [f1, f2, ..., f28]}
  stdout: {"score": <int 0-100>, "probability": <float>, "label": "phishing"|"legitimate"}
  stderr: error/diagnostic messages

Exit codes:
  0 — normal shutdown (stdin closed / EOF)
  1 — fatal startup error (model not found / load failure)

Model loading:
  1. MODEL_PATH env var (path to model.joblib)
  2. <script_dir>/model.joblib (default relative path)
"""

import json
import os
import sys

import joblib
import numpy as np


def _resolve_model_path() -> str:
    env_path = os.environ.get("MODEL_PATH")
    if env_path:
        return env_path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, "model.joblib")


def main() -> None:
    model_path = _resolve_model_path()

    if not os.path.isfile(model_path):
        print(f"ERROR: model not found at {model_path}", file=sys.stderr, flush=True)
        sys.exit(1)

    try:
        model = joblib.load(model_path)
    except Exception as exc:
        print(f"ERROR: failed to load model: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)

    print(f"INFO: model loaded from {model_path}", file=sys.stderr, flush=True)

    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue

        try:
            req = json.loads(raw_line)
            features = req["features"]
            if not isinstance(features, list) or len(features) != 28:
                raise ValueError(
                    f"expected 28 features, got {len(features) if isinstance(features, list) else type(features).__name__}"
                )
            X = np.array([features], dtype=np.float64)
            prob = float(model.predict_proba(X)[0, 1])
            score = round(prob * 100)
            label = "phishing" if prob >= 0.5 else "legitimate"
            resp: dict = {"score": score, "probability": prob, "label": label}
        except Exception as exc:
            print(f"ERROR: inference failed: {exc}", file=sys.stderr, flush=True)
            resp = {"score": 50, "probability": 0.5, "label": "unknown", "error": str(exc)}

        print(json.dumps(resp), flush=True)


if __name__ == "__main__":
    main()
