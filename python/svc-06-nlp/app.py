"""
CyberSiren SVC-06 NLP Analysis Service
=======================================
FastAPI wrapper around NLPInferenceEngine.

Spec §8.3 endpoint:
    POST /predict
    GET  /healthz

Default port: 8001 (CYBERSIREN_ML__NLP_SERVICE_URL = http://localhost:8001)
Called by SVC-07 aggregator with a 10-second timeout (shared/config/config.go).
"""

import logging
import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

from inference import NLPInferenceEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

engine: NLPInferenceEngine | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine
    logger.info("Loading NLP inference engine …")
    engine = NLPInferenceEngine()
    if engine.model_ready:
        logger.info("NLP service ready — model loaded")
    else:
        logger.warning(
            "NLP service started WITHOUT a model. "
            "POST /predict will return 503 until onnx/model_int8.onnx is replaced "
            "with the real model from cybersiren_nlp_out/onnx/model_int8.onnx."
        )
    yield


app = FastAPI(
    title="CyberSiren NLP Service",
    description=(
        "SVC-06 — Phishing / Spam / Legitimate email text classifier. "
        "Backbone: distilbert-base-uncased (INT8 ONNX). Spec: NLP-SPEC-v1.0."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ── Request / response models (spec §8.3) ─────────────────────────────────

class PredictRequest(BaseModel):
    subject: str
    body_plain: str
    body_html: str = ""


class TokenScore(BaseModel):
    token: str
    score: float


class PredictResponse(BaseModel):
    classification: str          # "phishing" | "spam" | "legitimate"
    confidence: float            # 0.0 – 1.0
    phishing_probability: float  # 0.0 – 1.0
    spam_probability: float      # 0.0 – 1.0
    content_risk_score: int      # 0 – 100  (feeds emails.content_risk_score)
    intent_labels: list[str]     # e.g. ["credential_harvest", "urgency_threat"]
    urgency_score: float         # 0.0 – 1.0
    obfuscation_detected: bool
    top_tokens: list[TokenScore] # always [] in production (LIME is offline)


# ── Endpoints ──────────────────────────────────────────────────────────────

@app.get("/healthz")
def health():
    return {
        "status": "ok",
        "model_ready": engine.model_ready if engine is not None else False,
    }


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    if engine is None or not engine.model_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "NLP model is not loaded. "
                "Place onnx/model_int8.onnx (from cybersiren_nlp_out/onnx/) "
                "in the service directory and restart."
            ),
        )
    try:
        result = engine.predict(req.subject, req.body_plain, req.body_html)
        return result
    except Exception:
        logger.exception("Inference error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Inference failed — see service logs.",
        )


# ── Entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8001))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
