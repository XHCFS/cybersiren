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
import threading
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
# Tracks the engine while it is still loading (same object once assigned).
_loading_engine: NLPInferenceEngine | None = None


def _load_engine_background() -> None:
    """Run in a daemon thread so FastAPI starts serving immediately."""
    global engine, _loading_engine
    try:
        e = NLPInferenceEngine()
        _loading_engine = e
        engine = e
        if engine.model_ready:
            logger.info("NLP service ready — model loaded")
        else:
            logger.warning(
                "NLP service started WITHOUT a model. "
                "POST /predict will return 503 until onnx/model_int8.onnx is present. "
                "Run `git lfs pull` (LFS source: python/svc-06-nlp/onnx/) or `make check-nlp-model`."
            )
    except Exception as exc:
        logger.error("Background engine load failed: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _loading_engine
    # Create a placeholder so /status can report progress from the start.
    _loading_engine = NLPInferenceEngine.__new__(NLPInferenceEngine)
    _loading_engine.model_ready = False
    _loading_engine.loading_stage = "starting"
    _loading_engine.loading_progress_pct = 0

    t = threading.Thread(target=_load_engine_background, daemon=True)
    t.start()
    logger.info("NLP engine loading in background thread — service ready on :%s", os.environ.get("CYBERSIREN_SERVER__PORT", "8086"))
    yield


app = FastAPI(
    title="CyberSiren NLP Service",
    description=(
        "SVC-06 — email text classifier (legitimate / spam / phishing). "
        "Backbone: distilbert-base-uncased (fp32 ONNX). Spec: NLP-SPEC-v2.0 "
        "(cycle-12, generalization-hardened). "
        "Scoring (v3): content_risk_score = round((1 - P(legitimate)) * 100) = "
        "overall maliciousness (spam + phishing). Spam / advance-fee scams ARE "
        "threats and contribute to the risk; the 3-class label still "
        "distinguishes phishing vs spam vs legitimate. "
        "URLs are stripped before tokenization — their reputation is scored "
        "separately by SVC-03 and combined at the aggregator."
    ),
    version="2.0.0",
    lifespan=lifespan,
)


# ── Request / response models (spec §8.3) ─────────────────────────────────

class PredictRequest(BaseModel):
    subject: str
    body_plain: str
    body_html: str = ""
    # Plumbed from the Kafka AnalysisText contract. Optional/defaulted so older
    # callers (subject/body/html only) keep working. Used by the heuristic
    # brand-impersonation facet to compare the claimed brand against the sender.
    sender_domain: str = ""
    sender_name: str = ""


class TokenScore(BaseModel):
    token: str
    score: float


class PredictResponse(BaseModel):
    classification: str          # "phishing" | "spam" | "legitimate"
    confidence: float            # 0.0 – 1.0
    phishing_probability: float  # 0.0 – 1.0  P(phishing) alone
    spam_probability: float      # 0.0 – 1.0  P(spam); now counts toward risk
    content_risk_score: int      # 0 – 100  = round((1 - P(legit)) * 100); feeds emails.content_risk_score
    intent_labels: list[str]     # e.g. ["credential_harvest", "urgency_threat"]
    urgency_score: float         # 0.0 – 1.0
    obfuscation_detected: bool
    # Heuristic facets (P4.2). impersonation_score is high when the email claims
    # a known brand the sender domain does not belong to; impersonated_brand is
    # the matched brand token (None when no brand claimed). deception_score is a
    # weighted linguistic phishing-cue score.
    impersonation_score: float        # 0.0 – 1.0
    impersonated_brand: str | None = None
    deception_score: float            # 0.0 – 1.0
    top_tokens: list[TokenScore] # always [] in production (LIME is offline)


# ── Endpoints ──────────────────────────────────────────────────────────────

@app.get("/healthz")
def health():
    if engine is None or not engine.model_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="NLP model is not loaded.",
        )
    return {
        "status": "ok",
        "model_ready": True,
    }


@app.get("/status")
def status_endpoint():
    """Always returns 200. Exposes loading progress for the demo UI."""
    ref = _loading_engine
    if ref is None:
        return {"model_ready": False, "loading_stage": "starting", "loading_progress_pct": 0}
    return {
        "model_ready": ref.model_ready,
        "loading_stage": ref.loading_stage,
        "loading_progress_pct": ref.loading_progress_pct,
    }


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    if engine is None or not engine.model_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "NLP model is not loaded. "
                "Fetch it with `git lfs pull` (LFS source: python/svc-06-nlp/onnx/) "
                "or `make check-nlp-model`, then restart."
            ),
        )
    try:
        result = engine.predict(
            req.subject,
            req.body_plain,
            req.body_html,
            sender_domain=req.sender_domain,
            sender_name=req.sender_name,
        )
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
