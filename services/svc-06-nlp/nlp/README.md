# SVC-06 — NLP Email Classifier (Python inference service)

A FastAPI microservice that classifies an email's **text** into
`legitimate | spam | phishing` and returns a `content_risk_score` (0–100). Called
by the Go aggregator (SVC-07) over HTTP. Backbone: `distilbert-base-uncased`,
served as a faithful fp32 ONNX graph on CPU via ONNX Runtime.

Model spec: `docs/internals/CyberSiren_NLP_Email_Classification_Model_Specification.html`
(**NLP-SPEC-v2.0**). Service spec: `..._Service_Specification.html`.

## What v2 changed (vs the original v1 checkpoint)

v1 passed same-distribution test metrics but **did not generalize** — it scored
~0.8% on held-out real phishing (corpus-overfit) and classified by *register*
(tone/length), so `"hi"` was flagged "suspicious" while calm BEC sailed through.
v2 is rebuilt as a deployable generalizer:

- **Scoring:** `content_risk_score = round(P(phishing) · 100)`. **Spam is a
  distinct, non-threat class** — the v1 spam+phishing collapse is retired.
- **URLs/sender stripped** before tokenization — link reputation is SVC-03's job,
  sender is SVC-04's; combined at the aggregator. Forces the model to learn
  *language/intent*, not memorize URLs.
- **Adversarial canonicalization** in preprocessing (homoglyph / leetspeak /
  letter-spacing folding + zero-width strip) maps known attacks back to clean
  text at inference — no retrain needed for those.
- **Results (cycle-12):** macro-F1 0.979, phishing recall 0.978, legit FPR 1.18%,
  **held-out real-phishing recall 87.3%** (from 0.8%), 64-axis deployability gate
  fully PASS, adversarial/metamorphic battery 0 evasions, novel probe 0 FN / 0 FP.

## Files

| File | Purpose |
|------|---------|
| `app.py` | FastAPI app: `POST /predict`, `GET /healthz`, `GET /status`. |
| `inference.py` | `NLPInferenceEngine` — load ONNX/tokenizer/config, head-tail encode, score. |
| `text_preprocess.py` | **Canonical** preprocessing (URL strip, normalize, canonicalization). Imported by BOTH training and serving — single source of truth, no train/serve skew. |
| `config.json` | Thresholds (temperature, `phish_threshold`), label map, intent taxonomy. |
| `metrics.json` | Measured v2 metrics + full battery breakdown. |
| `onnx/` | The fp32 ONNX model (see `onnx/README.md`). |
| `tokenizer/` | HuggingFace DistilBert tokenizer files. |
| `test_inference.py` | Unit tests (no model/network needed) covering preprocessing, the adversarial defenses, head-tail truncation, scoring, and config. |

## Run

```bash
cd services/svc-06-nlp/nlp
pip install -r requirements.txt
git lfs pull          # ensure onnx/model_int8.onnx is the real model, not a pointer
python app.py         # serves on :8001 (PORT env to override)
```

```bash
# tests (fast, no model required)
pytest test_inference.py -q
```

## API

`POST /predict` → `{ classification, confidence, phishing_probability,
spam_probability, content_risk_score, intent_labels, urgency_score,
obfuscation_detected, top_tokens }`. The Go mirror is
`services/svc-06-nlp/internal/nlp/client.go`.

## Adversarial robustness as a standing check

Robustness is tested as an **invariant**, not a frozen list: a semantics-preserving
transform of a caught phish must not let it evade
(`services/svc-06-nlp/nlp/adversarial_robustness.py`, a single pass/fail command). Adding a
future attack class is one transform function. See model spec §11.3–11.4 for the
methodology and the text-only Pareto-frontier decision.
