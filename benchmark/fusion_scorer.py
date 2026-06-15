"""
CyberSiren fusion scorer (learned late-fusion meta-learner).

Combines the per-channel risk scores (NLP content-risk, URL risk, Header risk)
into a single phishing probability, using the trained gradient-boosted
meta-learner instead of SVC-08's weighted-average blend.

WHY a meta-learner: a weighted average cannot catch both text-only phishing and
header-only phishing (proven impossible — the weights would have to contradict),
and it amplifies an over-flagging channel. The benchmark bake-off:

    weighted-average (current)   recall@1%FPR 63%   PR-AUC 0.775
    learned meta-learner (HGB)   recall@1%FPR 99%   PR-AUC 0.988

STATUS: SHADOW / ADVISORY. The shipped artifact was trained on the CS-E2E-Bench
stress benchmark (synthetic stress + real corporate anchor), with a lexical-only
URL channel and a header proxy. It must be RETRAINED on a real full-email
multi-channel corpus before it is allowed to gate production verdicts. Until then,
run it alongside the existing path and compare; do not let it override.

SAFE FALLBACK: if the artifact is missing, or no channel beyond NLP is present,
this returns the NLP content-risk score directly — never the weighted-average
(which the benchmark showed is dominated by NLP-alone anyway).
"""
from __future__ import annotations
import os
import numpy as np

_ART_PATH = os.path.join(os.path.dirname(__file__), "artifacts", "fusion_meta_v1.joblib")
_FEATURES = ["nlp", "url", "header", "has_url", "has_header", "n_high"]

_artifact = None
def _load():
    global _artifact
    if _artifact is None:
        try:
            import joblib
            _artifact = joblib.load(_ART_PATH)
        except Exception:
            _artifact = {}  # missing -> fallback mode
    return _artifact


def fuse(nlp_score: float, url_score: float | None = None,
         header_score: float | None = None) -> dict:
    """
    Inputs are 0-100 per-channel risk scores; None = channel absent.
      nlp_score    : SVC-06 content_risk_score (required).
      url_score    : SVC-03 risk (full-stack: lexical + operational + allowlist).
      header_score : SVC-04 header risk.

    Returns {fused_risk (0-100), phishing (bool), source, p_phish}.
    """
    art = _load()
    nlp_score = float(nlp_score)
    present = [s for s in (nlp_score, url_score, header_score) if s is not None]

    # FLOOR GUARD: if no channel sees anything suspicious, it's benign. Prevents the
    # meta-learner from hallucinating risk on rare all-low feature combinations it
    # under-saw in the benchmark (a known shadow-mode calibration gap).
    if max(present) < 25:
        return {"fused_risk": round(nlp_score), "phishing": False,
                "p_phish": nlp_score / 100, "source": "floor_benign"}

    # SAFE FALLBACK: no model, or NLP is the only signal -> trust NLP directly.
    if not art or (url_score is None and header_score is None):
        return {"fused_risk": round(nlp_score), "phishing": nlp_score > 50,
                "p_phish": nlp_score / 100, "source": "nlp_fallback"}

    n_high = (int(nlp_score > 50)
              + int(url_score is not None and url_score > 50)
              + int(header_score is not None and header_score > 50))
    x = np.array([[nlp_score,
                   np.nan if url_score is None else float(url_score),
                   np.nan if header_score is None else float(header_score),
                   0.0 if url_score is None else 1.0,
                   0.0 if header_score is None else 1.0,
                   float(n_high)]])
    p = float(art["model"].predict_proba(x)[0, 1])
    thr = art.get("operating_threshold", 0.5)
    return {"fused_risk": round(p * 100), "phishing": p > thr,
            "p_phish": p, "source": art.get("version", "fusion_meta")}


if __name__ == "__main__":
    # behaviour demo (the patterns the weighted-average gets wrong)
    cases = [
        ("text-only phish (nlp high, header clean)", dict(nlp_score=95, header_score=0)),
        ("header-only phish (text clean, From spoofed)", dict(nlp_score=5, header_score=85)),
        ("URL high ALONE (uncorroborated, noisy)", dict(nlp_score=0, url_score=95, header_score=0)),
        ("URL high + header spoofed (corroborated)", dict(nlp_score=0, url_score=95, header_score=80)),
        ("all clean", dict(nlp_score=3, url_score=2, header_score=0)),
        ("NLP only, no other channel (fallback)", dict(nlp_score=88)),
    ]
    for name, kw in cases:
        r = fuse(**kw)
        print(f"  {name:46} fused={r['fused_risk']:>3}  phishing={r['phishing']!s:5}  ({r['source']})")
