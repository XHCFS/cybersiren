"""Load models, preprocess HGB inputs, and fuse URL + operational probabilities."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import joblib
import numpy as np
import pandas as pd


def _string_col_cardinality(s: pd.Series) -> int:
    return int(s.astype(str).nunique(dropna=False))


def prepare_X_for_hgb(
    X: pd.DataFrame,
    *,
    ref_cardinality: dict[str, int] | None,
    max_categories: int,
) -> tuple[pd.DataFrame, dict[str, int]]:
    """
    HistGradientBoostingClassifier allows at most 255 levels per categorical column.
    Low-cardinality strings → pandas ``category``; high-cardinality → deterministic
    hash buckets as float (same string always maps to the same bucket).
    """
    X = X.copy()
    if ref_cardinality is None:
        ref_cardinality = {}
        for c in X.columns:
            if pd.api.types.is_object_dtype(X[c]) or pd.api.types.is_string_dtype(X[c]):
                ref_cardinality[c] = _string_col_cardinality(X[c])

    for c, nuniq in ref_cardinality.items():
        if c not in X.columns:
            continue
        if nuniq <= max_categories:
            X[c] = X[c].astype(str).astype("category")
        else:
            h = pd.util.hash_pandas_object(X[c].astype(str), index=False).astype(np.int64)
            X[c] = (np.abs(h) % 4096).astype(np.float64)
    return X, ref_cardinality


def score_url_hash(bundle: dict[str, Any], urls: list[str]) -> np.ndarray:
    pipe = bundle["pipeline"]
    arr = np.array([u.lower() for u in urls])
    return pipe.predict_proba(arr)[:, 1]


def load_operational_bundle(path: Path) -> tuple[Any, list[str], dict[str, int], int]:
    b = joblib.load(path)
    clf = b["model"]
    cols = list(clf.feature_names_in_)
    return clf, cols, b["ref_cardinality"], int(b["max_categories"])


def score_operational(
    clf: Any,
    cols: list[str],
    ref_card: dict[str, int],
    max_cat: int,
    rows: list[dict[str, Any]],
) -> np.ndarray:
    X = pd.DataFrame(rows)
    for c in cols:
        if c not in X.columns:
            X[c] = np.nan
    X = X[cols]
    Xp, _ = prepare_X_for_hgb(X, ref_cardinality=ref_card, max_categories=max_cat)
    return clf.predict_proba(Xp)[:, 1]


def fusion(
    url_p: np.ndarray,
    op_p: np.ndarray | None,
    *,
    mode: Literal["max", "mean"] = "mean",
    shortener_mask: np.ndarray | None = None,
) -> np.ndarray:
    """
    Fuse URL-model and operational-model probabilities.

    Default mode is ``"mean"`` with asymmetric weighting across three ranges:

    - CDN-phishing range (op_p < 0.01): 60% url_p + 40% op_p.
      Catches phishing hosted on clean cloud / CDN infrastructure where the
      domain barely resolves.  The Go domain guard already allowlists all
      top-10K domains, so this range only sees genuinely unknown domains.

    - Established-domain range (url_p > 0.95 AND 0.01 ≤ op_p < 0.10):
      40% url_p + 60% op_p.
      When the char model is extremely confident (url_p > 0.95) but the
      operational model gives a moderate benign signal (op_p 1–10%), the
      URL has phishing-like path keywords (login/verify/account) on a domain
      that is established but not in the top-10K.  This is a false-positive
      hotspot for legitimate small-business banking and portal sites.  Giving
      op_p 60% weight reduces those FPs while preserving recall for phishing
      where op_p is truly near zero (CDN range above).

    - Normal range (everything else with op_p ≥ 0.01): 50% url_p + 50% op_p.

    Use ``"max"`` only when you want either model's high score to dominate
    regardless of the other (more aggressive, higher FPR).

    ``shortener_mask``: boolean array marking URLs whose apex domain is a
    known URL shortener (bit.ly, t.co, tinyurl.com, etc.).  For these the
    URL char model scores the opaque code, not the redirect destination.
    Fusion weight shifts to 10% url_p + 90% op_p.  The production pipeline
    resolves redirects before scoring, so this mask is only needed for
    offline/unit-test scoring where redirects are not followed.
    """
    if op_p is None:
        return url_p
    if mode == "max":
        result = np.maximum(url_p, op_p)
    else:
        mean = 0.5 * url_p + 0.5 * op_p          # normal range
        dampened = 0.60 * url_p + 0.40 * op_p    # CDN-phishing range
        conservative = 0.40 * url_p + 0.60 * op_p  # established-domain range
        in_cdn = op_p < 0.01
        in_est = (url_p > 0.95) & ~in_cdn & (op_p < 0.10)
        result = np.where(in_cdn, dampened, mean)
        result = np.where(in_est, conservative, result)
    if shortener_mask is not None and op_p is not None:
        shortener_score = 0.1 * url_p + 0.9 * op_p
        result = np.where(shortener_mask, shortener_score, result)
    return result
