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

    - CDN-phishing range (op_p < 0.01): 65% url_p + 35% op_p.
      Catches phishing hosted on truly clean cloud / CDN infrastructure
      (op_p near zero).  url_p dominates because the operational model has
      no signal to contribute.  The Go domain guard allowlists top-10K domains
      before the sidecar is reached, so this zone only sees genuinely unknown
      low-reputation domains.

    - Normal range (0.01 ≤ op_p ≤ 0.60): 60% url_p + 40% op_p.
      url_p carries a moderate advantage because the char n-gram model is
      well-calibrated and phishing paths (login/verify/account/mfa) are
      strong lexical signals even on clean hosting infrastructure.

    - High-operational range (op_p > 0.60): 25% url_p + 75% op_p.
      When the operational model is highly confident (strong signals from
      DNS, WHOIS, TLS, content analysis, ASN), op_p dominates.  This
      catches phishing where the URL string is innocuous (numeric or
      brand-less domain names) but the infrastructure/content is clearly
      malicious.  Legitimate sites with clean infrastructure have op_p
      well below this threshold.

    Use ``"max"`` only when you want either model's high score to dominate
    regardless of the other (more aggressive, higher FPR).

    ``shortener_mask``: boolean array marking URLs whose apex domain is a
    known URL shortener (bit.ly, t.co, tinyurl.com, etc.).  For these the
    URL char model scores the opaque code, not the redirect destination.
    Fusion weight shifts to 10% url_p + 90% op_p.  Exception: when
    url_p > 0.95, the shortener domain itself is suspicious and the normal
    zone blend is kept.  The production pipeline resolves redirects before
    scoring, so this mask is only needed for offline/unit-test scoring where
    redirects are not followed.
    """
    if op_p is None:
        return url_p
    if mode == "max":
        result = np.maximum(url_p, op_p)
    else:
        in_cdn = op_p < 0.01
        in_high_op = op_p > 0.60
        cdn_blend = 0.65 * url_p + 0.35 * op_p    # CDN-phishing range
        high_op_blend = 0.25 * url_p + 0.75 * op_p  # high-operational range
        mean = 0.60 * url_p + 0.40 * op_p           # normal range
        result = np.where(in_cdn, cdn_blend, mean)
        result = np.where(in_high_op, high_op_blend, result)
    if shortener_mask is not None and op_p is not None:
        shortener_score = 0.1 * url_p + 0.9 * op_p
        # When the char model is highly confident even for an unresolved shortener
        # URL (url_p > 0.95), the shortener domain itself is suspicious — don't
        # suppress the url_p signal with the 10/90 blend; keep the zone blend.
        apply_shortener = shortener_mask & (url_p <= 0.95)
        result = np.where(apply_shortener, shortener_score, result)
    return result
