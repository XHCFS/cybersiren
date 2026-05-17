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
    mode: Literal["max", "mean", "op_only"] = "op_only",
    shortener_mask: np.ndarray | None = None,
) -> np.ndarray:
    """
    Fuse URL-model and operational-model probabilities.

    Default mode is ``"op_only"``:

    - ``"op_only"``: deploy_p = op_p. url_p drives zero weight in the verdict.
      If op_p is None (enrichment did not run at all), returns zeros — fail
      open, every URL scores 0.0 = benign. url_p and shortener_mask are
      ignored entirely in this mode.

    The ``"op_only"`` default is correct because url_p (structural LightGBM)
    scores deep legitimate OAuth and login URLs at ≥ 0.9 — path-entropy,
    path-depth, and sensitive-word features fire on any login flow regardless
    of domain legitimacy. url_p is a routing gate, not a verdict signal.

    Legacy modes (kept for backwards-compatibility):

    - ``"mean"``: asymmetric weighting — normal range (op_p ≥ 0.05): 50%/50%
      arithmetic mean; confident-benign range (op_p < 0.05): 15% url_p +
      85% op_p. Shortener mask shifts weight to 10%/90%.
    - ``"max"``: max(url_p, op_p) — more aggressive, higher FPR.

    ``shortener_mask``: boolean array marking URLs whose apex domain is a
    known URL shortener (bit.ly, t.co, tinyurl.com, etc.).  Only used in
    ``"mean"`` mode. The production pipeline resolves redirects before
    scoring, so this mask is only needed for offline/unit-test scoring where
    redirects are not followed.
    """
    if mode == "op_only":
        if op_p is None:
            return np.zeros_like(url_p)
        return op_p
    if op_p is None:
        return url_p
    if mode == "max":
        result = np.maximum(url_p, op_p)
    else:
        mean = 0.5 * (url_p + op_p)
        dampened = 0.15 * url_p + 0.85 * op_p
        result = np.where(op_p < 0.05, dampened, mean)
    if shortener_mask is not None and op_p is not None:
        shortener_score = 0.1 * url_p + 0.9 * op_p
        result = np.where(shortener_mask, shortener_score, result)
    return result
