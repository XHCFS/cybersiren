"""Pickle-safe URL string preprocessing for the URL-hash (char n-gram) model."""
from __future__ import annotations

import numpy as np


def canonicalize_url_for_model(url: str) -> str:
    """Lowercase URLs and upgrade a leading ``http://`` to ``https://`` for stable char n-grams."""
    s = str(url).strip().replace("\r", "").lower()
    if s.startswith("http://"):
        return "https://" + s[7:]
    return s


def canonicalize_url_batch(X):
    """Sklearn ``FunctionTransformer`` callable: 1d array-like of URL strings → object ndarray."""
    ar = np.asarray(X, dtype=object).ravel()
    return np.array([canonicalize_url_for_model(u) for u in ar], dtype=object)
