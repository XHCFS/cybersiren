"""
Structural URL feature extractor and scorer.

Replaces url_char_lr as the URL-side model. Instead of character n-grams,
extracts 33 structural features (path depth, entropy, subdomain count,
TLD legitimacy probability, Levenshtein distance to top-500 brands, etc.)
and runs them through a calibrated LightGBM classifier.

Key advantage over url_char_lr: brand names appear in both legitimate and
phishing URLs, so character n-gram models assign high phishing probability
to "google.com" and "amazon.com". Structural features don't have this bias —
a short root domain with high TLD legitimacy probability and Levenshtein
distance of 0 to a known brand scores correctly benign.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import numpy as np
import tldextract as tldx
import Levenshtein as lev_lib

SENSITIVE_WORDS = [
    # Generic phishing vocabulary — no brand names here.
    # Brand names cause false positives on the real brand's legitimate URLs.
    "secure", "account", "webscr", "ebayisapi", "banking",
    "confirm", "update", "verify", "password", "suspend",
    "authenticate", "wallet", "credential",
]

SUSPICIOUS_EXTENSIONS = frozenset({
    ".exe", ".zip", ".rar", ".scr", ".bat", ".cmd", ".msi", ".dll",
    ".vbs", ".js", ".jar", ".ps1", ".wsf", ".lnk", ".7z", ".cab",
})

_SHORTENER_DOMAINS = frozenset({
    "bit.ly", "t.co", "tinyurl.com", "lnkd.in", "rb.gy",
    "tiny.cc", "is.gd", "ow.ly", "buff.ly", "cutt.ly",
})

_REPEATED_DIGITS_RE = re.compile(r"(\d)\1{2,}")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)


def _char_continuation_rate(url: str) -> float:
    if not url:
        return 0.0
    max_alpha = max_digit = max_special = 0
    cur_alpha = cur_digit = cur_special = 0
    for c in url:
        if c.isalpha():
            cur_alpha += 1; max_alpha = max(max_alpha, cur_alpha)
            cur_digit = cur_special = 0
        elif c.isdigit():
            cur_digit += 1; max_digit = max(max_digit, cur_digit)
            cur_alpha = cur_special = 0
        else:
            cur_special += 1; max_special = max(max_special, cur_special)
            cur_alpha = cur_digit = 0
    return (max_alpha + max_digit + max_special) / len(url)


def extract_features(
    url: str,
    tld_prob: dict[str, float],
    full_domain_set: set[str],
    brand_names: list[str],
) -> dict[str, float]:
    """Extract 33 structural features from a URL string."""
    url_str = url.strip()
    try:
        parsed = urlparse(url_str if "://" in url_str else f"http://{url_str}")
    except Exception:
        return {k: 0.0 for k in _FEATURE_ORDER}

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    scheme = (parsed.scheme or "").lower()

    try:
        ext = tldx.extract(url_str)
        tld = ext.suffix.lower() if ext.suffix else ""
        domain = ext.domain.lower() if ext.domain else ""
        subdomain = ext.subdomain.lower() if ext.subdomain else ""
    except Exception:
        tld = domain = subdomain = ""

    subdomain_parts = [p for p in subdomain.split(".") if p] if subdomain else []
    url_lower = url_str.lower()

    f: dict[str, float] = {}
    f["url_length"] = float(len(url_str))
    f["num_dots"] = float(url_str.count("."))
    f["num_subdomains"] = float(len(subdomain_parts))
    f["has_ip_address"] = 1.0 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0.0
    f["num_hyphens_url"] = float(url_str.count("-"))
    f["num_hyphens_hostname"] = float(hostname.count("-"))
    f["https_flag"] = 1.0 if scheme == "https" else 0.0
    f["entropy_url"] = _entropy(url_str)
    f["num_numeric_chars"] = float(sum(c.isdigit() for c in url_str))
    f["num_sensitive_words"] = float(sum(url_lower.count(w) for w in SENSITIVE_WORDS))
    f["hostname_length"] = float(len(hostname))
    f["path_length"] = float(len(path))
    f["entropy_domain"] = _entropy(domain)
    f["num_query_params"] = float(len(query.split("&"))) if query else 0.0
    f["num_special_chars"] = float(sum(1 for c in url_str if c in "!@#$%^&*~`|\\<>{}"))
    f["at_symbol_present"] = 1.0 if "@" in url_str else 0.0
    f["pct_numeric_chars"] = float(sum(c.isdigit() for c in url_str)) / max(len(url_str), 1)
    f["suspicious_file_ext"] = 1.0 if any(path.lower().endswith(e) for e in SUSPICIOUS_EXTENSIONS) else 0.0
    f["path_depth"] = float(max(path.count("/") - 1, 0))
    f["num_underscores"] = float(url_str.count("_"))
    f["double_slash_in_path"] = 1.0 if "//" in path else 0.0
    f["query_length"] = float(len(query))
    f["has_fragment"] = 1.0 if fragment else 0.0
    f["has_repeated_digits"] = 1.0 if _REPEATED_DIGITS_RE.search(url_str) else 0.0
    f["avg_subdomain_length"] = (
        sum(len(p) for p in subdomain_parts) / len(subdomain_parts)
    ) if subdomain_parts else 0.0
    f["tld_length"] = float(len(tld))
    tokens = re.split(r"[/\?\&\=\-\_\.\:\@\#\+\~\%]", url_str)
    f["token_count"] = float(len([t for t in tokens if t]))
    f["tld_legit_prob"] = tld_prob.get(tld, 0.0)
    f["char_continuation_rate"] = _char_continuation_rate(url_str)

    hostname_bare = hostname[4:] if hostname.startswith("www.") else hostname
    reg_domain = f"{domain}.{tld}".lower() if domain and tld else ""

    if hostname_bare in full_domain_set or hostname in full_domain_set or reg_domain in full_domain_set:
        f["min_brand_levenshtein"] = 0.0
    elif domain and len(domain) >= 2 and brand_names:
        f["min_brand_levenshtein"] = float(
            min(lev_lib.distance(domain, b) for b in brand_names)
        )
    else:
        f["min_brand_levenshtein"] = 99.0

    f["registered_domain_top1m"] = 1.0 if reg_domain and reg_domain in full_domain_set else 0.0
    f["is_shortener_domain"] = 1.0 if hostname in _SHORTENER_DOMAINS else 0.0
    is_local = hostname in {"localhost", "127.0.0.1", "::1"}
    is_private = bool(re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)", hostname))
    f["is_local_or_private_host"] = 1.0 if (is_local or is_private) else 0.0

    return f


# Canonical feature order — must match training column order
_FEATURE_ORDER: tuple[str, ...] = (
    "url_length", "num_dots", "num_subdomains", "has_ip_address",
    "num_hyphens_url", "num_hyphens_hostname", "https_flag", "entropy_url",
    "num_numeric_chars", "num_sensitive_words", "hostname_length", "path_length",
    "entropy_domain", "num_query_params", "num_special_chars", "at_symbol_present",
    "pct_numeric_chars", "suspicious_file_ext", "path_depth", "num_underscores",
    "double_slash_in_path", "query_length", "has_fragment", "has_repeated_digits",
    "avg_subdomain_length", "tld_length", "token_count", "tld_legit_prob",
    "char_continuation_rate", "min_brand_levenshtein", "registered_domain_top1m",
    "is_shortener_domain", "is_local_or_private_host",
)


import pandas as pd


class StructuralScorer:
    """Drop-in replacement for score_url_hash using the LightGBM structural model."""

    def __init__(self, bundle: dict[str, Any]) -> None:
        self._model = bundle["model"]
        self._feature_names: list[str] = list(bundle["feature_names"])
        self._tld_prob: dict[str, float] = bundle["tld_prob"]
        self._full_domain_set: set[str] = bundle["full_domain_set"]
        self._brand_names: list[str] = bundle["brand_names"]

    def score(self, urls: list[str]) -> np.ndarray:
        """Return phishing probability array, shape (len(urls),)."""
        rows = [
            extract_features(u, self._tld_prob, self._full_domain_set, self._brand_names)
            for u in urls
        ]
        X = pd.DataFrame(rows).reindex(columns=self._feature_names, fill_value=0.0)
        return self._model.predict_proba(X)[:, 1]


def load_structural_scorer(path: Path) -> StructuralScorer:
    import joblib
    bundle = joblib.load(path)
    return StructuralScorer(bundle)
