#!/usr/bin/env python3
"""
CyberSiren — URL Inference Subprocess (svc-03)

Subprocess stdin/stdout protocol for Go process pool.

Protocol (one JSON object per line, newline-delimited):
  stdin (one of):
    {"url": "<raw-url-string>"}
    {"features": [<numeric-feature>, ...]}  # legacy precomputed-features request
  stdout: {"score": <int 0-100>, "probability": <float>, "label": "phishing"|"legitimate",
           "route_to_enrichment": <bool>, "route_reason": <string>}
  stderr: error/diagnostic messages

Label decision threshold:
  classification_threshold from config.json (default: 0.5 if absent)

Exit codes:
  0 — normal shutdown (stdin closed / EOF)
  1 — fatal startup error (model not found / load failure)

Model loading:
  1. MODEL_DIR env var (directory containing model.joblib + config.json)
  2. <script_dir>/ (default relative path)

Feature extraction is performed in Python using the same pipeline as
the Kaggle training notebook. This guarantees exact feature parity
with the model's training data — no Go↔Python drift.
"""

import json
import math
import os
import re
import sys
import warnings
from collections import Counter
from urllib.parse import urlparse

import joblib
import numpy as np

# Keep tldextract cache local to the model directory to avoid filesystem
# permission issues in restricted runtimes/tests.
if "TLDEXTRACT_CACHE" not in os.environ:
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    os.environ["TLDEXTRACT_CACHE"] = os.path.join(_script_dir, ".tldextract-cache")

# Suppress sklearn version mismatch warnings (model trained on slightly
# different sklearn version — predictions are unaffected).
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

# tldextract: use bundled PSL snapshot only — never try to download.
# suffix_list_urls=() disables HTTP fetching.
import tldextract as _tldextract
_tldextract_cache = _tldextract.TLDExtract(suffix_list_urls=())


# ═══════════════════════════════════════════════════════════════
# CONFIG & MODEL LOADING
# ═══════════════════════════════════════════════════════════════

def _resolve_model_dir() -> str:
    env_dir = os.environ.get("MODEL_DIR")
    if env_dir:
        return env_dir
    return os.path.dirname(os.path.abspath(__file__))


def _load_config(model_dir: str) -> dict:
    config_path = os.path.join(model_dir, "config.json")
    if not os.path.isfile(config_path):
        print(f"ERROR: config.json not found at {config_path}", file=sys.stderr, flush=True)
        sys.exit(1)
    with open(config_path, "r") as f:
        return json.load(f)


def _load_model(model_dir: str):
    model_path = os.path.join(model_dir, "model.joblib")
    if not os.path.isfile(model_path):
        print(f"ERROR: model not found at {model_path}", file=sys.stderr, flush=True)
        sys.exit(1)
    try:
        return joblib.load(model_path)
    except Exception as exc:
        print(f"ERROR: failed to load model: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)


def _load_top1m_domains_from_file() -> set:
    """Best-effort loader for top-1m exact domain matching."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, "data", "top-1m.csv"),
        os.path.join(script_dir, "top-1m.csv"),
    ]
    for path in candidates:
        if not os.path.isfile(path):
            continue
        domains = set()
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    row = line.strip()
                    if not row:
                        continue
                    parts = row.split(",", 1)
                    dom = parts[1].strip() if len(parts) == 2 else parts[0].strip()
                    if dom:
                        domains.add(dom.lower())
            if domains:
                return domains
        except Exception:
            continue
    return set()


def _prepare_runtime_lookups(config: dict) -> None:
    """Normalize and cache heavy lookup structures once at startup."""
    config["_brand_domains_norm"] = [
        str(b).lower() for b in config.get("brand_domains", []) if str(b).strip()
    ]

    top1m_raw = config.get("top1m_full_domains", [])
    top1m_set = set()
    if isinstance(top1m_raw, list) and top1m_raw:
        top1m_set = {str(d).lower() for d in top1m_raw if str(d).strip()}
    if not top1m_set:
        top1m_set = _load_top1m_domains_from_file()
    config["_top1m_full_domains_set"] = top1m_set


# ═══════════════════════════════════════════════════════════════
# FEATURE EXTRACTION (matches Kaggle training pipeline exactly)
# ═══════════════════════════════════════════════════════════════

REPEATED_DIGITS = re.compile(r"(\d)\1{2,}")


def _extract_tld(url: str) -> str:
    ext = _tldextract_cache(url)
    return ext.suffix.lower() if ext.suffix else ""


def _extract_domain(url: str) -> str:
    ext = _tldextract_cache(url)
    return ext.domain.lower() if ext.domain else ""


def _extract_subdomain(url: str) -> str:
    ext = _tldextract_cache(url)
    return ext.subdomain.lower() if ext.subdomain else ""


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)


def url_char_prob(url: str, char_prob_table: dict) -> float:
    alnum = [c for c in url.lower() if c.isalnum()]
    n = len(alnum)
    if n == 0:
        return 0.0
    return sum(char_prob_table.get(c, 0.0) for c in alnum) / n


def char_continuation_rate(url: str) -> float:
    if not url:
        return 0.0
    ma = md = ms = ca = cd = cs = 0
    for c in url:
        if c.isalpha():
            ca += 1; ma = max(ma, ca); cd = cs = 0
        elif c.isdigit():
            cd += 1; md = max(md, cd); ca = cs = 0
        else:
            cs += 1; ms = max(ms, cs); ca = cd = 0
    return (ma + md + ms) / len(url)


def _levenshtein_distance(a: str, b: str) -> int:
    """Compute Levenshtein distance with a small DP table."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            ins = curr[j - 1] + 1
            dele = prev[j] + 1
            sub = prev[j - 1] + (0 if ca == cb else 1)
            curr.append(min(ins, dele, sub))
        prev = curr
    return prev[-1]


def extract_features(url: str, config: dict) -> list:
    """Extract the active feature set used by the champion model.

    Returns a list of floats in the exact order of config['feature_names'].

    Pruned (not emitted):
      - has_ip_address      : 0 splits in champion model (ML-SPEC-v1.1 §5)
      - double_slash_in_path: 0 splits in champion model (ML-SPEC-v1.1 §5)
    """
    char_prob_table = config["char_prob_table"]
    tld_legit_prob = config["tld_legit_prob"]
    sensitive_words = config["sensitive_words"]
    brand_domains = config.get("_brand_domains_norm", [])
    top1m_full_domains = config.get("_top1m_full_domains_set", set())

    _default_suspicious_exts = {
        ".exe", ".zip", ".rar", ".scr", ".bat", ".cmd", ".msi", ".dll",
        ".vbs", ".js", ".jar", ".ps1", ".wsf", ".lnk", ".7z", ".cab",
    }
    suspicious_exts = set(config.get("suspicious_exts", _default_suspicious_exts))

    url_str = url.strip()
    parsed = urlparse(url_str if "://" in url_str else f"http://{url_str}")
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    scheme = (parsed.scheme or "").lower()
    tld = _extract_tld(url_str)
    domain = _extract_domain(url_str)
    subdomain = _extract_subdomain(url_str)
    sub_parts = [p for p in subdomain.split(".") if p] if subdomain else []
    url_lower = url_str.lower()

    f = {}

    # ─── TIER 1 (8 active of original 10) ─────────────────────
    f["url_length"]           = len(url_str)
    f["num_dots"]             = url_str.count(".")
    f["num_subdomains"]       = len(sub_parts)
    f["num_hyphens_url"]      = url_str.count("-")
    f["num_hyphens_hostname"] = hostname.count("-")
    f["https_flag"]           = 1 if scheme == "https" else 0
    f["entropy_url"]          = round(shannon_entropy(url_str), 6)
    f["num_numeric_chars"]    = sum(c.isdigit() for c in url_str)
    f["num_sensitive_words"]  = sum(url_lower.count(w) for w in sensitive_words)

    # ─── TIER 2 (10 active) ────────────────────────────────────
    f["hostname_length"]        = len(hostname)
    f["path_length"]            = len(path)
    f["url_char_prob"]          = round(url_char_prob(url_str, char_prob_table), 8)
    f["char_continuation_rate"] = round(char_continuation_rate(url_str), 6)
    f["tld_legit_prob"]         = round(tld_legit_prob.get(tld, 0.0), 8)
    f["entropy_domain"]         = round(shannon_entropy(domain), 6)
    f["num_query_params"]       = len(query.split("&")) if query else 0
    f["num_special_chars"]      = sum(1 for c in url_str if c in "!@#$%^&*~`|\\<>{}")
    f["at_symbol_present"]      = 1 if "@" in url_str else 0
    f["pct_numeric_chars"]      = round(f["num_numeric_chars"] / max(len(url_str), 1), 6)

    # ─── TIER 3 (9 active of original 10) ─────────────────────
    f["suspicious_file_ext"]  = 1 if any(path.lower().endswith(e) for e in suspicious_exts) else 0
    f["path_depth"]           = max(path.count("/") - 1, 0)
    f["num_underscores"]      = url_str.count("_")
    f["query_length"]         = len(query)
    f["has_fragment"]         = 1 if fragment else 0
    f["has_repeated_digits"]  = 1 if REPEATED_DIGITS.search(url_str) else 0
    f["avg_subdomain_length"] = round(sum(len(p) for p in sub_parts) / max(len(sub_parts), 1), 4)
    f["tld_length"]           = len(tld)
    f["token_count"]          = len([t for t in re.split(r"[/\?\&\=\-\_\.\:\@\#\+\~\%]", url_str) if t])
    if hostname.startswith("www."):
        hostname_bare = hostname[4:]
    else:
        hostname_bare = hostname
    if hostname_bare in top1m_full_domains:
        f["min_brand_levenshtein"] = 0
    elif domain and len(domain) >= 2 and brand_domains:
        f["min_brand_levenshtein"] = min(_levenshtein_distance(domain, b) for b in brand_domains)
    else:
        f["min_brand_levenshtein"] = 99

    # F32: registered_domain_top1m — Is the eTLD+1 in Cisco Umbrella top-1M?
    # Catches deep-path URLs on major platforms where the full hostname isn't in
    # top-1M (e.g. "gemini.google.com") but the registered domain IS ("google.com").
    reg_domain = (domain + "." + tld).lower() if domain and tld else ""
    f["registered_domain_top1m"] = 1 if (reg_domain and reg_domain in top1m_full_domains) else 0
    shortener_domains = {"bit.ly", "t.co", "tinyurl.com", "lnkd.in", "rb.gy", "tiny.cc", "is.gd", "ow.ly", "buff.ly", "cutt.ly"}
    f["is_shortener_domain"] = 1 if hostname in shortener_domains else 0
    is_local = hostname in {"localhost", "127.0.0.1", "::1"}
    is_private_v4 = bool(re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)", hostname))
    f["is_local_or_private_host"] = 1 if (is_local or is_private_v4) else 0

    # Return features in the exact order the model expects.
    feature_names = config["feature_names"]
    return [float(f.get(name, 0)) for name in feature_names]


def route_to_enrichment(prob: float, threshold: float, features: dict, raw_url: str = "") -> tuple[bool, str]:
    """
    Stage-B guardrail for structurally complex but likely-legitimate URLs.

    If the URL is above the phishing threshold mostly due to structural features
    (deep path/query/fragment/entropy), route to enrichment when legitimacy
    anchors are present and hard lexical-phish indicators are absent.
    """
    if prob < threshold:
        return False, ""

    structural_risk = (
        features.get("path_depth", 0) >= 1
        or features.get("num_query_params", 0) >= 1
        or features.get("has_fragment", 0) == 1
        or features.get("entropy_url", 0) >= 4.4
    )

    host = ""
    try:
        _u = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
        host = (_u.hostname or "").lower()
    except Exception:
        host = ""

    known_shorteners = {"bit.ly", "t.co", "tinyurl.com", "lnkd.in", "rb.gy", "tiny.cc", "is.gd", "ow.ly", "buff.ly", "cutt.ly"}
    is_known_shortener = features.get("is_shortener_domain", 0) == 1 or host in known_shorteners
    is_local_or_private = features.get("is_local_or_private_host", 0) == 1 or host in {"localhost", "127.0.0.1", "::1"}
    path = (_u.path or "").lower() if host else ""
    benign_path_tokens = {"dashboard", "home", "portal", "docs", "api", "users", "projects", "settings", "news"}
    path_tokens = {tok for tok in re.split(r"[^a-z0-9]+", path) if tok}
    benign_path_hint = len(path_tokens.intersection(benign_path_tokens)) > 0

    strong_platform_anchor = (
        features.get("registered_domain_top1m", 0) == 1
        and features.get("https_flag", 0) == 1
        and features.get("min_brand_levenshtein", 99) <= 2
    )
    known_domain_anchor = (
        features.get("registered_domain_top1m", 0) == 1
        and features.get("min_brand_levenshtein", 99) <= 2
        and features.get("num_sensitive_words", 0) == 0
        and features.get("at_symbol_present", 0) == 0
        and features.get("suspicious_file_ext", 0) == 0
    )
    soft_https_anchor = (
        features.get("https_flag", 0) == 1
        and features.get("at_symbol_present", 0) == 0
        and features.get("suspicious_file_ext", 0) == 0
        and features.get("num_sensitive_words", 0) <= 1
    )

    legitimacy_anchor = (
        strong_platform_anchor
        or known_domain_anchor
        or is_known_shortener
        or is_local_or_private
        or (soft_https_anchor and benign_path_hint)
    )

    strong_phish_lexical = (
        features.get("num_sensitive_words", 0) >= 2
        or features.get("at_symbol_present", 0) == 1
        or features.get("suspicious_file_ext", 0) == 1
    )

    contextual_risk = is_known_shortener or is_local_or_private or benign_path_hint
    if (structural_risk or contextual_risk) and legitimacy_anchor and not strong_phish_lexical:
        return True, "structural_shortcut_guardrail"
    return False, ""


# ═══════════════════════════════════════════════════════════════
# MAIN — SUBPROCESS LOOP
# ═══════════════════════════════════════════════════════════════

def main() -> None:
    model_dir = _resolve_model_dir()
    config = _load_config(model_dir)
    _prepare_runtime_lookups(config)
    model = _load_model(model_dir)

    feature_count = config.get("feature_count", 28)
    raw_threshold = config.get("classification_threshold", 0.5)
    try:
        threshold = float(raw_threshold)
    except (TypeError, ValueError):
        raise ValueError(
            f"invalid classification_threshold {raw_threshold!r} in config.json; expected float in [0.0, 1.0]"
        )
    if not (0.0 <= threshold <= 1.0):
        raise ValueError(
            f"invalid classification_threshold {threshold!r} in config.json; expected value in [0.0, 1.0]"
        )

    print(f"INFO: model loaded from {model_dir}", file=sys.stderr, flush=True)
    print(f"INFO: features={feature_count}, champion={config.get('champion_name', 'unknown')}", file=sys.stderr, flush=True)
    print("READY", flush=True)  # Signal readiness to Go process pool.

    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue

        try:
            req = json.loads(raw_line)

            # Support both protocols:
            #   {"url": "..."} — new: Python extracts features + predicts
            #   {"features": [...]} — legacy: pre-extracted features
            if "url" in req:
                url = req["url"]
                features = extract_features(url, config)
                feature_names = config.get("feature_names", [])
                feature_map = {k: float(v) for k, v in zip(feature_names, features)}
            elif "features" in req:
                features = req["features"]
                if not isinstance(features, list) or len(features) != feature_count:
                    raise ValueError(
                        f"expected {feature_count} features, got "
                        f"{len(features) if isinstance(features, list) else type(features).__name__}"
                    )
                feature_map = {}
            else:
                raise ValueError("request must contain 'url' or 'features' key")

            X = np.asarray([features], dtype=float)
            prob = float(model.predict_proba(X)[0, 1])
            score = round(prob * 100)
            routed, reason = route_to_enrichment(prob, threshold, feature_map, req.get("url", ""))
            label = "phishing" if prob >= threshold and not routed else "legitimate"
            resp: dict = {
                "score": score,
                "probability": prob,
                "label": label,
                "route_to_enrichment": routed,
                "route_reason": reason,
            }
        except Exception as exc:
            print(f"ERROR: inference failed: {exc}", file=sys.stderr, flush=True)
            resp = {"score": 50, "probability": 0.5, "label": "unknown", "error": str(exc)}

        print(json.dumps(resp), flush=True)


if __name__ == "__main__":
    main()
