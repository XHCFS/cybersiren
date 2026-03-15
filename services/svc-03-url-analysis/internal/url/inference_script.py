"""
╔══════════════════════════════════════════════════════════════════════╗
║  CyberSiren — Phishing URL Scanner Demo                            ║
║  Upload a .txt or .csv file → instant phishing scan                ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import concurrent.futures
import io
import json
import math
import os
import re
from collections import Counter
from urllib.parse import urlparse

import ipywidgets as widgets
import joblib
import numpy as np
import pandas as pd
from IPython.display import clear_output, display

# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════

MODEL_DIR = "/kaggle/input/datasets/saifeldenismail/thesavedmodel/cybersiren_model"

# ═══════════════════════════════════════════════════════════════
# LOAD MODEL & CONFIG
# ═══════════════════════════════════════════════════════════════

print("Loading CyberSiren model...")

with open(os.path.join(MODEL_DIR, "config.json"), "r") as f:
    config = json.load(f)

model = joblib.load(os.path.join(MODEL_DIR, "model.joblib"))

scaler = None
if config["needs_scaling"]:
    scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.joblib"))

FEATURE_NAMES    = config["feature_names"]
CHAR_PROB_TABLE  = config["char_prob_table"]
TLD_LEGIT_PROB   = config["tld_legit_prob"]
SENSITIVE_WORDS  = config["sensitive_words"]

# FIX 1: Load SUSPICIOUS_EXTS from config so inference always matches
# training. Falls back to a hardcoded set only if the key is absent
# (older saved models that pre-date the config addition).
_DEFAULT_SUSPICIOUS_EXTS = {
    ".exe", ".zip", ".rar", ".scr", ".bat", ".cmd", ".msi", ".dll",
    ".vbs", ".js", ".jar", ".ps1", ".wsf", ".lnk", ".7z", ".cab",
}
SUSPICIOUS_EXTS = set(config.get("suspicious_exts", _DEFAULT_SUSPICIOUS_EXTS))

print(f"  Model:    {config['champion_name']}")
print(f"  Features: {len(FEATURE_NAMES)}")
print(f"  Ready — upload a file below.\n")

# ═══════════════════════════════════════════════════════════════
# FEATURE EXTRACTION ENGINE (identical to training pipeline)
# ═══════════════════════════════════════════════════════════════

import subprocess
import sys

subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "tldextract"])
import tldextract as _tldextract


def _extract_tld(url: str) -> str:
    ext = _tldextract.extract(url)
    return ext.suffix.lower() if ext.suffix else ""

def _extract_domain(url: str) -> str:
    ext = _tldextract.extract(url)
    return ext.domain.lower() if ext.domain else ""

def _extract_subdomain(url: str) -> str:
    ext = _tldextract.extract(url)
    return ext.subdomain.lower() if ext.subdomain else ""

# FIX 2: Removed is_ip() — it was dead code. tldextract handles all
# IP-address URLs internally, and has_ip_address was pruned from the
# feature set anyway (0 splits in the champion LightGBM, ML-SPEC-v1.1 §5).

REPEATED_DIGITS = re.compile(r"(\d)\1{2,}")

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)

def url_char_prob(url: str) -> float:
    alnum = [c for c in url.lower() if c.isalnum()]
    n = len(alnum)
    if n == 0:
        return 0.0
    return sum(CHAR_PROB_TABLE.get(c, 0.0) for c in alnum) / n

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

def extract_features(url: str) -> dict:
    """Extract the 28 active features used by the champion LightGBM model.

    Pruned (not emitted):
      - has_ip_address      : 0 splits in champion model (ML-SPEC-v1.1 §5)
      - double_slash_in_path: 0 splits in champion model (ML-SPEC-v1.1 §5)
    """
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
    # F04 has_ip_address — PRUNED (0 splits)
    f["num_hyphens_url"]      = url_str.count("-")
    f["num_hyphens_hostname"] = hostname.count("-")
    f["https_flag"]           = 1 if scheme == "https" else 0
    f["entropy_url"]          = round(shannon_entropy(url_str), 6)
    f["num_numeric_chars"]    = sum(c.isdigit() for c in url_str)
    f["num_sensitive_words"]  = sum(url_lower.count(w) for w in SENSITIVE_WORDS)

    # ─── TIER 2 (10 active) ────────────────────────────────────
    f["hostname_length"]        = len(hostname)
    f["path_length"]            = len(path)
    f["url_char_prob"]          = round(url_char_prob(url_str), 8)
    f["char_continuation_rate"] = round(char_continuation_rate(url_str), 6)
    f["tld_legit_prob"]         = round(TLD_LEGIT_PROB.get(tld, 0.0), 8)
    f["entropy_domain"]         = round(shannon_entropy(domain), 6)
    f["num_query_params"]       = len(query.split("&")) if query else 0
    f["num_special_chars"]      = sum(1 for c in url_str if c in "!@#$%^&*~`|\\<>{}")
    f["at_symbol_present"]      = 1 if "@" in url_str else 0
    f["pct_numeric_chars"]      = round(f["num_numeric_chars"] / max(len(url_str), 1), 6)

    # ─── TIER 3 (9 active of original 10) ─────────────────────
    f["suspicious_file_ext"]  = 1 if any(path.lower().endswith(e) for e in SUSPICIOUS_EXTS) else 0
    f["path_depth"]           = max(path.count("/") - 1, 0)
    f["num_underscores"]      = url_str.count("_")
    # F24 double_slash_in_path — PRUNED (0 splits)
    f["query_length"]         = len(query)
    f["has_fragment"]         = 1 if fragment else 0
    f["has_repeated_digits"]  = 1 if REPEATED_DIGITS.search(url_str) else 0
    f["avg_subdomain_length"] = round(sum(len(p) for p in sub_parts) / max(len(sub_parts), 1), 4)
    f["tld_length"]           = len(tld)
    f["token_count"]          = len([t for t in re.split(r"[/\?\&\=\-\_\.\:\@\#\+\~\%]", url_str) if t])

    return f

# ═══════════════════════════════════════════════════════════════
# URL PARSING (from uploaded file bytes)
# ═══════════════════════════════════════════════════════════════

def parse_urls_from_bytes(content_bytes, filename: str) -> list:
    """Parse URLs from uploaded file content. Handles .txt and .csv."""

    if isinstance(content_bytes, memoryview):
        content_bytes = content_bytes.tobytes()
    elif isinstance(content_bytes, bytearray):
        content_bytes = bytes(content_bytes)
    elif not isinstance(content_bytes, bytes):
        content_bytes = bytes(content_bytes)

    text = content_bytes.decode("utf-8", errors="replace")
    lines = text.splitlines()
    first_line = lines[0].strip() if lines else ""

    # FIX 3: The original heuristic checked `"url" in first_line.lower()`,
    # which fired on any plain-text file whose first URL happened to contain
    # the substring "url" (e.g. "http://banking-url-checker.ru"). That caused
    # pandas to treat that URL as a column header, silently discarding it.
    #
    # Correct logic: treat the file as CSV only when the filename ends in
    # ".csv", OR when the first line looks like an actual header row — i.e.
    # it contains "url" but does NOT start with a URL scheme or bare hostname.
    is_url_like = bool(re.match(r"^https?://|^www\.", first_line, re.IGNORECASE))
    is_csv = filename.lower().endswith(".csv") or (
        "url" in first_line.lower() and not is_url_like
    )

    if is_csv:
        try:
            df = pd.read_csv(io.StringIO(text), low_memory=False)
        except Exception:
            return [l.strip() for l in lines if l.strip() and not l.strip().startswith("#") and len(l.strip()) > 5]

        if df.empty:
            return []

        url_col = None
        for col in df.columns:
            if str(col).strip().lower() == "url":
                url_col = col
                break
        if url_col is None:
            for col in df.columns:
                if "url" in str(col).strip().lower():
                    url_col = col
                    break
        if url_col is None:
            url_col = df.columns[0]

        urls = df[url_col].dropna().astype(str).str.strip().tolist()
        return [u for u in urls if u and u.lower() != "nan" and len(u) > 5]

    return [l.strip() for l in lines if l.strip() and not l.strip().startswith("#") and len(l.strip()) > 5]

# ═══════════════════════════════════════════════════════════════
# PREDICTION + DISPLAY
# ═══════════════════════════════════════════════════════════════

def risk_level(prob):
    if prob >= 0.85:   return "DANGEROUS"
    elif prob >= 0.50: return "SUSPICIOUS"
    elif prob >= 0.30: return "UNCERTAIN"
    else:              return "SAFE"

def scan_urls(urls: list, output_widget):
    """Run the full scan pipeline and save results as downloadable CSV."""
    with output_widget:
        clear_output(wait=True)

        if not urls:
            print("WARNING: No valid URLs found in the uploaded file.")
            return

        print(f"Scanning {len(urls):,} URLs...")

        # Parallelize feature extraction across CPU cores
        with concurrent.futures.ThreadPoolExecutor() as executor:
            rows = list(executor.map(extract_features, urls))

        X_demo = pd.DataFrame(rows)

        # Align to the exact 28-feature schema the model was trained on.
        # extract_features() already omits the two pruned features, so no
        # padding should be needed — this loop is a safety net only.
        for col in FEATURE_NAMES:
            if col not in X_demo.columns:
                X_demo[col] = 0
        X_demo = X_demo[FEATURE_NAMES]

        # Scale if needed (LightGBM does not require scaling; scaler is None)
        if scaler is not None:
            X_demo = scaler.transform(X_demo)

        # Predict
        y_pred = model.predict(X_demo)
        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_demo)[:, 1]
        else:
            y_prob = y_pred.astype(float)

        # Build full results dataframe, sorted most dangerous first
        results = pd.DataFrame({
            "url": urls,
            "prediction": ["PHISHING" if p == 1 else "LEGITIMATE" for p in y_pred],
            "phish_probability": [round(p, 4) for p in y_prob],
            "risk_level": [risk_level(p) for p in y_prob],
        })
        results = results.sort_values(by="phish_probability", ascending=False).reset_index(drop=True)

        # Save CSV
        out_path = "/kaggle/working/cybersiren_scan_results.csv"
        results.to_csv(out_path, index=False)

        # Summary
        n_phish     = (results["prediction"] == "PHISHING").sum()
        n_legit     = (results["prediction"] == "LEGITIMATE").sum()
        n_uncertain = results["risk_level"].isin(["UNCERTAIN", "SUSPICIOUS"]).sum()

        print(f"\nScan complete — {len(results):,} URLs processed")
        print(f"  Phishing:   {n_phish:,}")
        print(f"  Legitimate: {n_legit:,}")
        print(f"  Uncertainty band (routed to enrichment): {n_uncertain:,}")
        print(f"\nResults saved to: {out_path}")

        from IPython.display import FileLink
        display(FileLink(out_path, result_html_prefix="Download results: "))

# ═══════════════════════════════════════════════════════════════
# INTERACTIVE WIDGET
# ═══════════════════════════════════════════════════════════════

output = widgets.Output()

uploader = widgets.FileUpload(
    accept=".txt,.csv",
    multiple=False,
    description="Upload URLs",
    button_style="info",
    layout=widgets.Layout(width="300px"),
)

scan_btn = widgets.Button(
    description="Scan URLs",
    button_style="success",
    layout=widgets.Layout(width="200px", height="38px"),
    disabled=True,
)

status_label = widgets.HTML(
    value='<span style="color: #888; font-size: 13px;">Upload a .txt or .csv file to begin</span>'
)

_uploaded = {"bytes": None, "filename": None}


def on_upload(change):
    files = change["new"]
    if not files:
        return

    try:
        # ipywidgets v8
        if isinstance(files, tuple) and len(files) > 0:
            f = files[0]
            _uploaded["bytes"] = f["content"]
            _uploaded["filename"] = f["name"]
        # ipywidgets v7
        elif isinstance(files, dict):
            fname = list(files.keys())[0]
            _uploaded["bytes"] = files[fname]["content"]
            _uploaded["filename"] = fname
        else:
            raise ValueError(f"Unsupported upload structure: {type(files)}")

        n_bytes = len(_uploaded["bytes"])
        status_label.value = (
            f'<span style="color: #1D9E75; font-size: 13px;">'
            f'✓ <b>{_uploaded["filename"]}</b> ({n_bytes/1024:.1f} KB) — click Scan</span>'
        )
        scan_btn.disabled = False

    except Exception as e:
        status_label.value = (
            f'<span style="color: #D9534F; font-size: 13px;">'
            f'✗ Upload failed: {type(e).__name__}: {e}</span>'
        )


def on_scan(btn):
    if _uploaded["bytes"] is None:
        return

    scan_btn.disabled = True
    scan_btn.description = "Scanning..."
    status_label.value = '<span style="color: #888; font-size: 13px;">Processing...</span>'

    try:
        urls = parse_urls_from_bytes(_uploaded["bytes"], _uploaded["filename"])
        scan_urls(urls, output)

        status_label.value = (
            f'<span style="color: #1D9E75; font-size: 13px;">'
            f'✓ Done — upload another file or re-scan</span>'
        )

    except Exception as e:
        with output:
            clear_output(wait=True)
            import traceback
            print("ERROR during scan:")
            traceback.print_exc()

        status_label.value = (
            f'<span style="color: #D9534F; font-size: 13px;">'
            f'✗ Scan failed: {type(e).__name__}: {e}</span>'
        )

    finally:
        scan_btn.description = "Scan URLs"
        scan_btn.disabled = False


uploader.observe(on_upload, names="value")
scan_btn.on_click(on_scan)

display(widgets.VBox([
    widgets.HTML('<h3 style="margin: 0 0 8px;">CyberSiren — Phishing URL Scanner</h3>'),
    widgets.HBox([uploader, scan_btn], layout=widgets.Layout(gap="12px", align_items="center")),
    status_label,
    output,
]))
