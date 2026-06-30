#!/usr/bin/env python3
"""
Retrain hgb_operational.joblib with augmented features:
  - CDN geo-neutralization (Cloudflare, Akamai, Fastly, etc.)
  - domain_age_days, cert_age_days, cert_validity_span_days (numeric)
  - title_brand_mismatch, title_has_login_kw (binary float)

Reads the ready_operational split from data/ml_dataset/ready_operational/.

Usage::

  python fusion_export/scripts/retrain_operational.py
  python fusion_export/scripts/retrain_operational.py --out fusion_export/models/hgb_operational.joblib
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Tuple

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fusion_kit.operational import (  # noqa: E402
    _CDN_ASNS,
    _apex_is_numeric,
    _days_between,
    _days_since,
    _form_action_mismatch,
    _ip_in_url,
    _is_ephemeral_platform,
    _non_std_port,
    _subdomain_brand_count,
    _subdomain_depth,
    _title_brand_mismatch,
    _title_has_login_kw,
    _url_domain_char_ratio,
)


def _load_split(ready: Path, name: str) -> Tuple[pd.DataFrame, pd.DataFrame, np.ndarray]:
    d = ready / name
    X = pd.read_csv(d / "features.csv", low_memory=False)
    lab = pd.read_csv(d / "labels.csv", low_memory=False)
    if not (X["sample_id"].values == lab["sample_id"].values).all():
        raise SystemExit(f"{name}: sample_id mismatch")
    y = pd.to_numeric(lab["label"], errors="coerce").fillna(0).astype(np.int32).to_numpy()
    return X, lab, y


def _augment(df: pd.DataFrame) -> pd.DataFrame:
    """Apply CDN geo-neutralization and add derived features in-place."""
    df = df.copy()

    # --- CDN geo-neutralization ---
    asn_numeric = pd.to_numeric(df["asn"], errors="coerce")
    is_cdn = asn_numeric.apply(lambda v: not np.isnan(v) and int(v) in _CDN_ASNS)
    for geo_col in ("country", "country_name", "region", "city"):
        if geo_col in df.columns:
            df.loc[is_cdn, geo_col] = ""
    for geo_col in ("latitude", "longitude"):
        if geo_col in df.columns:
            df.loc[is_cdn, geo_col] = np.nan

    # --- Derived numeric features ---
    df["domain_age_days"] = df["creation_date"].apply(_days_since)
    df["cert_age_days"] = df["cert_valid_from"].apply(_days_since)
    df["cert_validity_span_days"] = df.apply(
        lambda r: _days_between(r["cert_valid_from"], r["cert_valid_to"]), axis=1
    )

    # --- Semantic title features ---
    hostname = df["hostname"].fillna("").astype(str)
    page_title = df["page_title"].fillna("").astype(str)
    df["title_brand_mismatch"] = [
        _title_brand_mismatch(t, h) for t, h in zip(page_title, hostname)
    ]
    df["title_has_login_kw"] = page_title.apply(_title_has_login_kw)

    # --- Structural hostname features ---
    df["subdomain_depth"] = hostname.apply(_subdomain_depth)
    df["subdomain_brand_count"] = hostname.apply(_subdomain_brand_count)
    df["apex_is_numeric"] = hostname.apply(_apex_is_numeric)

    # --- Content/redirect features ---
    form_action_domain = df["form_action_domain"].fillna("").astype(str) if "form_action_domain" in df.columns else pd.Series([""] * len(df))
    df["form_action_mismatch"] = [
        _form_action_mismatch(f or None, h) for f, h in zip(form_action_domain, hostname)
    ]

    # --- URL structural features (v5) — computable from url column ---
    # Note: url_path_entropy and url_path_depth excluded — they cause distribution shift
    # because training benign data (Tranco root domains) has simple paths while
    # legitimate brand auth / enterprise URLs have complex OAuth paths.
    url_col = df["url"].fillna("").astype(str) if "url" in df.columns else pd.Series([""] * len(df))
    df["ip_in_url"] = url_col.apply(_ip_in_url)
    df["non_std_port"] = url_col.apply(_non_std_port)
    df["url_domain_char_ratio"] = hostname.apply(_url_domain_char_ratio)

    # --- DOM/content features (v5) — not in historical training CSVs; set NaN so
    #     HGB treats as missing (learns no split, but features are forward-compatible).
    #     Training data pre-dates Playwright extraction. ---
    for col in ("favicon_domain_mismatch", "password_field_count", "has_hidden_redirect"):
        if col not in df.columns:
            df[col] = np.nan

    # --- Platform hosting feature (v6) ---
    df["is_ephemeral_platform"] = hostname.apply(_is_ephemeral_platform)

    return df


def _make_platform_rows(columns: list[str], n_per_class: int = 500) -> tuple[pd.DataFrame, np.ndarray]:
    """Synthetic balanced platform rows so HGB learns is_ephemeral_platform alone isn't deterministic.

    Without these, the training set contains no benign ephemeral-platform examples and the model
    treats is_ephemeral_platform=1 as near-certain phishing, causing 100% FPR on legitimate
    developer/portfolio sites hosted on GitHub Pages, Vercel, Netlify, etc.

    Discrimination the model learns from these rows:
      benign  → subdomain_brand_count=0, title_brand_mismatch=0, domain_age_days>>1000
      phishing → subdomain_brand_count≥1, title_brand_mismatch=1,  domain_age_days<60
    """
    _rng = np.random.default_rng(77)
    _platforms = [
        ("vercel.app",  13335.0, "CLOUDFLARENET"),
        ("pages.dev",   13335.0, "CLOUDFLARENET"),
        ("github.io",   36459.0, "GITHUB"),
        ("netlify.app", 54113.0, "FASTLY"),
        ("web.app",     15169.0, "GOOGLE"),
        ("glitch.me",   16509.0, "AMAZON-02"),
        ("webflow.io",  16509.0, "AMAZON-02"),
        ("myportfolio.com", 16509.0, "AMAZON-02"),
        ("company.site", 16509.0, "AMAZON-02"),
    ]
    _benign_prefixes = [
        "my-project", "portfolio", "team-docs", "blog", "landing",
        "internal-tools", "open-source", "developer-portfolio", "static-site",
        "crm-demo", "analytics", "docs-site",
    ]
    _brands = ["paypal", "microsoft", "google", "apple", "amazon", "bankofamerica", "chase"]
    _actions = ["secure", "verify", "login", "auth", "update"]

    rows: list[dict] = []
    labels: list[int] = []

    # Benign brand-auth rows — legitimate SSO pages: old domain, current cert, major ASN,
    # title_has_login_kw=1 but title_brand_mismatch=0 (brand matches own domain).
    # These anchor the model: login keywords + old domain + Microsoft/Google ASN = benign.
    _brand_auth = [
        ("login.microsoftonline.com", 8075.0,  "MICROSOFT-CORP"),
        ("accounts.google.com",       15169.0, "GOOGLE"),
        ("appleid.apple.com",         714.0,   "APPLE-ENGINEERING"),
        ("secure.bankofamerica.com",  16509.0, "AMAZON-02"),
        ("auth.chase.com",            16509.0, "AMAZON-02"),
        ("login.live.com",            8075.0,  "MICROSOFT-CORP"),
        ("login.salesforce.com",      16509.0, "AMAZON-02"),
        ("company.okta.com",          16509.0, "AMAZON-02"),
    ]
    for i in range(n_per_class):
        host, asn, asn_name = _brand_auth[i % len(_brand_auth)]
        domain_age = 3000.0 + float(_rng.integers(0, 2000))
        cert_age   = 10.0  + float(_rng.integers(0, 80))
        row: dict = {c: "" for c in columns}
        row.update({
            "url": f"https://{host}/signin",
            "hostname": host,
            "domain": ".".join(host.split(".")[-2:]),
            "tld": ".com",
            "asn": asn,
            "asn_name": asn_name,
            "isp": asn_name,
            "country": "US",
            "country_name": "United States",
            "ssl_enabled": "yes",
            "cert_issuer": "DigiCert",
            "cert_subject": host,
            "http_status_code": 200.0,
            "page_title": "Sign in to your account",
            "page_language": "en",
            "registrar": "MarkMonitor Inc.",
            "domain_age_days": domain_age,
            "cert_age_days": cert_age,
            "cert_validity_span_days": 365.0,
            "title_brand_mismatch": 0.0,
            "title_has_login_kw": 1.0,
            "subdomain_depth": float(max(0, len(host.split(".")) - 2)),
            "subdomain_brand_count": 0.0,
            "apex_is_numeric": 0.0,
            "form_action_mismatch": 0.0,
            "ip_in_url": 0.0,
            "non_std_port": 0.0,
            "url_domain_char_ratio": round(
                sum(1 for c in host if not c.isalpha() and c != ".") / max(len(host), 1), 4
            ),
            "favicon_domain_mismatch": np.nan,
            "password_field_count": np.nan,
            "has_hidden_redirect": np.nan,
            "is_ephemeral_platform": 0.0,
            "latitude": np.nan,
            "longitude": np.nan,
        })
        rows.append(row)
        labels.append(0)

    # Benign platform rows — no brand name in subdomain, neutral title, old apex domain age
    for i in range(n_per_class):
        plat_apex, asn, asn_name = _platforms[i % len(_platforms)]
        prefix = _benign_prefixes[i % len(_benign_prefixes)] + f"-{i:04d}"
        hostname = f"{prefix}.{plat_apex}"
        tld = "." + plat_apex.split(".")[-1]
        domain_age = 3500.0 + float(_rng.integers(0, 1000))
        cert_age   = 20.0  + float(_rng.integers(0, 60))
        row: dict = {c: "" for c in columns}
        row.update({
            "url": f"https://{hostname}/",
            "hostname": hostname,
            "domain": hostname,
            "tld": tld,
            "asn": asn,
            "asn_name": asn_name,
            "isp": asn_name,
            "country": "US",
            "country_name": "United States",
            "ssl_enabled": "yes",
            "cert_issuer": "Let's Encrypt",
            "cert_subject": hostname,
            "http_status_code": 200.0,
            "page_title": "Dashboard",
            "page_language": "en",
            "registrar": "Google LLC",
            # derived
            "domain_age_days": domain_age,
            "cert_age_days": cert_age,
            "cert_validity_span_days": 90.0,
            "title_brand_mismatch": 0.0,
            "title_has_login_kw": 0.0,
            "subdomain_depth": 1.0,
            "subdomain_brand_count": 0.0,
            "apex_is_numeric": 0.0,
            "form_action_mismatch": 0.0,
            "ip_in_url": 0.0,
            "non_std_port": 0.0,
            "url_domain_char_ratio": round(
                sum(1 for c in hostname if not c.isalpha() and c != ".") / max(len(hostname), 1), 4
            ),
            "favicon_domain_mismatch": np.nan,
            "password_field_count": np.nan,
            "has_hidden_redirect": np.nan,
            "is_ephemeral_platform": 1.0,
            "latitude": np.nan,
            "longitude": np.nan,
        })
        rows.append(row)
        labels.append(0)

    # Phishing platform rows — brand in subdomain, brand in title, fresh apex domain age
    for i in range(n_per_class):
        plat_apex, asn, asn_name = _platforms[i % len(_platforms)]
        brand  = _brands[i % len(_brands)]
        action = _actions[i % len(_actions)]
        hostname = f"{brand}-{action}-{i:04d}.{plat_apex}"
        tld = "." + plat_apex.split(".")[-1]
        domain_age = 5.0 + float(_rng.integers(0, 45))
        cert_age   = 3.0 + float(_rng.integers(0, 20))
        row = {c: "" for c in columns}
        row.update({
            "url": f"https://{hostname}/login",
            "hostname": hostname,
            "domain": hostname,
            "tld": tld,
            "asn": asn,
            "asn_name": asn_name,
            "isp": asn_name,
            "country": "US",
            "country_name": "United States",
            "ssl_enabled": "yes",
            "cert_issuer": "Let's Encrypt",
            "cert_subject": hostname,
            "http_status_code": 200.0,
            "page_title": f"{brand.capitalize()} — Sign In",
            "page_language": "en",
            "registrar": "Google LLC",
            # derived
            "domain_age_days": domain_age,
            "cert_age_days": cert_age,
            "cert_validity_span_days": 90.0,
            "title_brand_mismatch": 1.0,
            "title_has_login_kw": 1.0,
            "subdomain_depth": 1.0,
            "subdomain_brand_count": 1.0,
            "apex_is_numeric": 0.0,
            "form_action_mismatch": 0.0,
            "ip_in_url": 0.0,
            "non_std_port": 0.0,
            "url_domain_char_ratio": round(
                sum(1 for c in hostname if not c.isalpha() and c != ".") / max(len(hostname), 1), 4
            ),
            "favicon_domain_mismatch": np.nan,
            "password_field_count": np.nan,
            "has_hidden_redirect": np.nan,
            "is_ephemeral_platform": 1.0,
            "latitude": np.nan,
            "longitude": np.nan,
        })
        rows.append(row)
        labels.append(1)

    df = pd.DataFrame(rows, columns=columns)
    return df, np.array(labels, dtype=np.int32)


def _make_shortener_rows(columns: list[str], n_benign: int = 400) -> tuple[pd.DataFrame, np.ndarray]:
    """Synthetic benign rows for known URL shortener domains.

    Without these, the HGB model has never seen bit.ly / t.co as benign
    operational examples — they're not in the training corpus because
    real shortener URLs (bit.ly/abc123) are excluded from phish feeds.

    Key signals that distinguish a shortener domain from a fresh phishing domain:
      - domain_age_days >> 3000 (bit.ly registered 2008, t.co 2010)
      - cert_age_days low (90-day automated renewal: Let's Encrypt / DigiCert)
      - trusted ASN (Twitter=13414, Bitly=26802, Fastly=54113)
      - title_has_login_kw=0 (shortener redirect pages have no login form)
      - title_brand_mismatch=0
      - is_ephemeral_platform=0
    """
    _rng = np.random.default_rng(99)
    _shorteners = [
        ("t.co",        "t.co",        ".co",  13414, "TWITTER-NETWORK"),
        ("bit.ly",      "bit.ly",      ".ly",  26802, "BITLY-INC"),
        ("tinyurl.com", "tinyurl.com", ".com", 54113, "FASTLY"),
        ("ow.ly",       "ow.ly",       ".ly",  54113, "FASTLY"),
        ("buff.ly",     "buff.ly",     ".ly",  54113, "FASTLY"),
    ]

    rows: list[dict] = []
    labels: list[int] = []

    for i in range(n_benign):
        host, domain, tld, asn, asn_name = _shorteners[i % len(_shorteners)]
        # Shortener domains are years old
        domain_age = 4500.0 + float(_rng.integers(0, 1500))
        # But certs rotate on standard 90-day cycle
        cert_age   = 5.0 + float(_rng.integers(0, 85))
        # Random opaque code: 5-8 alphanumeric chars
        code_len = int(_rng.integers(5, 9))
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        code = "".join(chars[int(_rng.integers(0, len(chars)))] for _ in range(code_len))
        url = f"https://{host}/{code}"
        row: dict = {c: "" for c in columns}
        row.update({
            "url": url,
            "hostname": host,
            "domain": domain,
            "tld": tld,
            "asn": float(asn),
            "asn_name": asn_name,
            "isp": asn_name,
            "country": "US",
            "country_name": "United States",
            "ssl_enabled": "yes",
            "cert_issuer": "DigiCert",
            "cert_subject": host,
            "http_status_code": 301.0,
            "page_title": "",
            "page_language": "en",
            "registrar": "MarkMonitor Inc.",
            "domain_age_days": domain_age,
            "cert_age_days": cert_age,
            "cert_validity_span_days": 90.0,
            "title_brand_mismatch": 0.0,
            "title_has_login_kw": 0.0,
            "subdomain_depth": 0.0,
            "subdomain_brand_count": 0.0,
            "apex_is_numeric": 0.0,
            "form_action_mismatch": 0.0,
            "ip_in_url": 0.0,
            "non_std_port": 0.0,
            "url_domain_char_ratio": round(
                sum(1 for c in url if not c.isalpha() and c not in "./:") / max(len(url), 1), 4
            ),
            "favicon_domain_mismatch": np.nan,
            "password_field_count": np.nan,
            "has_hidden_redirect": 1.0,
            "is_ephemeral_platform": 0.0,
            "latitude": np.nan,
            "longitude": np.nan,
        })
        rows.append(row)
        labels.append(0)

    df = pd.DataFrame(rows, columns=columns)
    return df, np.array(labels, dtype=np.int32)


def _string_col_cardinality(s: pd.Series) -> int:
    return int(s.astype(str).nunique(dropna=False))


def _prepare_X_for_hgb(
    X: pd.DataFrame,
    *,
    ref_cardinality: dict[str, int] | None,
    max_categories: int,
) -> tuple[pd.DataFrame, dict[str, int]]:
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ready-dir", type=Path, default=ROOT / "data" / "ml_dataset" / "ready_operational")
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[1] / "models" / "hgb_operational.joblib")
    ap.add_argument("--max-iter", type=int, default=400)
    ap.add_argument("--learning-rate", type=float, default=0.06)
    ap.add_argument("--max-categories", type=int, default=255)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import accuracy_score, classification_report, roc_auc_score

    ready = args.ready_dir
    print(f"Loading splits from {ready} …")
    X_train_raw, _, y_train = _load_split(ready, "train")
    X_val_raw, _, y_val = _load_split(ready, "val")
    X_test_raw, _, y_test = _load_split(ready, "test")

    print("Augmenting features (CDN neutralization + derived features) …")
    # form_action_domain is only a source column for computing form_action_mismatch;
    # drop it so the model trains on the derived binary feature, not raw text.
    _drop_source_cols = ["sample_id", "form_action_domain"]
    X_train_aug = _augment(X_train_raw).drop(columns=[c for c in _drop_source_cols if c in X_train_raw.columns])
    X_val_aug = _augment(X_val_raw).drop(columns=[c for c in _drop_source_cols if c in X_val_raw.columns])
    X_test_aug = _augment(X_test_raw).drop(columns=[c for c in _drop_source_cols if c in X_test_raw.columns])

    print(f"Features: {list(X_train_aug.columns)}")

    # --- Inject synthetic platform rows (v6 calibration) ---
    # Training data has no benign ephemeral-platform examples, so without injection
    # HGB treats is_ephemeral_platform=1 as near-certain phishing.  Balanced injection
    # teaches it to discriminate via subdomain_brand_count + title_brand_mismatch.
    synth_X, synth_y = _make_platform_rows(list(X_train_aug.columns))
    X_train_aug = pd.concat([X_train_aug, synth_X], ignore_index=True)
    y_train = np.concatenate([y_train, synth_y])
    print(f"Injected {len(synth_y)} synthetic platform rows "
          f"({(synth_y==1).sum()} phishing, {(synth_y==0).sum()} benign)")

    # --- Inject synthetic URL shortener rows (v7 calibration) ---
    # Training data has no benign URL shortener domain examples (bit.ly, t.co, etc.)
    # because real shortener URLs are not in phish feeds.  Without injection, HGB
    # has no prior for old+trusted shortener domains and may assign elevated op_p.
    # These rows anchor: old domain + low cert_age + trusted ASN + no login kw = benign.
    short_X, short_y = _make_shortener_rows(list(X_train_aug.columns))
    X_train_aug = pd.concat([X_train_aug, short_X], ignore_index=True)
    y_train = np.concatenate([y_train, short_y])
    print(f"Injected {len(short_y)} synthetic shortener rows (all benign)")

    # Verify CDN neutralization impact
    orig_cdn_ca = ((X_train_raw["asn"] == 13335) & (X_train_raw["country"] == "CA")).sum()
    new_cdn_ca = ((X_train_aug["asn"] == 13335) & (X_train_aug["country"] == "CA")).sum()
    print(f"Cloudflare+CA rows before neutralization: {orig_cdn_ca} → after: {new_cdn_ca}")
    print(f"title_brand_mismatch rate  phishing={X_train_aug.loc[y_train==1, 'title_brand_mismatch'].mean():.3f}  benign={X_train_aug.loc[y_train==0, 'title_brand_mismatch'].mean():.4f}")

    X_train_p, ref_card = _prepare_X_for_hgb(X_train_aug, ref_cardinality=None, max_categories=args.max_categories)
    X_val_p, _ = _prepare_X_for_hgb(X_val_aug, ref_cardinality=ref_card, max_categories=args.max_categories)
    X_test_p, _ = _prepare_X_for_hgb(X_test_aug, ref_cardinality=ref_card, max_categories=args.max_categories)

    hashed = [c for c, n in ref_card.items() if n > args.max_categories]
    print(f"Hashed columns: {hashed}")

    clf = HistGradientBoostingClassifier(
        categorical_features="from_dtype",
        max_iter=args.max_iter,
        learning_rate=args.learning_rate,
        random_state=args.seed,
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=20,
    )
    print(f"Fitting on {len(y_train)} rows, {X_train_p.shape[1]} features …")
    clf.fit(X_train_p, y_train)
    print(f"  n_iter_={clf.n_iter_}")

    def report(name: str, X: pd.DataFrame, y: np.ndarray) -> dict:
        proba = clf.predict_proba(X)[:, 1]
        pred = (proba >= 0.5).astype(np.int32)
        acc = float(accuracy_score(y, pred))
        try:
            auc = float(roc_auc_score(y, proba))
        except ValueError:
            auc = float("nan")
        print(f"\n{name}: accuracy={acc:.4f}  roc_auc={auc:.6f}")
        print(classification_report(y, pred, target_names=["benign", "phishing"], digits=4))
        return {"accuracy": acc, "roc_auc": auc}

    metrics = {
        "train": report("train", X_train_p, y_train),
        "val": report("val", X_val_p, y_val),
        "test": report("test", X_test_p, y_test),
        "n_features": int(X_train_p.shape[1]),
        "feature_names": list(X_train_p.columns),
        "string_column_cardinality_train": ref_card,
        "hashed_columns": hashed,
        "max_categories": args.max_categories,
        "classifier": "HistGradientBoostingClassifier",
        "ready_dir": str(ready),
        "cdn_neutralized": True,
        "derived_features": ["domain_age_days", "cert_age_days", "cert_validity_span_days",
                             "title_brand_mismatch", "title_has_login_kw",
                             "subdomain_depth", "subdomain_brand_count", "apex_is_numeric",
                             "form_action_mismatch",
                             "ip_in_url", "non_std_port", "url_domain_char_ratio",
                             "favicon_domain_mismatch", "password_field_count", "has_hidden_redirect",
                             "is_ephemeral_platform"],
        "synthetic_injections": {
            "platform_rows": 1500,
            "shortener_rows": 400,
        },
    }

    payload = {"model": clf, "metrics": metrics, "ref_cardinality": ref_card, "max_categories": args.max_categories}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(payload, args.out)
    meta = args.out.with_suffix(".metrics.json")
    meta.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"\nWrote {args.out.resolve()}")
    print(f"Wrote {meta.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
