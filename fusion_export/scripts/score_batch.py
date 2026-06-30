#!/usr/bin/env python3
"""
Score URLs with fusion: ``mean(url_char_lr, hgb_operational)`` (default).

Reads one URL per line from a text file (or stdin), enriches each URL, maps to operational
features, loads both models from ``./models/`` by default, prints TSV:
url, effective_url, url_p, op_p, deploy_p.

Example::

  python scripts/score_batch.py --urls urls.txt --workers 6
  cat urls.txt | python scripts/score_batch.py --urls -
"""
from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fusion_kit.enrich import enrich_url, resolve_short_url  # noqa: E402
from fusion_kit.operational import enrichment_to_operational_row  # noqa: E402
from fusion_kit.scoring import fusion, load_operational_bundle, score_operational, score_url_hash  # noqa: E402
# URL normalization (http→https, lowercase) is applied inside the joblib pipeline via
# FunctionTransformer(canonicalize_url_batch) — no manual call needed here.
from fusion_kit import content_gate as cgate  # noqa: E402


def _apex(url: str) -> str:
    """Return last-two-label apex domain from URL, lowercase."""
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _read_urls(path: Path) -> list[str]:
    if str(path) == "-":
        raw = sys.stdin.read().splitlines()
    else:
        raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
    out: list[str] = []
    seen: set[str] = set()
    for line in raw:
        s = line.strip().replace("\r", "")
        if not s or s.startswith("#"):
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--urls", type=Path, required=True, help="File with one URL per line, or - for stdin")
    ap.add_argument("--models-dir", type=Path, default=ROOT / "models")
    ap.add_argument("--fusion", choices=("max", "mean"), default="mean")
    ap.add_argument("--threshold", type=float, default=0.35,
                    help="Fusion score threshold for phishing verdict (default: 0.35)")
    ap.add_argument("--feed-tag", type=str, default="fusion_export", help="Second arg to enrich_url")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--url-only", action="store_true", help="Only URL char model (skip enrich + operational)")
    ap.add_argument("--content-gate", action="store_true",
                    help="Run gated content analysis for gray-zone / commerce URLs")
    args = ap.parse_args()

    url_path = args.models_dir / "url_char_lr.joblib"
    op_path = args.models_dir / "hgb_operational.joblib"
    if not url_path.exists():
        print(f"Missing {url_path}", file=sys.stderr)
        return 1
    if not args.url_only and not op_path.exists():
        print(f"Missing {op_path}", file=sys.stderr)
        return 1

    urls = _read_urls(args.urls)
    if not urls:
        print("No URLs to score.", file=sys.stderr)
        return 1

    uh = joblib.load(url_path)

    if args.url_only:
        url_p = score_url_hash(uh, urls)
        print("url\turl_p\tdeploy_p")
        for u, p in zip(urls, url_p):
            print(f"{u}\t{p:.6f}\t{p:.6f}")
        return 0

    op_clf, op_cols, ref_card, max_cat = load_operational_bundle(op_path)

    # Enrich all URLs first so we can use final_url for URL model scoring
    # (URL shortener resolution: t.co/abc → https://phishing.xyz/paypal → score phishing.xyz URL)
    enriched: list[Any] = [None] * len(urls)

    def enrich_one(idx_url: tuple[int, str]) -> tuple[int, Any]:
        i, u = idx_url
        try:
            # Pre-resolve URL shorteners before full enrichment so that final_url
            # is available for the URL model and the operational model sees the
            # destination's real hostname features.
            resolved = resolve_short_url(u)
            if resolved:
                ed = enrich_url(resolved, args.feed_tag)
                if ed.final_url is None:
                    ed.final_url = resolved
                return i, ed
            return i, enrich_url(u, args.feed_tag)
        except Exception as e:
            return i, e

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {ex.submit(enrich_one, (i, u)): i for i, u in enumerate(urls)}
        for fut in as_completed(futs):
            i, result = fut.result()
            enriched[i] = result

    # Determine effective URL for URL model: use final_url when redirect crosses apex domain
    effective_urls = []
    for u, ed in zip(urls, enriched):
        if isinstance(ed, Exception) or ed is None:
            effective_urls.append(u)
        elif getattr(ed, "final_url", None) and _apex(ed.final_url) != _apex(u):
            effective_urls.append(ed.final_url)
        else:
            effective_urls.append(u)

    url_p = score_url_hash(uh, effective_urls)

    _NUMERIC_OP_COLS = frozenset({
        "asn", "latitude", "longitude", "http_status_code",
        "domain_age_days", "cert_age_days", "cert_validity_span_days",
        "title_brand_mismatch", "title_has_login_kw",
        "subdomain_depth", "subdomain_brand_count", "apex_is_numeric",
        "form_action_mismatch",
        "ip_in_url", "non_std_port", "url_domain_char_ratio",
        "favicon_domain_mismatch", "password_field_count", "has_hidden_redirect",
    })
    rows: list[dict[str, Any]] = []
    for u, ed in zip(urls, enriched):
        if isinstance(ed, Exception) or ed is None:
            row = {c: np.nan if c in _NUMERIC_OP_COLS else "" for c in op_cols}
        else:
            row = enrichment_to_operational_row(ed, columns=op_cols)
        rows.append(row)

    op_p = score_operational(op_clf, op_cols, ref_card, max_cat, rows)

    # When redirect resolution fails, effective_url == original shortener URL.
    # The URL model then sees the opaque code rather than the destination —
    # apply shortener-aware weighting to avoid FP from DGA-like codes.
    from fusion_kit.enrich import _SHORTENER_APEXES
    shortener_mask = np.array([
        _apex(u) in _SHORTENER_APEXES and eu == u
        for u, eu in zip(urls, effective_urls)
    ], dtype=bool)
    dep = fusion(url_p, op_p, mode=args.fusion,
                 shortener_mask=shortener_mask if shortener_mask.any() else None)

    # Optional content gate: re-score gray-zone / commerce URLs with HTML analysis
    gate_results: list[cgate.ContentGateResult] = []
    if args.content_gate:
        def gate_one(idx_url_fusion):
            i, u, f = idx_url_fusion
            return i, cgate.run(u, f, args.threshold)

        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
            futs = {ex.submit(gate_one, (i, u, float(d))): i
                    for i, (u, d) in enumerate(zip(effective_urls, dep))}
            gate_results = [None] * len(urls)
            for fut in as_completed(futs):
                i, gr = fut.result()
                gate_results[i] = gr

        # Apply content gate boost to deploy_p
        dep = [
            gr.boosted_fusion if (gr and gr.triggered) else d
            for gr, d in zip(gate_results, dep)
        ]
    else:
        gate_results = [None] * len(urls)

    header = "url\teffective_url\turl_p\top_p\tdeploy_p"
    if args.content_gate:
        header += "\tcg_triggered\tcg_score\tcg_signals"
    print(header)

    for u, eu, a, b, d, gr in zip(urls, effective_urls, url_p, op_p, dep, gate_results):
        redirected = "*" if eu != u else ""
        line = f"{u}\t{eu}{redirected}\t{a:.6f}\t{b:.6f}\t{d:.6f}"
        if args.content_gate and gr is not None:
            line += f"\t{int(gr.triggered)}\t{gr.content_score:.4f}\t{';'.join(gr.signals)}"
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
