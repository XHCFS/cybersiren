#!/usr/bin/env python3
"""
Thin HTTP sidecar: exposes the fusion scorer as a JSON API.

Designed to run alongside a Go service. The Go service POSTs URLs here
and receives phishing verdicts. No external dependencies beyond those
already in requirements.txt.

Usage:
  python scripts/serve.py --port 8765 --workers 6
  python scripts/serve.py --port 8765 --content-gate --threshold 0.50

API:
  POST /score
  Content-Type: application/json
  Body: {"urls": ["https://example.com", ...]}

  Response 200:
  {
    "results": [
      {
        "url":        "https://example.com",
        "url_p":      0.003,
        "op_p":       0.001,
        "deploy_p":   0.002,
        "verdict":    "benign",
        "cg_triggered": false,
        "cg_score":   0.0,
        "cg_signals": []
      },
      ...
    ],
    "threshold": 0.35,
    "fusion_mode": "mean"
  }

  POST /score_one        (convenience single-URL endpoint)
  Body: {"url": "https://example.com"}
  Response: single result object (same fields as above)

  GET  /health           (liveness probe)
  Response: {"status": "ok", "models_loaded": true}
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fusion_kit.enrich import _SHORTENER_APEXES, enrich_url, resolve_short_url  # noqa: E402
from fusion_kit.operational import enrichment_to_operational_row  # noqa: E402
from fusion_kit.scoring import (  # noqa: E402
    fusion,
    load_operational_bundle,
    score_operational,
    score_url_hash,
)
from fusion_kit.url_struct import load_structural_scorer  # noqa: E402
from fusion_kit import content_gate as cgate  # noqa: E402

_NUMERIC_OP_COLS = frozenset({
    "asn", "latitude", "longitude", "http_status_code",
    "domain_age_days", "cert_age_days", "cert_validity_span_days",
    "title_brand_mismatch", "title_has_login_kw",
    "subdomain_depth", "subdomain_brand_count", "apex_is_numeric",
    "form_action_mismatch", "ip_in_url", "non_std_port",
    "url_domain_char_ratio", "favicon_domain_mismatch",
    "password_field_count", "has_hidden_redirect",
})


def _apex(url: str) -> str:
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


class Scorer:
    def __init__(self, models_dir: Path, fusion_mode: str, threshold: float,
                 content_gate: bool, workers: int, feed_tag: str):
        self.fusion_mode = fusion_mode
        self.threshold = threshold
        self.content_gate = content_gate
        self.workers = workers
        self.feed_tag = feed_tag

        struct_path = models_dir / "url_struct_lgb.joblib"
        url_path = models_dir / "url_char_lr.joblib"
        op_path = models_dir / "hgb_operational.joblib"

        if struct_path.exists():
            self._struct = load_structural_scorer(struct_path)
            self._url_bundle = None
        else:
            self._struct = None
            self._url_bundle = joblib.load(url_path)

        self.op_clf, self.op_cols, self.ref_card, self.max_cat = load_operational_bundle(op_path)

    def score(self, urls: list[str]) -> list[dict[str, Any]]:
        if not urls:
            return []

        enriched: list[Any] = [None] * len(urls)

        def enrich_one(idx_url):
            i, u = idx_url
            try:
                resolved = resolve_short_url(u)
                if resolved:
                    ed = enrich_url(resolved, self.feed_tag)
                    if ed.final_url is None:
                        ed.final_url = resolved
                    return i, ed
                return i, enrich_url(u, self.feed_tag)
            except Exception as e:
                return i, e

        with ThreadPoolExecutor(max_workers=max(1, self.workers)) as ex:
            futs = {ex.submit(enrich_one, (i, u)): i for i, u in enumerate(urls)}
            for fut in as_completed(futs):
                i, result = fut.result()
                enriched[i] = result

        effective_urls = []
        for u, ed in zip(urls, enriched):
            if isinstance(ed, Exception) or ed is None:
                effective_urls.append(u)
            elif getattr(ed, "final_url", None) and _apex(ed.final_url) != _apex(u):
                effective_urls.append(ed.final_url)
            else:
                effective_urls.append(u)

        if self._struct is not None:
            url_p = self._struct.score(effective_urls)
        else:
            url_p = score_url_hash(self._url_bundle, effective_urls)

        rows = []
        for u, ed in zip(urls, enriched):
            if isinstance(ed, Exception) or ed is None:
                row = {c: np.nan if c in _NUMERIC_OP_COLS else "" for c in self.op_cols}
            else:
                row = enrichment_to_operational_row(ed, columns=self.op_cols)
            rows.append(row)

        op_p = score_operational(self.op_clf, self.op_cols, self.ref_card, self.max_cat, rows)

        # Apply shortener-aware fusion for unresolved shortener URLs.
        shortener_mask = np.array([
            _apex(u) in _SHORTENER_APEXES and eu == u
            for u, eu in zip(urls, effective_urls)
        ], dtype=bool)
        dep = fusion(url_p, op_p, mode=self.fusion_mode,
                     shortener_mask=shortener_mask if shortener_mask.any() else None)

        gate_results: list[Any] = [None] * len(urls)
        if self.content_gate:
            def gate_one(args):
                i, u, f = args
                return i, cgate.run(u, f, self.threshold)

            with ThreadPoolExecutor(max_workers=max(1, self.workers)) as ex:
                futs = {ex.submit(gate_one, (i, u, float(d))): i
                        for i, (u, d) in enumerate(zip(effective_urls, dep))}
                for fut in as_completed(futs):
                    i, gr = fut.result()
                    gate_results[i] = gr

            dep = [
                gr.boosted_fusion if (gr and gr.triggered) else d
                for gr, d in zip(gate_results, dep)
            ]

        results = []
        for u, eu, up, opp, dp, gr in zip(urls, effective_urls, url_p, op_p, dep, gate_results):
            r: dict[str, Any] = {
                "url": u,
                "effective_url": eu,
                "url_p": round(float(up), 6),
                "op_p": round(float(opp), 6),
                "deploy_p": round(float(dp), 6),
                "verdict": "phishing" if dp >= self.threshold else "benign",
            }
            if self.content_gate:
                r["cg_triggered"] = bool(gr.triggered) if gr else False
                r["cg_score"] = round(gr.content_score, 4) if gr else 0.0
                r["cg_signals"] = gr.signals if gr else []
            results.append(r)
        return results


_scorer: Scorer | None = None
_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress default per-request stdout noise

    def _send_json(self, code: int, obj: Any) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Any:
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length))

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "models_loaded": _scorer is not None})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        try:
            body = self._read_json()
        except Exception:
            self._send_json(400, {"error": "invalid JSON"})
            return

        if self.path == "/score":
            urls = body.get("urls", [])
            if not isinstance(urls, list):
                self._send_json(400, {"error": "'urls' must be a list"})
                return
            if len(urls) > 500:
                self._send_json(400, {"error": "max 500 URLs per request"})
                return
            with _lock:
                results = _scorer.score(urls)
            self._send_json(200, {
                "results": results,
                "threshold": _scorer.threshold,
                "fusion_mode": _scorer.fusion_mode,
            })

        elif self.path == "/score_one":
            url = body.get("url", "")
            if not url:
                self._send_json(400, {"error": "'url' is required"})
                return
            with _lock:
                results = _scorer.score([url])
            self._send_json(200, results[0] if results else {})

        else:
            self._send_json(404, {"error": "not found"})


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", type=str, default="127.0.0.1")
    ap.add_argument("--models-dir", type=Path, default=ROOT / "models")
    ap.add_argument("--fusion", choices=("max", "mean"), default="mean")
    ap.add_argument("--threshold", type=float, default=0.50)
    ap.add_argument("--content-gate", action="store_true")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--feed-tag", type=str, default="fusion_sidecar")
    args = ap.parse_args()

    global _scorer
    print(f"Loading models from {args.models_dir} ...", flush=True)
    _scorer = Scorer(
        models_dir=args.models_dir,
        fusion_mode=args.fusion,
        threshold=args.threshold,
        content_gate=args.content_gate,
        workers=args.workers,
        feed_tag=args.feed_tag,
    )
    url_model = "structural_lgb" if _scorer._struct is not None else "url_char_lr"
    print(f"Models loaded. url_model={url_model} threshold={args.threshold} "
          f"fusion={args.fusion} content_gate={args.content_gate}", flush=True)

    server = HTTPServer((args.host, args.port), Handler)
    print(f"Listening on {args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
