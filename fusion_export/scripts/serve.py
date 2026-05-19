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
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import joblib
import numpy as np

# Prometheus instrumentation. Optional dependency — when the package is
# unavailable (lightweight sidecar builds, the e2e stub) the module falls back
# to no-op stand-ins so the rest of the server still works.
try:  # pragma: no cover - import guard
    from prometheus_client import (  # type: ignore
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )
    _PROM_AVAILABLE = True
except ImportError:  # pragma: no cover - import guard
    CONTENT_TYPE_LATEST = "text/plain"

    class _NoopMetric:
        def __init__(self, *_args, **_kwargs):
            pass

        def labels(self, *_a, **_kw):
            return self

        def inc(self, *_a, **_kw):
            pass

        def set(self, *_a, **_kw):
            pass

        def observe(self, *_a, **_kw):
            pass

    Counter = Gauge = Histogram = _NoopMetric  # type: ignore[misc,assignment]
    CollectorRegistry = object  # type: ignore[misc,assignment]

    def generate_latest(_registry=None):  # type: ignore[misc]
        return b"# prometheus_client not installed in this image\n"

    _PROM_AVAILABLE = False


_metric_registry = CollectorRegistry() if _PROM_AVAILABLE else None

_REQUESTS_TOTAL = Counter(
    "fusion_sidecar_requests_total",
    "Total HTTP requests handled by the L2 fusion sidecar.",
    ["method", "route", "code"],
    **({"registry": _metric_registry} if _PROM_AVAILABLE else {}),
)
_REQUEST_DURATION = Histogram(
    "fusion_sidecar_request_duration_seconds",
    "Per-request wall-clock duration handled by the L2 fusion sidecar.",
    ["route"],
    buckets=(0.005, 0.025, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 45.0),
    **({"registry": _metric_registry} if _PROM_AVAILABLE else {}),
)
_SCORE_OUTCOMES = Counter(
    "fusion_sidecar_scores_total",
    "Total per-URL scoring outcomes produced by the sidecar (sum across batch calls).",
    ["route", "verdict"],
    **({"registry": _metric_registry} if _PROM_AVAILABLE else {}),
)
_MODELS_LOADED = Gauge(
    "fusion_sidecar_models_loaded",
    "1 when the Scorer initialised cleanly (models + content gate ready), 0 otherwise.",
    **({"registry": _metric_registry} if _PROM_AVAILABLE else {}),
)


# ── OTEL tracing (OTLP/HTTP to Jaeger) ───────────────────────────────────
# Optional dependency stack — falls back to a no-op tracer if any of the
# OTEL packages are missing or OTEL_SDK_DISABLED=true. Endpoint is taken
# from OTEL_EXPORTER_OTLP_ENDPOINT (set on the compose service to
# http://jaeger:4318).
import os as _os  # noqa: E402  - kept local to keep the OTEL block isolated

_OTEL_ENABLED = False
try:  # pragma: no cover - import guard
    from opentelemetry import trace as _otel_trace  # type: ignore
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # type: ignore
        OTLPSpanExporter as _OTLPSpanExporter,
    )
    from opentelemetry.sdk.resources import Resource as _OTELResource  # type: ignore
    from opentelemetry.sdk.trace import TracerProvider as _TracerProvider  # type: ignore
    from opentelemetry.sdk.trace.export import (  # type: ignore
        BatchSpanProcessor as _BatchSpanProcessor,
    )

    _otel_endpoint = _os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if _otel_endpoint and _os.environ.get("OTEL_SDK_DISABLED", "").lower() != "true":
        _resource = _OTELResource.create({"service.name": "fusion-sidecar"})
        _provider = _TracerProvider(resource=_resource)
        _exporter = _OTLPSpanExporter(endpoint=_otel_endpoint.rstrip("/") + "/v1/traces")
        _provider.add_span_processor(_BatchSpanProcessor(_exporter))
        _otel_trace.set_tracer_provider(_provider)
        _OTEL_ENABLED = True
    _tracer = _otel_trace.get_tracer("fusion-sidecar")
except ImportError:  # pragma: no cover - import guard
    class _NoopSpan:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def set_attribute(self, *_a, **_kw):
            pass

        def record_exception(self, *_a, **_kw):
            pass

    class _NoopTracer:
        def start_as_current_span(self, *_args, **_kw):
            return _NoopSpan()

    _tracer = _NoopTracer()


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
                 content_gate: bool, workers: int, feed_tag: str, url_model: str):
        self.url_model = url_model
        self.fusion_mode = fusion_mode
        self.threshold = threshold
        self.content_gate = content_gate
        self.workers = workers
        self.feed_tag = feed_tag

        struct_path = models_dir / "url_struct_lgb.joblib"
        url_path    = models_dir / "url_char_lr.joblib"
        op_path = models_dir / "hgb_operational.joblib"

        if url_model == "structural" and struct_path.exists():
            self._struct = load_structural_scorer(struct_path)
            self._url_bundle = None
        else:
            self._struct = None
            self._url_bundle = joblib.load(url_path)

        self.op_clf, self.op_cols, self.ref_card, self.max_cat = load_operational_bundle(op_path)

    def score_features(self, requests_: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Score pre-computed feature rows (from Go enricher), bypassing re-enrichment.

        Each element of requests_ must have:
          "normalized_url"  – the (possibly redirect-resolved) URL string
          "is_shortener"    – bool, whether the apex is a known URL shortener
          "features"        – flat dict of enrichment features (Go FeatureVector keys)
        """
        if not requests_:
            return []

        norm_urls = [r.get("normalized_url", "") for r in requests_]
        shortener_mask = np.array([bool(r.get("is_shortener", False)) for r in requests_], dtype=bool)

        if self._struct is not None:
            url_p = self._struct.score(norm_urls)
        else:
            url_p = score_url_hash(self._url_bundle, norm_urls)

        rows = []
        for r in requests_:
            feat = r.get("features") or {}
            row: dict[str, Any] = {}
            for col in self.op_cols:
                row[col] = feat.get(col, np.nan if col in _NUMERIC_OP_COLS else "")
            rows.append(row)

        op_p = score_operational(self.op_clf, self.op_cols, self.ref_card, self.max_cat, rows)
        dep = fusion(url_p, op_p, mode=self.fusion_mode,
                     shortener_mask=shortener_mask if shortener_mask.any() else None)

        results = []
        for u, up, opp, dp in zip(norm_urls, url_p, op_p, dep):
            results.append({
                "url":       u,
                "url_p":     round(float(up),  6),
                "op_p":      round(float(opp), 6),
                "deploy_p":  round(float(dp),  6),
                "verdict":   "phishing" if dp >= self.threshold else "benign",
            })
        return results

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

    def _route_label(self) -> str:
        # Bound label cardinality: only known endpoints are reported by name,
        # everything else collapses to "other" so a 404 flood can't blow up
        # Prometheus's series count.
        known = {"/health", "/metrics", "/score", "/score_one", "/score-features"}
        return self.path if self.path in known else "other"

    def _send_metrics(self) -> None:
        body = generate_latest(_metric_registry) if _PROM_AVAILABLE else generate_latest(None)
        self.send_response(200)
        self.send_header("Content-Type", CONTENT_TYPE_LATEST)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _record(self, route: str, code: int, started_at: float) -> None:
        _REQUESTS_TOTAL.labels(self.command, route, str(code)).inc()
        _REQUEST_DURATION.labels(route).observe(time.perf_counter() - started_at)

    def _send_json(self, code: int, obj: Any) -> None:  # type: ignore[override]
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        # Remember the last status code so dispatchers can record metrics
        # without threading the value back through the call site.
        self._last_status = code

    def do_GET(self):
        started = time.perf_counter()
        route = self._route_label()
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "models_loaded": _scorer is not None})
        elif self.path == "/metrics":
            self._send_metrics()
            self._last_status = 200
        else:
            self._send_json(404, {"error": "not found"})
        self._record(route, getattr(self, "_last_status", 200), started)

    def do_POST(self):
        started = time.perf_counter()
        route = self._route_label()
        try:
            self._handle_post()
        finally:
            self._record(route, getattr(self, "_last_status", 500), started)

    def _handle_post(self) -> None:
        try:
            body = self._read_json()
        except Exception:
            self._send_json(400, {"error": "invalid JSON"})
            return

        # Guard non-object bodies (null, lists, scalars) before calling .get().
        if not isinstance(body, dict):
            self._send_json(400, {"error": "request body must be a JSON object"})
            return

        # No global lock around Scorer.score: models are loaded once at startup
        # and treated as read-only thereafter. The ThreadingHTTPServer below
        # gives us per-request threads; serializing them defeats the point.
        if self.path == "/score":
            urls = body.get("urls", [])
            if not isinstance(urls, list):
                self._send_json(400, {"error": "'urls' must be a list"})
                return
            if len(urls) > 500:
                self._send_json(400, {"error": "max 500 URLs per request"})
                return
            with _tracer.start_as_current_span("fusion.score") as sp:
                sp.set_attribute("fusion.batch_size", len(urls))
                sp.set_attribute("fusion.path", "score")
                results = _scorer.score(urls)
                self._annotate_span_with_first_result(sp, results)
            self._count_verdicts("/score", results)
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
            with _tracer.start_as_current_span("fusion.score_one") as sp:
                sp.set_attribute("fusion.path", "score_one")
                sp.set_attribute("fusion.url", url)
                results = _scorer.score([url])
                self._annotate_span_with_first_result(sp, results)
            self._count_verdicts("/score_one", results)
            self._send_json(200, results[0] if results else {})

        elif self.path == "/score-features":
            reqs = body.get("requests", [])
            if not isinstance(reqs, list):
                self._send_json(400, {"error": "'requests' must be a list"})
                return
            if len(reqs) > 500:
                self._send_json(400, {"error": "max 500 requests per call"})
                return
            with _tracer.start_as_current_span("fusion.score_features") as sp:
                sp.set_attribute("fusion.batch_size", len(reqs))
                sp.set_attribute("fusion.path", "score-features")
                results = _scorer.score_features(reqs)
                self._annotate_span_with_first_result(sp, results)
            self._count_verdicts("/score-features", results)
            self._send_json(200, {
                "results": results,
                "threshold": _scorer.threshold,
                "fusion_mode": _scorer.fusion_mode,
            })

        else:
            self._send_json(404, {"error": "not found"})

    @staticmethod
    def _annotate_span_with_first_result(sp, results) -> None:
        if not results:
            return
        first = results[0] if isinstance(results[0], dict) else None
        if first is None:
            return
        for key in ("verdict", "url_p", "op_p", "deploy_p"):
            if key in first:
                sp.set_attribute(f"fusion.{key}", first[key])

    @staticmethod
    def _count_verdicts(route: str, results: list[dict]) -> None:
        for r in results:
            verdict = r.get("verdict") if isinstance(r, dict) else None
            if verdict in ("phishing", "benign"):
                _SCORE_OUTCOMES.labels(route, verdict).inc()


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
    ap.add_argument("--url-model", choices=("char_lr", "structural"), default="char_lr",
                    help="URL-side model: char_lr (higher recall) or structural (lower FPR)")
    args = ap.parse_args()

    global _scorer
    print(f"Loading models from {args.models_dir} ...", flush=True)
    try:
        _scorer = Scorer(
            models_dir=args.models_dir,
            fusion_mode=args.fusion,
            threshold=args.threshold,
            content_gate=args.content_gate,
            workers=args.workers,
            feed_tag=args.feed_tag,
            url_model=args.url_model,
        )
    except Exception:
        _MODELS_LOADED.set(0)
        raise
    _MODELS_LOADED.set(1)
    print(f"Models loaded. url_model={_scorer.url_model} threshold={args.threshold} "
          f"fusion={args.fusion} content_gate={args.content_gate}", flush=True)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Listening on {args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
