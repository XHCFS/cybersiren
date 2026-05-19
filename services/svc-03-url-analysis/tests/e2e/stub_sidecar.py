#!/usr/bin/env python3
"""Stdlib-only stub of fusion_export/scripts/serve.py for e2e tests.

Implements the minimum surface the Go phishing client at
internal/phishing/client/client.go calls: GET /health, POST /score,
POST /score_one. Verdicts are deterministic from substrings in the URL so
the e2e cases are reproducible without any models on disk.

Run: python3 stub_sidecar.py --port 8765
"""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def verdict_for(url: str) -> tuple[float, str]:
    """Return (deploy_p, verdict) keyed on URL substrings."""
    low = url.lower()
    if "evil-phish" in low:
        return 0.92, "phishing"
    if "looks-bad" in low:
        return 0.85, "phishing"
    return 0.05, "benign"


def score_one(url: str) -> dict:
    deploy_p, verdict = verdict_for(url)
    return {
        "url": url,
        "effective_url": url,
        "url_p": deploy_p,
        "op_p": deploy_p,
        "deploy_p": deploy_p,
        "verdict": verdict,
    }


class StubHandler(BaseHTTPRequestHandler):
    def _send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict | None:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return None
        raw = self.rfile.read(length)
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return obj if isinstance(obj, dict) else None

    def do_GET(self) -> None:  # noqa: N802 (stdlib signature)
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "models_loaded": True})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 (stdlib signature)
        body = self._read_json()
        if body is None:
            self._send_json(400, {"error": "body must be a JSON object"})
            return

        if self.path == "/score":
            urls = body.get("urls", [])
            if not isinstance(urls, list):
                self._send_json(400, {"error": "urls must be a list"})
                return
            self._send_json(
                200,
                {
                    "results": [score_one(u) for u in urls if isinstance(u, str)],
                    "threshold": 0.50,
                    "fusion_mode": "mean",
                },
            )
            return

        if self.path == "/score_one":
            url = body.get("url", "")
            if not isinstance(url, str) or not url:
                self._send_json(400, {"error": "url is required"})
                return
            self._send_json(200, score_one(url))
            return

        self._send_json(404, {"error": "not found"})

    def log_message(self, fmt: str, *args) -> None:  # quieter than default
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Stub L2 fusion sidecar")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    httpd = ThreadingHTTPServer((args.host, args.port), StubHandler)
    print(f"[stub-sidecar] listening on http://{args.host}:{args.port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
