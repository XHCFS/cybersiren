"""Regression tests for the L2 fusion HTTP sidecar request handler.

These drive a real ThreadingHTTPServer on loopback with a stub Scorer so we
can assert that malformed input and scorer failures produce a proper HTTP
status (4xx/5xx) instead of an unhandled exception that drops the connection.
"""
from __future__ import annotations

import http.client
import json
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

# scripts/serve.py is not an installable package; put it on the path.
_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import serve  # noqa: E402


class _StubScorer:
    """Minimal stand-in for Scorer.

    score()/score_features() either echo a benign verdict or raise, depending
    on `boom`, so we can exercise both the happy path and the error boundary
    without loading any ML model.
    """

    threshold = 0.5
    fusion_mode = "mean"

    def __init__(self, boom: bool = False):
        self.boom = boom

    def score(self, urls):
        if self.boom:
            raise RuntimeError("synthetic scorer failure")
        return [{"url": u, "verdict": "benign", "url_p": 0.0,
                 "op_p": 0.0, "deploy_p": 0.0} for u in urls]

    def score_features(self, reqs):
        if self.boom:
            raise RuntimeError("synthetic scorer failure")
        return [{"url": r.get("normalized_url", ""), "verdict": "benign",
                 "url_p": 0.0, "op_p": 0.0, "deploy_p": 0.0} for r in reqs]


class _ServerFixture:
    """Spin up the real Handler on an ephemeral loopback port."""

    def __init__(self, scorer):
        self._prev = serve._scorer
        serve._scorer = scorer
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), serve.Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        serve._scorer = self._prev

    def post(self, path, body, raw=False, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        payload = body if raw else json.dumps(body)
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        conn.request("POST", path, payload, hdrs)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data


class TestHandlerErrorBoundaries(unittest.TestCase):
    def _server(self, boom=False):
        fx = _ServerFixture(_StubScorer(boom=boom))
        self.addCleanup(fx.close)
        return fx

    # ── Finding: scorer exceptions must become a 500, not a dropped socket ──
    def test_scorer_failure_returns_500_not_dropped_connection(self):
        fx = self._server(boom=True)
        status, body = fx.post("/score", {"urls": ["http://example.com"]})
        self.assertEqual(status, 500)
        self.assertIn(b"scoring failed", body)

    def test_score_one_scorer_failure_returns_500(self):
        fx = self._server(boom=True)
        status, body = fx.post("/score_one", {"url": "http://example.com"})
        self.assertEqual(status, 500)
        self.assertIn(b"scoring failed", body)

    def test_score_features_scorer_failure_returns_500(self):
        fx = self._server(boom=True)
        status, body = fx.post("/score-features",
                               {"requests": [{"normalized_url": "http://x"}]})
        self.assertEqual(status, 500)
        self.assertIn(b"scoring failed", body)

    # ── Finding: non-string url elements must be rejected with 400 ──────────
    def test_score_rejects_non_string_url_elements(self):
        fx = self._server()
        for bad in ([123], [None], [["nested"]], [True]):
            with self.subTest(bad=bad):
                status, body = fx.post("/score", {"urls": bad})
                self.assertEqual(status, 400)
                self.assertIn(b"string", body)

    def test_score_accepts_string_urls(self):
        fx = self._server()
        status, _ = fx.post("/score", {"urls": ["http://example.com"]})
        self.assertEqual(status, 200)

    # ── Finding: /score_one must require a non-empty string ─────────────────
    def test_score_one_rejects_non_string_url(self):
        fx = self._server()
        for bad in (123, True, ["http://x"], {"u": 1}):
            with self.subTest(bad=bad):
                status, body = fx.post("/score_one", {"url": bad})
                self.assertEqual(status, 400)
                self.assertIn(b"non-empty string", body)

    def test_score_one_rejects_empty_url(self):
        fx = self._server()
        status, _ = fx.post("/score_one", {"url": ""})
        self.assertEqual(status, 400)

    # ── Finding: /score-features must reject non-dict elements ──────────────
    def test_score_features_rejects_non_dict_elements(self):
        fx = self._server()
        status, body = fx.post("/score-features",
                               {"requests": [{"normalized_url": "http://x"}, 1, None]})
        self.assertEqual(status, 400)
        self.assertIn(b"JSON object", body)

    # ── Finding: oversized Content-Length must be rejected with 413 ─────────
    def test_oversized_body_returns_413(self):
        fx = self._server()
        # Declare an over-cap Content-Length but send only a small body, so the
        # handler rejects on the header before reading. (A truly multi-GB body
        # would be capped the same way; we don't allocate it here.)
        big = serve._MAX_BODY_BYTES + 1
        conn = http.client.HTTPConnection("127.0.0.1", fx.port, timeout=5)
        conn.putrequest("POST", "/score")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(big))
        conn.endheaders()
        # Send far less than declared; the server must not block waiting for the
        # full Content-Length and must answer 413.
        conn.send(b'{"urls": []}')
        resp = conn.getresponse()
        status = resp.status
        resp.read()
        conn.close()
        self.assertEqual(status, 413)

    def test_read_json_caps_oversized_content_length(self):
        # Unit-level guard: _read_json returns the too-large sentinel without
        # reading the body when Content-Length exceeds the cap.
        handler = serve.Handler.__new__(serve.Handler)
        handler.headers = {"Content-Length": str(serve._MAX_BODY_BYTES + 1)}

        class _ExplodingReader:
            def read(self, *_a):
                raise AssertionError("body must not be read once over the cap")

        handler.rfile = _ExplodingReader()
        self.assertIs(handler._read_json(), serve._BodyTooLarge)

    def test_within_cap_body_is_processed(self):
        fx = self._server()
        status, _ = fx.post("/score", {"urls": ["http://example.com"]})
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
