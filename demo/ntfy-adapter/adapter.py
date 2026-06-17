#!/usr/bin/env python3
"""Tiny ntfy adapter for svc-09 alerts.

svc-09's webhook channel POSTs its raw Alert JSON. Point NOTIFY_WEBHOOK_URL at this
service (http://ntfy-adapter:8099/alert) and it reformats each alert into a titled,
prioritised, tagged ntfy push, then reposts to NTFY_URL (an ntfy topic). Stdlib only.

Env:
  PORT      listen port (default 8099)
  NTFY_URL  ntfy topic URL to publish to (default https://ntfy.sh/cybersiren-cie21-alerts)
"""
import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NTFY_URL = os.environ.get("NTFY_URL", "https://ntfy.sh/cybersiren-cie21-alerts")
PORT = int(os.environ.get("PORT", "8099"))

# verdict_label -> (emoji, ntfy priority 1..5, ntfy tag)
STYLE = {
    "malware": ("\U0001FA9A", "5", "skull"),       # urgent
    "phishing": ("\U0001F3A3", "4", "warning"),    # high
    "suspicious": ("⚠️", "3", "warning"),
    "benign": ("✅", "2", "white_check_mark"),
}


def forward(alert):
    label = str(alert.get("verdict_label", "unknown")).lower()
    emoji, prio, tag = STYLE.get(label, ("❓", "3", "question"))
    risk = alert.get("risk_score", "?")
    conf = alert.get("confidence")
    eid = alert.get("email_id", "?")
    camp = alert.get("campaign_id")

    # NOTE: HTTP headers are latin-1, so X-Title must stay ASCII (no emoji/em-dash).
    # The emoji goes in the body (UTF-8) and severity shows via X-Tags / X-Priority.
    title = f"{label.upper()}: risk {risk}/100"
    lines = [f"{emoji} CyberSiren flagged an email as {label} (risk {risk}/100)."]
    if isinstance(conf, (int, float)):
        lines.append(f"Confidence: {conf:.0%}")
    if camp:
        lines.append(f"Campaign #{camp}")
    lines.append(f"email_id: {eid}")

    req = urllib.request.Request(NTFY_URL, data="\n".join(lines).encode(), method="POST")
    req.add_header("X-Title", title)
    req.add_header("X-Priority", prio)
    req.add_header("X-Tags", f"{tag},cybersiren")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b"{}"
        ok = False
        try:
            status = forward(json.loads(raw or b"{}"))
            ok = 200 <= status < 300
        except Exception as e:  # noqa: BLE001 - report any failure to svc-09 so it retries
            self.log_message("forward error: %s", e)
        self.send_response(200 if ok else 502)
        self.end_headers()
        self.wfile.write(b"ok" if ok else b"err")

    def do_GET(self):  # /healthz
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        print("[ntfy-adapter] " + (fmt % args), flush=True)


if __name__ == "__main__":
    print(f"[ntfy-adapter] listening :{PORT} -> {NTFY_URL}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
