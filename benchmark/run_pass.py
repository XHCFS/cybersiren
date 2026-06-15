#!/usr/bin/env python3
"""
run_pass.py — submit the representative subset through the live pipeline and read
back per-email verdict + ALL component scores from Postgres. One pass = one variant
(with-212 / without-212). Adapted from benchmark/fullpipe_eval.py.

Resource cap (user requirement: host CPU and RAM both < 80%):
  - RAM guard: back off while MemAvailable < --min-free-mb (default 6300MB ≈ keep
    >20% of 31GiB free), abort after sustained starvation.
  - CPU guard: before each batch, sample host CPU over 0.6s; while it is over
    --cpu-cap, sleep. Plus a low submit concurrency so the pipeline is paced.

Correlation: each email is submitted with Message-ID <bench-<label>-<id>@eval>;
svc-02 dedups + keys on the FIRST Message-ID, so a NEW --label per variant means
the second pass is not deduped against the first. Results are read by that prefix.
"""
import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PG = ["docker", "exec", "cybersiren-postgres", "psql", "-U", "postgres",
      "-d", "cybersiren", "-t", "-A", "-F", "\t", "-c"]


def psql(sql):
    return subprocess.run(PG + [sql], capture_output=True, text=True, timeout=120).stdout.strip()


def mem_available_mb():
    for line in open("/proc/meminfo"):
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) // 1024
    return 1 << 30


def _cpu_snap():
    p = open("/proc/stat").readline().split()[1:]
    v = list(map(int, p))
    idle = v[3] + v[4]
    return sum(v), idle


def cpu_pct(dt=0.6):
    t0, i0 = _cpu_snap()
    time.sleep(dt)
    t1, i1 = _cpu_snap()
    d, di = t1 - t0, i1 - i0
    return 100.0 * (d - di) / d if d else 0.0


def processed_count(label):
    out = psql(f"SELECT count(*) FROM emails WHERE message_id LIKE 'bench-{label}-%' "
               f"AND current_verdict_label IS NOT NULL;")
    try:
        return int(out)
    except ValueError:
        return 0


def sanitize_utf8(raw):
    try:
        raw.decode("utf-8")
        return raw
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace").encode("utf-8")


def submit(api, key, raw, msgid):
    body = (f"Message-ID: <{msgid}>\r\n").encode() + sanitize_utf8(raw)
    req = urllib.request.Request(f"{api.rstrip('/')}/api/v1/scan", data=body, method="POST")
    req.add_header("X-API-Key", key)
    req.add_header("Content-Type", "message/rfc822")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status in (200, 202)
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True, help="run tag, NEW per variant (e.g. with212)")
    ap.add_argument("--manifest", default=str(ROOT / "manifest.jsonl"),
                    help="manifest.jsonl to run; eml paths + output resolve next to it")
    ap.add_argument("--api", default="http://localhost:8081")
    ap.add_argument("--api-key", default="cs_demokey000000000000000000000DEMO")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--batch", type=int, default=60)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--min-free-mb", type=int, default=6300)
    ap.add_argument("--cpu-cap", type=float, default=78.0)
    ap.add_argument("--drain-timeout", type=int, default=1200)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    mani = Path(a.manifest).resolve()
    base = mani.parent
    recs = [json.loads(l) for l in mani.read_text().splitlines() if l.strip()]
    if a.limit:
        recs = recs[:a.limit]
    by_id = {r["id"]: r for r in recs}
    print(f"[{a.label}] {len(recs)} emails; batch={a.batch} workers={a.workers} "
          f"min_free={a.min_free_mb}MB cpu_cap={a.cpu_cap}%", file=sys.stderr)

    base_done = processed_count(a.label)
    submitted = sub_ok = sub_err = 0
    aborted = False
    t0 = time.time()

    def submit_one(r):
        raw = (base / r["eml_path"]).read_bytes()
        return submit(a.api, a.api_key, raw, f"bench-{a.label}-{r['id']}@eval")

    with ThreadPoolExecutor(max_workers=a.workers) as pool:
        for c in range(0, len(recs), a.batch):
            # RAM guard
            backoffs = 0
            while mem_available_mb() < a.min_free_mb:
                backoffs += 1
                print(f"[{a.label}] LOW MEM {mem_available_mb()}MB — backoff {backoffs}", file=sys.stderr)
                time.sleep(10)
                if backoffs >= 8:
                    print(f"[{a.label}] ABORT at {c}/{len(recs)} (sustained low mem)", file=sys.stderr)
                    aborted = True
                    break
            if aborted:
                break
            # CPU guard
            cguards = 0
            while True:
                cp = cpu_pct()
                if cp <= a.cpu_cap or cguards >= 30:
                    break
                cguards += 1
                print(f"[{a.label}] HIGH CPU {cp:.0f}% — wait {cguards}", file=sys.stderr)
                time.sleep(4)

            chunk = recs[c:c + a.batch]
            for ok in pool.map(submit_one, chunk):
                submitted += 1
                sub_ok += ok
                sub_err += (not ok)

            # pace: let the pipeline catch up to within one batch of backlog
            target = base_done + submitted - a.batch
            wait0 = time.time()
            while processed_count(a.label) < target and time.time() - wait0 < 240:
                time.sleep(2)
            done = processed_count(a.label) - base_done
            print(f"[{a.label}] submitted={submitted}/{len(recs)} processed={done} "
                  f"mem={mem_available_mb()}MB cpu={cpu_pct(0.3):.0f}% "
                  f"elapsed={int(time.time()-t0)}s", file=sys.stderr)

    # final drain
    print(f"[{a.label}] submitted {submitted} (ok={sub_ok} err={sub_err}); draining…", file=sys.stderr)
    dstart = time.time()
    last = -1
    stable = 0
    while time.time() - dstart < a.drain_timeout:
        done = processed_count(a.label) - base_done
        if done >= sub_ok:
            break
        stable = stable + 1 if done == last else 0
        if stable >= 20:
            print(f"[{a.label}] drain plateau at {done}/{sub_ok}", file=sys.stderr)
            break
        last = done
        time.sleep(4)
    done = processed_count(a.label) - base_done
    print(f"[{a.label}] drained {done}/{sub_ok} in {int(time.time()-dstart)}s", file=sys.stderr)

    # bulk-read verdict + ALL component scores
    rows = psql(
        "SELECT message_id, current_verdict_label, risk_score, content_risk_score, "
        "url_risk_score, header_risk_score, attachment_risk_score "
        f"FROM emails WHERE message_id LIKE 'bench-{a.label}-%';")
    out_rows = []
    matched = 0
    for line in rows.splitlines():
        p = line.split("\t")
        if len(p) < 2:
            continue
        mid = p[0]
        rid = mid[len(f"bench-{a.label}-"):].rsplit("@eval", 1)[0]
        rr = by_id.get(rid)
        if not rr or not p[1]:
            continue
        matched += 1

        def num(x):
            x = x.strip()
            if x == "" or x.lower() == "null":
                return None
            try:
                return int(x)
            except ValueError:
                try:
                    return float(x)
                except ValueError:
                    return None
        out_rows.append({
            "id": rid,
            "label": rr["label"],
            "is_phishing": rr["is_phishing"],
            "provenance": rr["provenance"],
            "clean_ood": rr["clean_ood"],
            "difficulty": rr["difficulty"],
            "family": rr["family"],
            "slice": rr["slice"],
            "channels_expected": rr["channels_expected"],
            "has_headers": rr["has_headers"],
            "has_url": rr["has_url"],
            "verdict": p[1],
            "risk_score": num(p[2]) if len(p) > 2 else None,
            "content_risk_score": num(p[3]) if len(p) > 3 else None,
            "url_risk_score": num(p[4]) if len(p) > 4 else None,
            "header_risk_score": num(p[5]) if len(p) > 5 else None,
            "attachment_risk_score": num(p[6]) if len(p) > 6 else None,
        })

    out = {
        "label": a.label,
        "submitted": submitted, "sub_ok": sub_ok, "sub_err": sub_err,
        "matched": matched, "aborted": aborted,
        "elapsed_s": round(time.time() - t0, 1),
        "rows": out_rows,
    }
    (base / a.out).write_text(json.dumps(out, indent=2))
    print(f"[{a.label}] DONE matched={matched}/{len(recs)} → {base / a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
