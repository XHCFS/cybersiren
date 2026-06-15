#!/usr/bin/env python3
"""capture_rich.py — live pass that captures the 4 numeric channel scores AND the
rich svc-06 NLP signals (facets / classification / confidence / phishing_probability),
which are only on the emails.scored Kafka topic, never persisted to Postgres.

Flow:
  1. submit manifest emails (Message-ID = bench-<label>-<id>@eval), paced + RAM/CPU guarded
  2. drain until processed
  3. DB read: internal_id + verdict + 4 channel scores (keyed by message_id prefix)
  4. consume emails.scored (-o start:end), parse component_details.nlp.details per internal_id
  5. join on internal_id, write big/raw_rich_<label>.json with all signals per bench id

Reuses the submission/guard logic of run_pass.py. spam_probability is reconstructed as
max(0, content_risk_score/100 - phishing_probability) since svc-06 doesn't forward it.
"""
import argparse, json, subprocess, sys, time, urllib.error, urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PG = ["docker", "exec", "cybersiren-postgres", "psql", "-U", "postgres",
      "-d", "cybersiren", "-t", "-A", "-F", "\t", "-c"]


def psql(sql):
    return subprocess.run(PG + [sql], capture_output=True, text=True, timeout=180).stdout.strip()


def mem_available_mb():
    for line in open("/proc/meminfo"):
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) // 1024
    return 1 << 30


def _cpu_snap():
    v = list(map(int, open("/proc/stat").readline().split()[1:]))
    return sum(v), v[3] + v[4]


def cpu_pct(dt=0.6):
    t0, i0 = _cpu_snap(); time.sleep(dt); t1, i1 = _cpu_snap()
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
        raw.decode("utf-8"); return raw
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace").encode("utf-8")


def submit(api, key, raw, msgid):
    body = (f"Message-ID: <{msgid}>\r\n").encode() + sanitize_utf8(raw)
    req = urllib.request.Request(f"{api.rstrip('/')}/api/v1/scan", data=body, method="POST")
    req.add_header("X-API-Key", key); req.add_header("Content-Type", "message/rfc822")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status in (200, 202)
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def topic_total(topic):
    """Sum of (high_watermark - log_start) across partitions = records available now."""
    out = subprocess.run(["docker", "exec", "cybersiren-redpanda", "rpk", "topic", "describe",
                          topic, "-p"], capture_output=True, text=True, timeout=60).stdout
    total = 0
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[0].isdigit():
            try:
                logstart = int(parts[-2]); hw = int(parts[-1]); total += max(0, hw - logstart)
            except ValueError:
                continue
    return total


def consume_nlp_details(internal_ids):
    """Consume the whole emails.scored topic (-o start -n total); return iid->nlp dict (latest)."""
    want = set(internal_ids)
    total = topic_total("emails.scored")
    print(f"[consume] emails.scored has ~{total} records; reading from start", file=sys.stderr)
    proc = subprocess.Popen(
        ["docker", "exec", "cybersiren-redpanda", "rpk", "topic", "consume",
         "emails.scored", "-o", "start", "-n", str(total), "-f", "%v\n"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1 << 20)
    by_iid = {}
    seen = 0
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        seen += 1
        try:
            v = json.loads(line)
        except json.JSONDecodeError:
            continue
        iid = v.get("internal_id")
        if iid not in want:
            continue
        nlp_raw = (v.get("component_details") or {}).get("nlp")
        if not nlp_raw:
            by_iid[iid] = {"nlp_score": v.get("nlp_score")}
            continue
        try:
            n = json.loads(nlp_raw) if isinstance(nlp_raw, str) else nlp_raw
        except json.JSONDecodeError:
            continue
        d = n.get("details") or {}
        fac = d.get("facets") or {}
        phish = d.get("phishing_probability")
        nlp_score = n.get("score")
        spam = None
        if phish is not None and nlp_score is not None:
            spam = max(0.0, nlp_score / 100.0 - float(phish))
        by_iid[iid] = {  # latest write wins (topic is in offset order)
            "nlp_score": nlp_score,
            "classification": d.get("classification"),
            "confidence": d.get("confidence"),
            "phishing_probability": phish,
            "spam_probability": spam,
            "intent_label": d.get("intent_label") or fac.get("intent_label"),
            "intent_confidence": d.get("intent_confidence") or fac.get("intent_confidence"),
            "intent_labels": d.get("intent_labels"),
            "urgency_score": d.get("urgency_score") if d.get("urgency_score") is not None else fac.get("urgency_score"),
            "impersonation_score": fac.get("impersonation_score"),
            "impersonated_brand": fac.get("impersonated_brand"),
            "deception_score": fac.get("deception_score"),
            "obfuscation_detected": d.get("obfuscation_detected"),
        }
    proc.wait()
    print(f"[consume] scanned {seen} scored msgs, matched {len(by_iid)}/{len(want)} internal_ids",
          file=sys.stderr)
    return by_iid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--manifest", default=str(ROOT / "big" / "manifest.jsonl"))
    ap.add_argument("--api", default="http://localhost:8081")
    ap.add_argument("--api-key", default="cs_demokey000000000000000000000DEMO")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--batch", type=int, default=60)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--min-free-mb", type=int, default=4000)
    ap.add_argument("--cpu-cap", type=float, default=85.0)
    ap.add_argument("--drain-timeout", type=int, default=1800)
    ap.add_argument("--out", required=True)
    ap.add_argument("--skip-submit", action="store_true", help="reuse existing DB rows for this label")
    a = ap.parse_args()

    mani = Path(a.manifest).resolve(); base = mani.parent
    recs = [json.loads(l) for l in mani.read_text().splitlines() if l.strip()]
    if a.limit:
        recs = recs[:a.limit]
    by_id = {r["id"]: r for r in recs}
    print(f"[{a.label}] {len(recs)} emails", file=sys.stderr)
    t0 = time.time()
    submitted = sub_ok = 0

    if not a.skip_submit:
        base_done = processed_count(a.label)

        def submit_one(r):
            raw = (base / r["eml_path"]).read_bytes()
            return submit(a.api, a.api_key, raw, f"bench-{a.label}-{r['id']}@eval")

        with ThreadPoolExecutor(max_workers=a.workers) as pool:
            for c in range(0, len(recs), a.batch):
                bo = 0
                while mem_available_mb() < a.min_free_mb:
                    bo += 1; print(f"[{a.label}] LOW MEM {mem_available_mb()}MB backoff {bo}", file=sys.stderr)
                    time.sleep(10)
                    if bo >= 10:
                        print(f"[{a.label}] ABORT low mem at {c}", file=sys.stderr); break
                cg = 0
                while cg < 30:
                    cp = cpu_pct()
                    if cp <= a.cpu_cap:
                        break
                    cg += 1; print(f"[{a.label}] HIGH CPU {cp:.0f}% wait {cg}", file=sys.stderr); time.sleep(4)
                chunk = recs[c:c + a.batch]
                for ok in pool.map(submit_one, chunk):
                    submitted += 1; sub_ok += ok
                target = base_done + submitted - a.batch
                w0 = time.time()
                while processed_count(a.label) < target and time.time() - w0 < 300:
                    time.sleep(2)
                done = processed_count(a.label) - base_done
                print(f"[{a.label}] submitted={submitted}/{len(recs)} processed={done} "
                      f"mem={mem_available_mb()}MB elapsed={int(time.time()-t0)}s", file=sys.stderr)

        # drain
        dstart = time.time(); last = -1; stable = 0
        while time.time() - dstart < a.drain_timeout:
            done = processed_count(a.label) - base_done
            if done >= sub_ok:
                break
            stable = stable + 1 if done == last else 0
            if stable >= 25:
                print(f"[{a.label}] drain plateau {done}/{sub_ok}", file=sys.stderr); break
            last = done; time.sleep(4)
        print(f"[{a.label}] drained in {int(time.time()-dstart)}s", file=sys.stderr)

    # DB read incl internal_id
    rows = psql(
        "SELECT internal_id, message_id, current_verdict_label, risk_score, content_risk_score, "
        "url_risk_score, header_risk_score, attachment_risk_score "
        f"FROM emails WHERE message_id LIKE 'bench-{a.label}-%';")

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

    db = {}  # rid -> (internal_id, dbfields)
    for line in rows.splitlines():
        p = line.split("\t")
        if len(p) < 3 or not p[2]:
            continue
        iid = int(p[0])
        mid = p[1]
        rid = mid[len(f"bench-{a.label}-"):].rsplit("@eval", 1)[0]
        if rid not in by_id:
            continue
        db[rid] = (iid, {
            "verdict": p[2],
            "risk_score": num(p[3]) if len(p) > 3 else None,
            "content_risk_score": num(p[4]) if len(p) > 4 else None,
            "url_risk_score": num(p[5]) if len(p) > 5 else None,
            "header_risk_score": num(p[6]) if len(p) > 6 else None,
            "attachment_risk_score": num(p[7]) if len(p) > 7 else None,
        })
    print(f"[{a.label}] DB matched {len(db)}/{len(recs)}", file=sys.stderr)

    # consume facets keyed by internal_id
    iid_to_rid = {iid: rid for rid, (iid, _) in db.items()}
    nlp_by_iid = consume_nlp_details(set(iid_to_rid))

    out_rows = []
    for rid, (iid, f) in db.items():
        r = by_id[rid]
        nlp = nlp_by_iid.get(iid, {})
        row = {
            "id": rid, "internal_id": iid,
            "label": r["label"], "is_phishing": r["is_phishing"], "provenance": r["provenance"],
            "clean_ood": r["clean_ood"], "difficulty": r["difficulty"], "family": r["family"],
            "slice": r["slice"], "has_headers": r["has_headers"], "has_url": r["has_url"],
        }
        row.update(f)        # verdict + 4 channel scores
        row.update({k: nlp.get(k) for k in (
            "classification", "confidence", "phishing_probability", "spam_probability",
            "intent_label", "intent_confidence", "intent_labels", "urgency_score",
            "impersonation_score", "impersonated_brand", "deception_score", "obfuscation_detected")})
        out_rows.append(row)

    out = {"label": a.label, "n": len(out_rows), "elapsed_s": round(time.time() - t0, 1), "rows": out_rows}
    (ROOT / a.out).write_text(json.dumps(out, indent=2))
    matched_facets = sum(1 for r in out_rows if r.get("classification") is not None)
    print(f"[{a.label}] DONE rows={len(out_rows)} facets_matched={matched_facets} → {ROOT / a.out}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
