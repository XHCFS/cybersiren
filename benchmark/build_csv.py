"""Flatten the representative benchmark JSONL (+ aligned channel scores) into one
analysis-ready CSV. One row per email; headers parsed out; scores joined by index."""
import json, csv, re

JSONL = "benchmark/cybersiren_e2e_benchmark_representative.jsonl"
FEAT  = "benchmark/fusion_features.csv"
OUT   = "benchmark/cybersiren_e2e_benchmark_representative.csv"
LABEL_INT = {"legitimate": 0, "spam": 1, "phishing": 2}

feats = list(csv.DictReader(open(FEAT)))
rows  = [json.loads(l) for l in open(JSONL)]
assert len(rows) == len(feats), "score file not aligned with jsonl"

def auth(h, field):
    m = re.search(rf"{field}=(\w+)", h.get("Authentication-Results", "") if h else "")
    return m.group(1) if m else ""

def addr(frm):
    m = re.search(r"<([^>]+)>", frm or "")
    return m.group(1) if m else (frm or "")

COLS = [
    "id", "label", "label_int", "is_phishing", "difficulty", "family", "provenance",
    "clean_ood", "source_corpus", "channels_expected", "n_channels_expected",
    "subject", "body_plain", "body_html", "subject_len", "body_len",
    "has_url", "n_urls", "urls",
    "has_headers", "from_display", "from_addr", "from_domain", "reply_to",
    "return_path", "spf", "dkim", "dmarc", "auth_all_pass", "received_hops", "list_bulk",
    "nlp_score", "url_score", "header_score",
]

n = 0
with open(OUT, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=COLS, extrasaction="ignore")
    w.writeheader()
    for r, sc in zip(rows, feats):
        h = r.get("headers")
        frm = (h or {}).get("From", "")
        a = addr(frm)
        dom = a.split("@")[-1].lower() if "@" in a else ""
        spf, dkim, dmarc = auth(h, "spf"), auth(h, "dkim"), auth(h, "dmarc")
        recv = h.get("Received") if h else None
        urls = r.get("urls") or []
        ch = r.get("channels_expected") or []
        nlp = sc["nlp"]; url = sc["url"]; hdr = sc["header"]
        w.writerow({
            "id": r["id"], "label": r["label"], "label_int": LABEL_INT.get(r["label"], ""),
            "is_phishing": int(r["label"] == "phishing"),
            "difficulty": r.get("difficulty", ""), "family": r.get("family", ""),
            "provenance": r.get("provenance", ""), "clean_ood": int(bool(r.get("clean_ood"))),
            "source_corpus": r.get("source_corpus", ""),
            "channels_expected": "|".join(ch), "n_channels_expected": len(ch),
            "subject": r.get("subject", ""), "body_plain": r.get("body_plain", ""),
            "body_html": r.get("body_html") or "",
            "subject_len": len(r.get("subject", "") or ""), "body_len": len(r.get("body_plain", "") or ""),
            "has_url": int(bool(urls)), "n_urls": len(urls), "urls": "|".join(urls),
            "has_headers": int(h is not None),
            "from_display": frm.split("<")[0].strip() if frm else "",
            "from_addr": a, "from_domain": dom,
            "reply_to": addr((h or {}).get("Reply-To", "")) if h else "",
            "return_path": addr((h or {}).get("Return-Path", "")) if h else "",
            "spf": spf, "dkim": dkim, "dmarc": dmarc,
            "auth_all_pass": int(spf == "pass" and dkim == "pass" and dmarc == "pass") if h else "",
            "received_hops": len(recv) if isinstance(recv, list) else ("" if h is None else 1),
            "list_bulk": int(bool((h or {}).get("List-Unsubscribe"))) if h else "",
            "nlp_score": nlp,
            "url_score": "" if url in ("", "nan") else url,
            "header_score": "" if hdr in ("", "nan") else hdr,
        })
        n += 1
print(f"wrote {n} rows x {len(COLS)} cols -> {OUT}")
