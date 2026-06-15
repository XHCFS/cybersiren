#!/usr/bin/env python3
"""
build_subset.py — render a RANDOM, REPRESENTATIVE subset of
cybersiren_e2e_benchmark_representative.csv to RFC822 .eml files + a manifest.

Representative design (fixed seed → byte-reproducible):
  Stratify by `family` (each generator family = a distinct "case"). For every
  family draw n = clamp(round(RATE * size), FLOOR, CAP) rows without replacement
  (take all if size <= FLOOR). The CAP stops the one huge benign corpus (real::D1,
  4869 rows) from drowning the minority phishing/spam/adversarial families, so the
  subset spans ALL 25 families AND keeps enough phishing/spam for tight recall/FPR.

Rendering reuses the validated primitives in ../wholesys/build/common.py:
  - has_headers==1 (synthetic): full From/Reply-To/Return-Path/Authentication-
    Results/Received/List-* so svc-04 sees real header signals.
  - has_headers==0 (real, body-only): minimal neutral envelope so the row
    exercises NLP (+URL where a link survives), matching the body-only corpus.

Emits manifest.jsonl (one row/email) with label + slice + provenance/clean_ood/
difficulty/family/channels_expected so the analysis can split honest vs real_seen
and attribute per module.
"""
import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str((HERE.parent / "wholesys" / "build").resolve()))
import pandas as pd
import common as C

# defaults reproduce the original 1,238-email subset
SEED = 42
RATE = 0.15
FLOOR = 25
CAP = 200


def threat_type_for(label, family):
    if label == "spam":
        return "spam"
    if label != "phishing":
        return None
    f = (family or "").lower()
    if "bec" in f:
        return "bec"
    if "nigerian" in f or "419" in f or "advance" in f:
        return "advance_fee_fraud"
    if "url" in f or "nazario" in f or "obvious" in f or "phishy" in f or "spoof" in f:
        return "credential_harvesting"
    return "phishing"


def embed_urls(body: str, urls: list) -> str:
    extra = [u for u in urls if u and u not in body]
    if not extra:
        return body
    sep = "\n\n" if body.strip() else ""
    return body + sep + "\n".join(extra)


def select(df: pd.DataFrame, seed: int, rate: float, floor: int, cap: int) -> pd.DataFrame:
    rng = random.Random(seed)
    picks = []
    for fam, grp in df.groupby("family", sort=True):
        size = len(grp)
        n = size if size <= floor else max(floor, min(cap, round(rate * size)))
        idx = list(grp.index)
        rng.shuffle(idx)
        picks.extend(idx[:n])
    return df.loc[sorted(picks)]


def main():
    ap = argparse.ArgumentParser(description="render a stratified representative subset of the CSV")
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--rate", type=float, default=RATE, help="per-family sampling rate")
    ap.add_argument("--floor", type=int, default=FLOOR, help="min rows per family")
    ap.add_argument("--cap", type=int, default=CAP, help="max rows per family")
    ap.add_argument("--outdir", default=str(HERE),
                    help="output dir (manifest.jsonl + corpus/ written here)")
    a = ap.parse_args()

    outdir = Path(a.outdir).resolve()
    corpus = outdir / "corpus"
    df = pd.read_csv(C.CSV_PATH, dtype=str, keep_default_na=False)
    sub = select(df, a.seed, a.rate, a.floor, a.cap)
    print(f"selected {len(sub)} / {len(df)} rows  (seed={a.seed} rate={a.rate} "
          f"floor={a.floor} cap={a.cap}) -> {outdir}", file=sys.stderr)

    manifest = []
    for i, r in enumerate(sub.itertuples(index=False)):
        d = r._asdict()
        src_id = d["id"]
        bid = f"rb-{src_id}"
        bucket = f"{i // 500:03d}"
        rel = f"corpus/{bucket}/{bid}.eml"

        label = d["label"]
        is_phish = 1 if d["is_phishing"] == "1" else 0
        has_headers = d["has_headers"] == "1"
        has_url = d["has_url"] == "1"
        provenance = d["provenance"]
        clean_ood = 1 if d["clean_ood"] == "1" else 0
        difficulty = d["difficulty"]
        family = d["family"]
        channels = d["channels_expected"]
        urls = [u for u in d["urls"].split("|") if u] if has_url else []
        body = embed_urls(d["body_plain"], urls)
        subject = d["subject"]
        mid = f"<{bid}@cybersiren-bench.invalid>"
        slice_name = "honest" if (provenance == "synthetic" or clean_ood == 1) else "real_seen"

        if has_headers:
            spf, dkim, dmarc = d["spf"], d["dkim"], d["dmarc"]
            hop = int(d["received_hops"]) if d["received_hops"] else 0
            list_bulk = d["list_bulk"] == "1"
            ar = C.build_auth_results(spf, dkim, dmarc, mailfrom=d["from_domain"])
            eml = C.render_eml(
                subject=subject, body=body,
                from_display=d["from_display"], from_addr=d["from_addr"],
                reply_to=d["reply_to"], return_path=d["return_path"],
                auth_results=ar, received_hops=hop, list_bulk=list_bulk,
                message_id=mid, idx=i,
            )
        else:
            eml = C.render_eml(
                subject=subject, body=body,
                from_addr="sender@mail.example.com",
                message_id=mid, idx=i,
            )

        out = corpus / bucket / f"{bid}.eml"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(eml)

        coverage = ["nlp"]
        if has_url:
            coverage.append("url")
        if has_headers:
            coverage.append("header")

        manifest.append({
            "id": bid,
            "src_id": src_id,
            "eml_path": rel,
            "label": label,                 # legitimate | spam | phishing  (ground truth)
            "label_int": int(d["label_int"]),
            "is_phishing": is_phish,
            "provenance": provenance,
            "clean_ood": clean_ood,
            "difficulty": difficulty,
            "family": family,
            "slice": slice_name,            # honest | real_seen
            "channels_expected": channels,
            "has_headers": int(has_headers),
            "has_url": int(has_url),
            "n_urls": int(d["n_urls"]) if d["n_urls"] else 0,
            "threat_type": threat_type_for(label, family),
            "coverage": coverage,
        })

    (outdir / "manifest.jsonl").write_text("".join(json.dumps(m) + "\n" for m in manifest))

    # composition report
    by_label = Counter(m["label"] for m in manifest)
    by_slice = Counter(m["slice"] for m in manifest)
    by_diff = Counter(m["difficulty"] for m in manifest)
    print("== subset composition ==", file=sys.stderr)
    print("label:", dict(by_label), file=sys.stderr)
    print("slice:", dict(by_slice), file=sys.stderr)
    print("difficulty:", dict(by_diff), file=sys.stderr)
    print("families:", len(set(m["family"] for m in manifest)), file=sys.stderr)
    print(f"manifest → {outdir/'manifest.jsonl'} ({len(manifest)} rows)", file=sys.stderr)


if __name__ == "__main__":
    main()
