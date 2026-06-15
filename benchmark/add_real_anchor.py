"""
Add the REAL-CORPUS generalization anchor to the synthetic stress benchmark.

Philosophy (per the deployment aspiration): the benchmark must be anchored in
*actually real corporate emails*, not only crafted cases. This pulls real emails
from the held-out splits of the source corpora:
  - Real corporate LEGIT: D7_Enron (real Enron internal mail) + D7_Ling + D1.
  - Real PHISHING: the `ood` split = real Nazario + Nigerian-419 held out of
    training (the honest out-of-distribution set), plus held-out D6/D4.
  - Real SPAM: D7_Assassin (SpamAssassin) + TREC/CEAS held-out.

Honesty / anti-leakage (the sin we refuse to repeat):
  Each real record is tagged with `split` and `clean_ood`. `clean_ood=True`
  (the `ood` split) is genuinely held out and is the leakage-free slice to report.
  Records from the `test` split are v1-held-out but their *source corpora* were
  (capped) inputs to v2 training — so treat them as "seen-distribution real,"
  not OOD. Consumers should report the synthetic + clean_ood slices for the
  honest number and use the rest for coverage.

These real records are body-only (the processed corpora dropped raw headers), so
they exercise the NLP channel (and URL where a link survives in the text). Full
multi-channel evaluation on real email needs raw .eml corpora (Nazario mbox /
SpamAssassin .eml) — the next acquisition step.

Run (after generate_e2e_benchmark.py):
    python benchmark/add_real_anchor.py
"""
import csv
import json
import random
import re
from collections import defaultdict
from pathlib import Path

csv.field_size_limit(10 ** 7)
random.seed(1337)

HERE = Path(__file__).parent
CSV = HERE.parent / "scratch_nlp_data" / "cybersiren_nlp_dataset_v1.csv"
SYN = HERE / "cybersiren_e2e_benchmark.jsonl"
OUT = HERE / "cybersiren_e2e_benchmark_full.jsonl"

LABEL = {"0": "legitimate", "1": "spam", "2": "phishing"}
URLRE = re.compile(r"https?://\S+|www\.\S+", re.I)

# how many real anchors per (label). PRIORITY = ordered source preference; we fill
# from the most deployment-relevant corpus first (real CORPORATE mail = Enron for legit).
TARGET = {"legitimate": 700, "phishing": 700, "spam": 500}
PRIORITY = {
    "legitimate": ["D7_Enron", "D7_Ling", "D1"],          # Enron = real corporate, first
    "phishing": ["D6_Nazario", "D6_Nigerian", "D4_human-generated", "D4_llm-generated", "D2"],
    "spam": ["D7_Assassin", "D7_TREC-07", "D7_CEAS-08", "D7_TREC-06", "D7_TREC-05"],
}

# bucket candidate rows: keep held-out only (test/ood); index by (label, source).
pool = defaultdict(lambda: defaultdict(list))   # label -> source -> [(clean_ood, text)]
with open(CSV, newline="") as f:
    for row in csv.DictReader(f):
        split = row["split"]
        if split not in ("test", "ood"):
            continue
        lab = LABEL.get(row["label"])
        if lab is None:
            continue
        pool[lab][row["source_dataset"]].append((split == "ood", row["text"]))


def parse(text):
    """'Subject: X\\n\\nBody: Y' -> (subject, body); fall back gracefully."""
    m = re.match(r"\s*Subject:\s*(.*?)\n\nBody:\s*(.*)$", text, re.S)
    if m:
        return m.group(1).strip()[:200], m.group(2).strip()
    m = re.match(r"\s*Subject:\s*(.*?)\n(.*)$", text, re.S)
    if m:
        return m.group(1).strip()[:200], m.group(2).strip()
    return "", text.strip()


_uid = [900000]
def real_record(lab, clean_ood, source, text):
    _uid[0] += 1
    subj, body = parse(text)
    urls = URLRE.findall(text)
    channels = []
    if lab == "phishing":
        channels = ["nlp"] + (["url"] if urls else [])
    return {
        "id": f"cse2e-real-{_uid[0]}",
        "label": lab,
        "difficulty": "real_ood" if clean_ood else "real_seen",
        "family": f"real::{source}",
        "channels_expected": channels,
        "provenance": "real",
        "source_corpus": source,
        "split": "ood" if clean_ood else "test",
        "clean_ood": clean_ood,          # True = leakage-free, honest slice
        "headers": None,                  # body-only corpus (raw headers not retained)
        "body_plain": body[:8000],
        "body_html": None,
        "urls": urls[:10],
    }


real = []
for lab, target in TARGET.items():
    remaining = target
    # 1) clean OOD first (leakage-free), across all sources
    ood_rows = [(s, t) for s, rows in pool[lab].items() for (c, t) in rows if c and len(t) > 25]
    random.shuffle(ood_rows)
    for source, text in ood_rows[:remaining]:
        real.append(real_record(lab, True, source, text)); remaining -= 1
    # 2) fill from `test` split in source-PRIORITY order (corporate corpus first)
    for source in PRIORITY[lab]:
        if remaining <= 0:
            break
        rows = [t for (c, t) in pool[lab].get(source, []) if not c and len(t) > 25]
        random.shuffle(rows)
        for text in rows[:remaining]:
            real.append(real_record(lab, False, source, text)); remaining -= 1

# tag synthetic records with provenance and merge
combined = []
for line in open(SYN):
    r = json.loads(line)
    r["provenance"] = "synthetic"
    r["clean_ood"] = False
    combined.append(r)
combined += real
random.shuffle(combined)
with open(OUT, "w") as f:
    for r in combined:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

# ── summary ──────────────────────────────────────────────────────────────────
from collections import Counter
prov = Counter(r["provenance"] for r in combined)
lab = Counter(r["label"] for r in combined)
prov_lab = Counter((r["provenance"], r["label"]) for r in combined)
clean = Counter(r["label"] for r in combined if r["clean_ood"])
realsrc = Counter(r.get("source_corpus") for r in combined if r["provenance"] == "real")
print(f"wrote {len(combined)} emails -> {OUT}")
print("provenance:", dict(prov))
print("label:     ", dict(lab))
print("provenance x label:", {f"{p}/{l}": c for (p, l), c in sorted(prov_lab.items())})
print("clean OOD (leakage-free) by label:", dict(clean))
print("real sources:", dict(realsrc))
# diversity on the real layer
rb = [r["body_plain"] for r in combined if r["provenance"] == "real"]
print(f"real bodies: {len(rb)}, unique {len(set(rb))}")
