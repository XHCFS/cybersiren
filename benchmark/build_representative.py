"""
Assemble the REPRESENTATIVE CyberSiren benchmark: legit-dominated, like a real
post-filter corporate inbox (~85% legit / 5% spam / 10% phishing — the realistic
validation mix documented in the NLP spec). Real emails are the backbone; the
synthetic stress cases are a labeled minority that supplies the hard FP/FN /
adversarial / channel-isolation coverage real corpora can't.

Output: benchmark/cybersiren_e2e_benchmark_representative.jsonl
"""
import csv, json, random, re
from collections import defaultdict, Counter
from pathlib import Path

csv.field_size_limit(10 ** 7)
random.seed(1337)
HERE = Path(__file__).parent
CSV = HERE.parent / "scratch_nlp_data" / "cybersiren_nlp_dataset_v1.csv"
SYN = HERE / "cybersiren_e2e_benchmark.jsonl"
OUT = HERE / "cybersiren_e2e_benchmark_representative.jsonl"
LABEL = {"0": "legitimate", "1": "spam", "2": "phishing"}
URLRE = re.compile(r"https?://\S+|www\.\S+", re.I)

# ── targets (≈85/5/10, real-backbone) ───────────────────────────────────────
REAL_TARGET = {"legitimate": 8800, "spam": 330, "phishing": 400}   # phishing = clean OOD only
SYN_TARGET = {"legitimate": 920, "spam": 240, "phishing": 740}     # subsample synth phish, keep owners
PRIORITY = {  # corporate corpus first
    "legitimate": ["D7_Enron", "D7_Ling", "D7_TREC-05", "D7_TREC-07", "D7_CEAS-08", "D2", "D1"],
    "spam": ["D7_Assassin", "D7_TREC-07", "D7_CEAS-08", "D7_TREC-06"],
}

# ── pull real (held-out) ─────────────────────────────────────────────────────
pool = defaultdict(lambda: defaultdict(list))   # label -> source -> [(clean_ood, text)]
with open(CSV, newline="") as f:
    for row in csv.DictReader(f):
        if row["split"] not in ("test", "ood"):
            continue
        lab = LABEL.get(row["label"])
        if lab:
            pool[lab][row["source_dataset"]].append((row["split"] == "ood", row["text"]))


def parse(t):
    m = re.match(r"\s*Subject:\s*(.*?)\n\nBody:\s*(.*)$", t, re.S) or re.match(r"\s*Subject:\s*(.*?)\n(.*)$", t, re.S)
    return (m.group(1).strip()[:200], m.group(2).strip()) if m else ("", t.strip())


_uid = [900000]
def real_record(lab, clean_ood, source, text):
    _uid[0] += 1
    subj, body = parse(text)
    urls = URLRE.findall(text)
    ch = (["nlp"] + (["url"] if urls else [])) if lab == "phishing" else []
    return {"id": f"cse2e-real-{_uid[0]}", "label": lab,
            "difficulty": "real_ood" if clean_ood else "real_seen", "family": f"real::{source}",
            "channels_expected": ch, "provenance": "real", "source_corpus": source,
            "clean_ood": clean_ood, "headers": None, "body_plain": body[:8000],
            "body_html": None, "urls": urls[:10], "subject": subj}


real = []
# legit + spam: priority-source from `test`
for lab in ("legitimate", "spam"):
    need = REAL_TARGET[lab]
    for source in PRIORITY[lab]:
        if need <= 0:
            break
        rows = [t for (c, t) in pool[lab].get(source, []) if not c and len(t) > 25]
        random.shuffle(rows)
        for t in rows[:need]:
            real.append(real_record(lab, False, source, t)); need -= 1
# phishing: clean OOD only (leakage-free)
ood = [(s, t) for s, rows in pool["phishing"].items() for (c, t) in rows if c and len(t) > 25]
random.shuffle(ood)
for s, t in ood[:REAL_TARGET["phishing"]]:
    real.append(real_record("phishing", True, s, t))

# ── pull synthetic (subsample phishing, preserve owner families) ─────────────
syn = [json.loads(l) for l in open(SYN)]
for r in syn:
    r["provenance"] = "synthetic"; r["clean_ood"] = False; r["subject"] = r["headers"]["Subject"]
by_cls = defaultdict(list)
for r in syn:
    by_cls[r["label"]].append(r)
chosen_syn = []
for lab, tgt in SYN_TARGET.items():
    rs = by_cls[lab]
    if lab == "phishing":  # stratified by family to keep channel owners balanced
        byfam = defaultdict(list)
        for r in rs:
            byfam[r["family"]].append(r)
        per = max(1, tgt // len(byfam))
        picked = []
        for fam, rows in byfam.items():
            random.shuffle(rows); picked += rows[:per]
        random.shuffle(picked); chosen_syn += picked[:tgt]
    else:
        random.shuffle(rs); chosen_syn += rs[:tgt]

combined = real + chosen_syn
random.shuffle(combined)
with open(OUT, "w") as f:
    for r in combined:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

# ── summary ──────────────────────────────────────────────────────────────────
lab = Counter(r["label"] for r in combined)
prov = Counter((r["provenance"], r["label"]) for r in combined)
tot = len(combined)
print(f"wrote {tot} emails -> {OUT}")
print("distribution: " + "  ".join(f"{k} {v} ({100*v/tot:.1f}%)" for k, v in lab.most_common()))
print("provenance x label:", {f"{p}/{l}": c for (p, l), c in sorted(prov.items())})
print("clean-OOD phishing (leakage-free):", sum(1 for r in combined if r["clean_ood"]))
print("real corporate (Enron) legit:", sum(1 for r in combined if r.get("source_corpus") == "D7_Enron"))
