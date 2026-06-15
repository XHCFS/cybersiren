#!/usr/bin/env python3
"""rich_analysis.py — does the rich NLP signal carry ORTHOGONAL information that the
4 numeric channels lack? Two decisive questions:

Q1 (recall): on MISSED hard/medium phishing (low content_risk), do the facets
   (impersonation/deception/urgency) or class/phish_prob fire? If yes -> a richer
   combiner can recover them. If no -> facets won't help recall.
Q2 (FPR): on FP-prone legit-hard (high content_risk), is confidence/phish_prob/class
   different from real phishing? If yes -> can suppress FPs.
"""
import json, sys
from collections import Counter
from pathlib import Path
import numpy as np

fn = sys.argv[1] if len(sys.argv) > 1 else "big/raw_rich_3k.json"
ROOT = Path(__file__).resolve().parent.parent
rows = json.load(open(ROOT / fn))["rows"]
print(f"loaded {len(rows)} rows from {fn}\n")

NUMF = ["content_risk_score", "url_risk_score", "header_risk_score"]
RICHF = ["confidence", "phishing_probability", "spam_probability", "impersonation_score",
         "deception_score", "urgency_score", "intent_confidence"]


def g(r, k, d=0.0):
    v = r.get(k)
    return d if v is None else v


def summ(sub, keys):
    for k in keys:
        xs = [g(r, k) for r in sub]
        a = np.array(xs, float)
        print(f"    {k:22s} mean={a.mean():6.3f} p50={np.percentile(a,50):6.3f} p90={np.percentile(a,90):6.3f}")


def cls_dist(sub):
    print("    classification:", dict(Counter(r.get("classification") for r in sub)))
    print("    intent_label  :", dict(Counter(r.get("intent_label") for r in sub)))


# ---- Q1: missed phishing (content_risk < 26 = would be benign on content alone) ----
print("=" * 70)
print("Q1: hard/medium phishing with LOW content_risk (<26) — do other signals fire?")
hardphish_low = [r for r in rows if r["label"] == "phishing"
                 and r["difficulty"] in ("hard", "medium") and g(r, "content_risk_score") < 26]
print(f"  n={len(hardphish_low)} (these are the recall-killers)")
summ(hardphish_low, RICHF); cls_dist(hardphish_low)
print(f"  header mean={np.mean([g(r,'header_risk_score') for r in hardphish_low]):.1f} "
      f"url-present={sum(1 for r in hardphish_low if r.get('url_risk_score') is not None)}")

print("\n  vs hard/medium phishing with HIGH content_risk (>=26) — caught ones:")
hardphish_hi = [r for r in rows if r["label"] == "phishing"
                and r["difficulty"] in ("hard", "medium") and g(r, "content_risk_score") >= 26]
print(f"  n={len(hardphish_hi)}")
summ(hardphish_hi, RICHF)

# ---- Q2: legit-hard with HIGH content_risk (FP-prone) vs real phishing ----
print("\n" + "=" * 70)
print("Q2: legit with HIGH content_risk>=26 (FP-prone) vs phishing with content>=26")
legit_hi = [r for r in rows if r["label"] == "legitimate" and g(r, "content_risk_score") >= 26]
phish_hi = [r for r in rows if r["label"] == "phishing" and g(r, "content_risk_score") >= 26]
spam_hi = [r for r in rows if r["label"] == "spam" and g(r, "content_risk_score") >= 26]
print(f"  legit_hi n={len(legit_hi)}:")
summ(legit_hi, RICHF); cls_dist(legit_hi)
print(f"  phish_hi n={len(phish_hi)}:")
summ(phish_hi, RICHF); cls_dist(phish_hi)
print(f"  spam_hi n={len(spam_hi)}:")
summ(spam_hi, RICHF); cls_dist(spam_hi)

# ---- separability check: AUC of each rich feature for legit_hi vs (phish_hi+spam_hi) ----
print("\n" + "=" * 70)
print("Q2b: per-feature AUC to separate FP-prone legit_hi(neg) from threat_hi(pos)")
from sklearn.metrics import roc_auc_score
pos = phish_hi + spam_hi
y = [0] * len(legit_hi) + [1] * len(pos)
for k in RICHF + ["content_risk_score", "header_risk_score"]:
    x = [g(r, k) for r in legit_hi] + [g(r, k) for r in pos]
    try:
        auc = roc_auc_score(y, x)
        print(f"    {k:22s} AUC={auc:.3f}")
    except ValueError:
        print(f"    {k:22s} (degenerate)")

# class==legitimate as a benign gate: how clean?
print("\n" + "=" * 70)
print("Q3: 'class==legitimate & confidence>=t' as a benign gate — precision of the gate")
for t in (0.90, 0.95, 0.99, 0.995):
    gated = [r for r in rows if r.get("classification") == "legitimate" and g(r, "confidence") >= t]
    if not gated:
        continue
    n_threat = sum(1 for r in gated if r["label"] in ("phishing", "spam"))
    print(f"    t={t}: gated={len(gated)}  threats_wrongly_gated={n_threat} "
          f"({100*n_threat/len(gated):.1f}%)  legit_in_gate={sum(1 for r in gated if r['label']=='legitimate')}")
