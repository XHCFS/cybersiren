#!/usr/bin/env python3
"""missed_anatomy.py — anatomy of the threats Plan A MISSES (test split), to see what
signal (if any) could recover them. Focus: do missed threats carry a URL signal that a
cleaner authoritative-URL channel (Plan B) could exploit? And conversely, how much benign
URL noise would that re-introduce?
"""
import json, sys
from collections import Counter
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parent))
import combiner_lib as L

RICH = L.load_rich("big/raw_rich_3k.json")
ids = sorted(RICH)
train, test = L.stratified_split(ids, {i: RICH[i]["label"] for i in ids})
PLANA = {r["id"]: r["verdict"] for r in json.load(open(L.ROOT / "big/raw_big_planAlive.json"))["rows"]}
BROAD = {"suspicious", "phishing", "malware", "spam"}


def flagged(i):
    return PLANA.get(i) in BROAD


missed = [RICH[i] for i in test if RICH[i]["label"] in ("phishing", "spam") and not flagged(i)]
print(f"Plan A misses {len(missed)} threats on test. Anatomy:")
print("  by (label,difficulty):", dict(Counter((r['label'], r['difficulty']) for r in missed)))

def has_url(r): return r.get("url_risk_score") is not None
print(f"\n  of missed: url-present={sum(has_url(r) for r in missed)}  "
      f"url>=50={sum(1 for r in missed if (r.get('url_risk_score') or 0)>=50)}  "
      f"url>=100={sum(1 for r in missed if (r.get('url_risk_score') or 0)>=100)}")
print(f"  of missed: header>=50={sum(1 for r in missed if (r.get('header_risk_score') or 0)>=50)}  "
      f"content>=15={sum(1 for r in missed if (r.get('content_risk_score') or 0)>=15)}")

# missed with a strong url signal = Plan-B recoverable IF authoritative url agrees
recov = [r for r in missed if (r.get("url_risk_score") or 0) >= 50]
print(f"\n  MISSED with url>=50 (Plan-B candidates) n={len(recov)}:")
print("    by (label,difficulty):", dict(Counter((r['label'], r['difficulty']) for r in recov)))

# benign URL noise: legit emails in test with url>=50 (these would be NEW FPs if url un-muted)
legit_test = [RICH[i] for i in test if RICH[i]["label"] == "legitimate"]
legit_url_hi = [r for r in legit_test if (r.get("url_risk_score") or 0) >= 50]
print(f"\n  legit (test) with url>=50 (would-be new FPs from url channel) n={len(legit_url_hi)} "
      f"/ {len(legit_test)} ; of these real_seen={sum(1 for r in legit_url_hi if r['difficulty']=='real_seen')}")
print(f"  legit (test) url distribution: present={sum(has_url(r) for r in legit_test)} "
      f"url>=25={sum(1 for r in legit_test if (r.get('url_risk_score') or 0)>=25)} "
      f"url>=50={len(legit_url_hi)} url>=100={sum(1 for r in legit_test if (r.get('url_risk_score') or 0)>=100)}")

# the truly-unrecoverable missed (no url, no header, low content) = NLP blind spots
blind = [r for r in missed if (r.get("url_risk_score") or 0) < 50 and (r.get("header_risk_score") or 0) < 50
         and (r.get("content_risk_score") or 0) < 26]
print(f"\n  UNRECOVERABLE blind-spots (url<50 & header<50 & content<26) n={len(blind)} "
      f"= {100*len(blind)/len(missed):.0f}% of misses")
print("    by (label,difficulty):", dict(Counter((r['label'], r['difficulty']) for r in blind)))
print("    classification:", dict(Counter(r.get('classification') for r in blind)))

# How much recall could a PERFECT authoritative-url add at no FP cost?
# upper bound: missed threats with url>=50 that are NOT benign-url-confusable
n_threat_test = sum(1 for i in test if RICH[i]["label"] in ("phishing", "spam"))
cur_recall = sum(1 for i in test if RICH[i]["label"] in ("phishing", "spam") and flagged(i)) / n_threat_test
print(f"\n  current Plan A recall={cur_recall:.3f}; perfect-url-recovery upper bound = "
      f"{(sum(1 for i in test if RICH[i]['label'] in ('phishing','spam') and flagged(i))+len(recov))/n_threat_test:.3f}")
