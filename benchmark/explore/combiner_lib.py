#!/usr/bin/env python3
"""combiner_lib.py — harness for svc-08 fusion candidates over the RICH capture.

A candidate = (feature_builder, model_factory). We:
  - fit on train (SEED=7 60/40 stratified-by-label),
  - pick the operating threshold on TRAIN (leakage-safe: target FPR or max-F1),
  - report held-out TEST View-B metrics + real-world slices + ROC-AUC + recall@FPR,
  - 5-fold CV for stability, and a PROVENANCE holdout (train synthetic / test real)
    as a generalization stress test.

All randomness is seeded. None/missing handled per-feature.
"""
import json
import random
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

ROOT = Path(__file__).resolve().parent.parent
SEED = 7
THREAT = ("phishing", "spam")


def _read_json(path):
    """Read a JSON file, transparently handling a .gz sibling (committed evidence is gzipped)."""
    import gzip
    p = Path(path)
    if not p.exists() and Path(str(p) + ".gz").exists():
        p = Path(str(p) + ".gz")
    if str(p).endswith(".gz"):
        with gzip.open(p, "rt") as f:
            return json.load(f)
    return json.loads(p.read_text())


def load_rich(fn="big/raw_rich_3k.json"):
    rows = _read_json(ROOT / fn)["rows"]
    return {r["id"]: r for r in rows}


def stratified_split(ids, label_of, seed=SEED, frac=0.6):
    rng = random.Random(seed)
    by = defaultdict(list)
    for i in ids:
        by[label_of[i]].append(i)
    train = set()
    for lab, lst in by.items():
        lst = list(lst); rng.shuffle(lst); train |= set(lst[: int(len(lst) * frac)])
    test = [i for i in ids if i not in train]
    return sorted(train), test


def y_of(r):
    return 1 if r["label"] in THREAT else 0


# ---------------- feature builders: row -> np.array ----------------
def gv(r, k, d=0.0):
    v = r.get(k)
    return d if v is None else float(v)


INTENTS = ["legitimate", "scam", "bec", "credential_harvesting", "malware_delivery"]
CLASSES = ["legitimate", "spam", "phishing"]


def feat_full(r):
    """All meaningful signals. None->0 for scores; presence flags for sparse channels."""
    url = r.get("url_risk_score")
    att = r.get("attachment_risk_score")
    f = [
        gv(r, "content_risk_score") / 100.0,
        gv(r, "header_risk_score") / 100.0,
        (0.0 if url is None else url / 100.0),
        1.0 if url is not None else 0.0,           # url present
        (0.0 if att is None else att / 100.0),
        gv(r, "phishing_probability"),
        gv(r, "spam_probability"),
        gv(r, "confidence"),
        gv(r, "impersonation_score"),
        gv(r, "deception_score"),
        gv(r, "urgency_score"),
        gv(r, "intent_confidence"),
        1.0 if r.get("obfuscation_detected") else 0.0,
    ]
    # one-hot intent + classification
    il = r.get("intent_label")
    f += [1.0 if il == x else 0.0 for x in INTENTS]
    cl = r.get("classification")
    f += [1.0 if cl == x else 0.0 for x in CLASSES]
    return np.array(f, float)


def feat_numeric4(r):
    """The 4 numeric channels only (baseline parity with bakeoff_4ch)."""
    url = r.get("url_risk_score"); att = r.get("attachment_risk_score")
    return np.array([
        gv(r, "content_risk_score") / 100.0,
        gv(r, "header_risk_score") / 100.0,
        (0.0 if url is None else url / 100.0), 1.0 if url is not None else 0.0,
        (0.0 if att is None else att / 100.0), 1.0 if att is not None else 0.0,
    ], float)


def feat_interpretable(r):
    """Small, causally-meaningful, monotone-friendly set for a robust logistic combiner."""
    url = r.get("url_risk_score")
    return np.array([
        gv(r, "content_risk_score") / 100.0,                 # maliciousness
        gv(r, "phishing_probability"),                        # phishy intent (model head)
        gv(r, "spam_probability"),                            # spammy intent
        max(gv(r, "impersonation_score"), gv(r, "deception_score")),  # heuristic phish facet
        gv(r, "urgency_score"),
        gv(r, "header_risk_score") / 100.0,                  # header anomaly (>0.1 = non-neutral)
        (0.0 if url is None else url / 100.0),               # url lexical risk
        gv(r, "confidence") * (1.0 if r.get("classification") == "legitimate" else 0.0),  # confident-legit (suppressor)
    ], float)


# ---------------- metrics ----------------
def prf(tp, fp, fn, tn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return dict(precision=round(p, 4), recall=round(r, 4), f1=round(f, 4), fpr=round(fpr, 4))


def viewB(rows, flags):
    tp = fp = fn = tn = 0
    for r, fl in zip(rows, flags):
        if r["label"] in THREAT:
            tp += fl; fn += not fl
        elif r["label"] == "legitimate":
            fp += fl; tn += not fl
    return prf(tp, fp, fn, tn)


def slices(rows, flags):
    def rate(pred):
        sel = [(r, fl) for r, fl in zip(rows, flags) if pred(r)]
        return (round(sum(fl for _, fl in sel) / len(sel), 4), len(sel)) if sel else (None, 0)
    out = {}
    out["real_seen_FPR"] = rate(lambda r: r["label"] == "legitimate" and r["difficulty"] == "real_seen")[0]
    out["synth_legit_FPR"] = rate(lambda r: r["label"] == "legitimate" and r["provenance"] == "synthetic")[0]
    out["real_ood_recall"] = rate(lambda r: r["label"] == "phishing" and r["difficulty"] == "real_ood")[0]
    out["spam_flag"] = rate(lambda r: r["label"] == "spam")[0]
    out["phish_recall"] = rate(lambda r: r["label"] == "phishing")[0]
    return out


def roc(rows, scores):
    y = np.array([y_of(r) if r["label"] != "spam" or True else 0 for r in rows])
    # View B: pos=threat, neg=legit; drop nothing (spam is pos)
    y = np.array([1 if r["label"] in THREAT else 0 for r in rows])
    s = np.array(scores)
    auc = roc_auc_score(y, s) if len(set(y)) > 1 else float("nan")
    pts = []
    for thr in np.unique(np.concatenate([[-1e9], np.linspace(0, 1, 201)])):
        fl = s > thr
        tp = int(((y == 1) & fl).sum()); fn = int(((y == 1) & ~fl).sum())
        fp = int(((y == 0) & fl).sum()); tn = int(((y == 0) & ~fl).sum())
        rr = tp / (tp + fn) if tp + fn else 0
        fpr = fp / (fp + tn) if fp + tn else 0
        pts.append((thr, rr, fpr))
    return auc, pts


def recall_at_fpr(pts, fpr_t):
    ok = [r for (_, r, fpr) in pts if fpr <= fpr_t]
    return max(ok) if ok else 0.0


def pick_threshold(rows, scores, mode="fpr", target=0.046):
    """Choose operating threshold on TRAIN. mode: 'fpr' (max recall s.t. fpr<=target) or 'f1'."""
    _, pts = roc(rows, scores)
    if mode == "fpr":
        cand = [(r, thr) for (thr, r, fpr) in pts if fpr <= target]
        return max(cand)[1] if cand else 1.0
    # f1
    best = (-1, 1.0)
    for thr, r, fpr in pts:
        # need precision -> recompute
        s = np.array(scores); y = np.array([1 if x["label"] in THREAT else 0 for x in rows])
        fl = s > thr
        tp = int(((y == 1) & fl).sum()); fp = int(((y == 0) & fl).sum()); fn = int(((y == 1) & ~fl).sum())
        p = tp / (tp + fp) if tp + fp else 0; rc = tp / (tp + fn) if tp + fn else 0
        f = 2 * p * rc / (p + rc) if p + rc else 0
        if f > best[0]:
            best = (f, thr)
    return best[1]


def fmt(m, extra):
    return (f"R={m['recall']:.3f} P={m['precision']:.3f} F1={m['f1']:.3f} FPR={m['fpr']:.3f} | "
            f"real_seenFPR={extra['real_seen_FPR']} ood={extra['real_ood_recall']} "
            f"spam={extra['spam_flag']} phishR={extra['phish_recall']}")
