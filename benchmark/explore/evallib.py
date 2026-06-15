#!/usr/bin/env python3
"""evallib.py — reusable evaluation infrastructure for the svc-08 fusion search.

Loads captured per-email component scores, applies the leakage-safe split
(SEED=7, 60/40 stratified by label — IDENTICAL to fit_planA.py / compare_final.py),
and provides View-B threat metrics + the real-world slices (real_seen FPR,
real_ood / clean_ood phishing recall, spam-flag rate).

A "config" is a function score_fn(row)->float in [0,100] (continuous risk) OR a
verdict_map id->band. We evaluate at the production band threshold (flag if
score>25 i.e. round(score)>=26) AND sweep the threshold for the full ROC.
"""
import json
import random
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent  # repbench/
BROAD = {"suspicious", "phishing", "malware", "spam"}
SEED = 7


def load_rows(fn):
    """Load a raw_big_*.json -> dict id->row (transparently handles a .gz sibling)."""
    import gzip
    p = ROOT / fn if not Path(fn).is_absolute() else Path(fn)
    if not p.exists() and Path(str(p) + ".gz").exists():
        p = Path(str(p) + ".gz")
    if str(p).endswith(".gz"):
        with gzip.open(p, "rt") as f:
            return {r["id"]: r for r in json.load(f)["rows"]}
    return {r["id"]: r for r in json.loads(p.read_text())["rows"]}


def split(ids, labels_of, seed=SEED, frac=0.6):
    """Stratified-by-label 60/40 split. Returns (train_set, test_list).
    labels_of: id->label. Matches fit_planA.py exactly."""
    rng = random.Random(seed)
    by = defaultdict(list)
    for i in ids:
        by[labels_of[i]].append(i)
    train = set()
    for lab, lst in by.items():
        lst = list(lst)
        rng.shuffle(lst)
        train |= set(lst[: int(len(lst) * frac)])
    test = [i for i in ids if i not in train]
    return train, test


def is_mal(row):
    return row["label"] != "legitimate"


def band(score):
    s = round(score)
    return "benign" if s <= 25 else "suspicious" if s <= 50 else "phishing" if s <= 75 else "malware"


def prf(tp, fp, fn, tn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return dict(precision=round(p, 4), recall=round(r, 4), f1=round(f, 4), fpr=round(fpr, 4),
                tp=tp, fp=fp, fn=fn, tn=tn)


def viewB_from_flags(rows, flags):
    """rows: list of row dicts (test); flags: parallel list of bool flagged.
    View B: pos = phishing|spam, neg = legitimate."""
    tp = fp = fn = tn = 0
    for r, fl in zip(rows, flags):
        if r["label"] in ("phishing", "spam"):
            tp += fl
            fn += not fl
        elif r["label"] == "legitimate":
            fp += fl
            tn += not fl
    return prf(tp, fp, fn, tn)


def slice_metrics(rows, flags):
    """Real-world slices: real_seen legit FPR, real_ood phishing recall,
    clean_ood phishing recall, spam flag rate, synthetic-legit FPR."""
    out = {}
    def rate(pred):
        sel = [(r, fl) for r, fl in zip(rows, flags) if pred(r)]
        if not sel:
            return None, 0
        return round(sum(fl for _, fl in sel) / len(sel), 4), len(sel)

    out["real_seen_FPR"], out["n_real_seen_legit"] = rate(
        lambda r: r["label"] == "legitimate" and r["difficulty"] == "real_seen")
    out["synth_legit_FPR"], out["n_synth_legit"] = rate(
        lambda r: r["label"] == "legitimate" and r["provenance"] == "synthetic")
    out["real_ood_recall"], out["n_real_ood"] = rate(
        lambda r: r["label"] == "phishing" and r["difficulty"] == "real_ood")
    out["clean_ood_recall"], out["n_clean_ood"] = rate(
        lambda r: r["label"] == "phishing" and r.get("clean_ood") == 1)
    out["spam_flag"], out["n_spam"] = rate(lambda r: r["label"] == "spam")
    out["phish_recall"], out["n_phish"] = rate(lambda r: r["label"] == "phishing")
    return out


def evaluate(score_map, rows_by_id, test_ids, thr=25.5):
    """score_map: id->continuous risk [0,100]. Flag if score>thr (default 25.5 ~ band>benign).
    Returns View-B metrics + slices on test_ids."""
    rows = [rows_by_id[i] for i in test_ids]
    flags = [score_map[i] > thr for i in test_ids]
    m = viewB_from_flags(rows, flags)
    m.update(slice_metrics(rows, flags))
    return m


def evaluate_verdicts(verdict_map, rows_by_id, test_ids):
    """verdict_map: id->band string. Flag if in BROAD."""
    rows = [rows_by_id[i] for i in test_ids]
    flags = [verdict_map[i] in BROAD for i in test_ids]
    m = viewB_from_flags(rows, flags)
    m.update(slice_metrics(rows, flags))
    return m


def roc_points(score_map, rows_by_id, test_ids):
    """Full ROC over View-B. Returns (auc, list of (thr, recall, fpr, f1, prec))."""
    rows = [rows_by_id[i] for i in test_ids]
    scores = np.array([score_map[i] for i in test_ids])
    y = np.array([1 if r["label"] in ("phishing", "spam") else (0 if r["label"] == "legitimate" else -1)
                  for r in rows])
    keep = y >= 0
    scores, y = scores[keep], y[keep]
    # AUC via rank
    from sklearn.metrics import roc_auc_score
    auc = roc_auc_score(y, scores) if len(set(y)) > 1 else float("nan")
    pts = []
    for thr in np.unique(np.concatenate([[-1], np.linspace(0, 100, 201)])):
        fl = scores > thr
        tp = int(((y == 1) & fl).sum()); fn = int(((y == 1) & ~fl).sum())
        fp = int(((y == 0) & fl).sum()); tn = int(((y == 0) & ~fl).sum())
        r = tp / (tp + fn) if tp + fn else 0
        fpr = fp / (fp + tn) if fp + tn else 0
        p = tp / (tp + fp) if tp + fp else 0
        f = 2 * p * r / (p + r) if p + r else 0
        pts.append((float(thr), r, fpr, f, p))
    return auc, pts


def recall_at_fpr(pts, fpr_target):
    """Best recall achievable at fpr <= fpr_target."""
    ok = [r for (_, r, fpr, _, _) in pts if fpr <= fpr_target]
    return max(ok) if ok else 0.0


def best_f1(pts):
    return max((f, thr, r, fpr, p) for (thr, r, fpr, f, p) in pts)


def fmt(m):
    return (f"R={m['recall']:.3f} P={m['precision']:.3f} F1={m['f1']:.3f} FPR={m['fpr']:.3f} | "
            f"real_seenFPR={m['real_seen_FPR']} ood={m['real_ood_recall']} "
            f"spam={m['spam_flag']} phishR={m['phish_recall']}")


# convenience: the canonical test split over the four captured runs
def canonical_split():
    A = load_rows("big/raw_big_with212.json")
    ids = sorted(A)
    train, test = split(ids, {i: A[i]["label"] for i in ids})
    return A, train, test
