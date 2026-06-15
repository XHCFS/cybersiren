#!/usr/bin/env python3
"""round3.py — exploit the one orthogonal FP signal (confidence) and ask the Pareto
question directly: can any GENERALIZABLE combiner give recall>=0.785 at FPR<0.046?

Adds:
  - confidence + content*confidence interaction features (the U-shaped FP discriminator
    the monotone/calibrated-OR models structurally cannot use).
  - logistic variants (implementable as a dot-product+sigmoid+isotonic in Go svc-08).
  - the Pareto fine-FPR sweep: FPR needed to reach recall 0.785, and recall at FPR
    {.046,.040,.035,.030}, on held-out test, with provenance-holdout + LOFO checks.
"""
import json, sys
from collections import defaultdict
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parent))
import combiner_lib as L
import calor as CO
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score

RICH = L.load_rich("big/raw_rich_3k.json")
ids = sorted(RICH)
train, test = L.stratified_split(ids, {i: RICH[i]["label"] for i in ids})
tr_rows = [RICH[i] for i in train]; te_rows = [RICH[i] for i in test]
PLANA = {r["id"]: r["verdict"] for r in json.load(open(L.ROOT / "big/raw_big_planAlive.json"))["rows"]}
BROAD = {"suspicious", "phishing", "malware", "spam"}


def gv(r, k):
    v = r.get(k); return 0.0 if v is None else float(v)


def feat_conf(r):
    """monotone-malicious features + confidence + content*confidence interaction."""
    c = gv(r, "content_risk_score") / 100.0
    conf = gv(r, "confidence")
    url = r.get("url_risk_score")
    return np.array([
        c, gv(r, "header_risk_score") / 100.0,
        0.0 if url is None else url / 100.0,
        gv(r, "phishing_probability"), gv(r, "spam_probability"),
        gv(r, "impersonation_score"), gv(r, "deception_score"), gv(r, "urgency_score"),
        conf, c * conf, c * (1 - conf),                 # interaction terms
    ], float)


def build_logit(feat, **kw):
    def b(trows):
        X = np.array([feat(r) for r in trows]); y = np.array([L.y_of(r) for r in trows])
        sc = StandardScaler().fit(X)
        clf = LogisticRegression(max_iter=5000, **kw).fit(sc.transform(X), y)
        return lambda r: float(clf.predict_proba(sc.transform(feat(r).reshape(1, -1)))[0, 1])
    return b


def build_histgb_conf(trows):
    X = np.array([feat_conf(r) for r in trows]); y = np.array([L.y_of(r) for r in trows])
    # monotone on first 8 (malicious), unconstrained on confidence + interactions
    cst = [1] * 8 + [0, 0, 0]
    clf = HistGradientBoostingClassifier(monotonic_cst=cst, max_depth=3, learning_rate=0.05,
                                         max_iter=200, l2_regularization=1.0, random_state=0).fit(X, y)
    return lambda r: float(clf.predict_proba(feat_conf(r).reshape(1, -1))[0, 1])


def build_calor4(trows):
    f = CO.scorer([CO.CH_URL, CO.CH_HEADER, CO.CH_CONTENT, CO.CH_ATTACH])(trows)
    return lambda r: f(r) / 100.0


def fpr_for_recall(rows, scores, rtarget=0.785):
    y = np.array([1 if r["label"] in ("phishing", "spam") else (0 if r["label"] == "legitimate" else -1) for r in rows])
    s = np.array(scores)
    order = np.argsort(-s)
    best = 1.0
    for thr in np.unique(s):
        fl = s > thr
        tp = int(((y == 1) & fl).sum()); fn = int(((y == 1) & ~fl).sum())
        fp = int(((y == 0) & fl).sum()); tn = int(((y == 0) & ~fl).sum())
        rec = tp / (tp + fn) if tp + fn else 0; fpr = fp / (fp + tn) if fp + tn else 0
        if rec >= rtarget:
            best = min(best, fpr)
    return best


def recall_at(rows, scores, fpr_t):
    _, pts = L.roc(rows, scores)
    return L.recall_at_fpr(pts, fpr_t)


CANDS = [
    ("calor_4ch (ref)", build_calor4),
    ("logit_conf", build_logit(feat_conf, C=1.0)),
    ("logit_conf_C0.3", build_logit(feat_conf, C=0.3)),
    ("histgb_mono+conf", build_histgb_conf),
]

mA = L.viewB(te_rows, [PLANA.get(i) in BROAD for i in test])
slA = L.slices(te_rows, [PLANA.get(i) in BROAD for i in test])
print(f"[REF Plan A] {L.fmt(mA, slA)}\n")
print("=== PARETO question: recall@FPR grid + FPR@recall0.785 (held-out TEST) ===")
for name, build in CANDS:
    sc = build(tr_rows)
    s_te = [sc(r) for r in te_rows]
    auc = roc_auc_score([L.y_of(r) for r in te_rows], s_te)
    grid = {f: recall_at(te_rows, s_te, f) for f in (0.046, 0.040, 0.035, 0.030)}
    fpr785 = fpr_for_recall(te_rows, s_te, 0.785)
    print(f"  {name:18s} AUC={auc:.4f}  R@.046={grid[0.046]:.3f} R@.040={grid[0.040]:.3f} "
          f"R@.035={grid[0.035]:.3f} R@.030={grid[0.030]:.3f}  FPR@R0.785={fpr785:.3f}")

print("\n=== generalization: provenance holdout (train synth->test real) + LOFO ===")
synth = [RICH[i] for i in ids if RICH[i]["provenance"] == "synthetic"]
real = [RICH[i] for i in ids if RICH[i]["provenance"] == "real"]
for name, build in CANDS:
    sc = build(synth)
    thr = L.pick_threshold(synth, [sc(r) for r in synth], "fpr", 0.046)
    fl = [sc(r) > thr for r in real]
    m = L.viewB(real, fl); sl = L.slices(real, fl)
    auc = roc_auc_score([L.y_of(r) for r in real], [sc(r) for r in real])
    print(f"  PROV  {name:18s} R={m['recall']:.3f} FPR={m['fpr']:.3f} rsFPR={sl['real_seen_FPR']} "
          f"ood={sl['real_ood_recall']} AUC={auc:.4f}")

fams = defaultdict(list)
for i in ids:
    fams[RICH[i]["family"]].append(i)
for name, build in CANDS:
    aucs = []; fl_legit = ln = tf = tn = 0
    for fam, fids in fams.items():
        tr_ids = [i for i in ids if i not in set(fids)]
        trr = [RICH[i] for i in tr_ids]; ter = [RICH[i] for i in fids]
        yl = [L.y_of(r) for r in ter]
        sc = build(trr)
        thr = L.pick_threshold(trr, [sc(r) for r in trr], "fpr", 0.046)
        if len(set(yl)) == 2:
            aucs.append(roc_auc_score(yl, [sc(r) for r in ter]))
        for r in ter:
            f = sc(r) > thr
            if r["label"] == "legitimate":
                ln += 1; fl_legit += f
            else:
                tn += 1; tf += f
    print(f"  LOFO  {name:18s} fam-AUC={np.mean(aucs):.4f} recall={tf/tn:.3f} FPR={fl_legit/ln:.3f}")
