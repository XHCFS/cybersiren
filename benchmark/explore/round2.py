#!/usr/bin/env python3
"""round2.py — can a MONOTONE-constrained combiner beat Plan A AND generalize?

Hypothesis: the unconstrained gbm overfits by carving non-monotone regions that flag real
legit (FP balloon .135 on provenance holdout). A monotone constraint (every malicious signal
↑ => P(threat) ↑, never ↓) keeps the signal-combination power but cannot create those spurious
FP regions. If it beats Plan A on the in-corpus split AND holds on (a) provenance holdout and
(b) leave-one-family-out CV, the gain is structural, not memorized.

Adjudicators:
  - in-corpus stratified held-out TEST (the official bar)
  - provenance holdout: train SYNTHETIC -> test REAL
  - leave-one-FAMILY-out CV: hold out whole generator families (new-family OOD)
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
from sklearn.metrics import roc_auc_score

RICH = L.load_rich(sys.argv[1] if len(sys.argv) > 1 else "big/raw_rich_3k.json")
ids = sorted(RICH)
label_of = {i: RICH[i]["label"] for i in ids}
train, test = L.stratified_split(ids, label_of)
tr_rows = [RICH[i] for i in train]; te_rows = [RICH[i] for i in test]
BROAD = {"suspicious", "phishing", "malware", "spam"}
PLANA = {r["id"]: r["verdict"] for r in json.load(open(L.ROOT / "big/raw_big_planAlive.json"))["rows"]}

# ---- monotone feature vector (all features INCREASING in P(threat)); confidence excluded ----
MONO_KEYS = [  # (key, scale, is_prob)
    ("content_risk_score", 0.01), ("header_risk_score", 0.01), ("url_risk_score", 0.01),
    ("phishing_probability", 1.0), ("spam_probability", 1.0),
    ("impersonation_score", 1.0), ("deception_score", 1.0), ("urgency_score", 1.0),
]


def feat_mono(r):
    f = []
    for k, s in MONO_KEYS:
        v = r.get(k)
        f.append(0.0 if v is None else float(v) * s)
    return np.array(f, float)


MONO_CST = [1] * len(MONO_KEYS)   # all monotonic increasing


def build_histgb_mono(trows, **kw):
    X = np.array([feat_mono(r) for r in trows]); y = np.array([L.y_of(r) for r in trows])
    clf = HistGradientBoostingClassifier(monotonic_cst=MONO_CST, random_state=0, **kw)
    clf.fit(X, y)
    return lambda r: float(clf.predict_proba(feat_mono(r).reshape(1, -1))[0, 1])


def build_histgb_free(trows, **kw):
    X = np.array([feat_mono(r) for r in trows]); y = np.array([L.y_of(r) for r in trows])
    clf = HistGradientBoostingClassifier(random_state=0, **kw)
    clf.fit(X, y)
    return lambda r: float(clf.predict_proba(feat_mono(r).reshape(1, -1))[0, 1])


def build_logit_mono(trows):
    # plain logistic on the monotone (all-malicious-increasing) feature set, as an
    # interpretable robust reference. (Not hard-constrained positive; weights usually come out +.)
    X = np.array([feat_mono(r) for r in trows]); y = np.array([L.y_of(r) for r in trows])
    clf = LogisticRegression(max_iter=5000, C=1.0)
    clf.fit(X, y)
    return lambda r: float(clf.predict_proba(feat_mono(r).reshape(1, -1))[0, 1])


def build_calor4(trows):
    f = CO.scorer([CO.CH_URL, CO.CH_HEADER, CO.CH_CONTENT, CO.CH_ATTACH])(trows)
    return lambda r: f(r) / 100.0


def evalpoint(scorer, train_rows, eval_rows, target=0.046):
    thr = L.pick_threshold(train_rows, [scorer(r) for r in train_rows], mode="fpr", target=target)
    fl = [scorer(r) > thr for r in eval_rows]
    m = L.viewB(eval_rows, fl); sl = L.slices(eval_rows, fl)
    auc, pts = L.roc(eval_rows, [scorer(r) for r in eval_rows])
    return m, sl, auc, L.recall_at_fpr(pts, target), L.recall_at_fpr(pts, 0.089)


CANDS = [
    ("calor_4ch (ref)", build_calor4),
    ("histgb_FREE", lambda t: build_histgb_free(t, max_depth=3, learning_rate=0.05, max_iter=200, l2_regularization=1.0)),
    ("histgb_MONO", lambda t: build_histgb_mono(t, max_depth=3, learning_rate=0.05, max_iter=200, l2_regularization=1.0)),
    ("histgb_MONO_reg", lambda t: build_histgb_mono(t, max_depth=2, learning_rate=0.03, max_iter=300, l2_regularization=5.0, min_samples_leaf=40)),
    ("logit_MONO", build_logit_mono),
]

mA = L.viewB(te_rows, [PLANA.get(i) in BROAD for i in test])
slA = L.slices(te_rows, [PLANA.get(i) in BROAD for i in test])
print(f"[REF Plan A live] {L.fmt(mA, slA)}\n")

print("=== (1) in-corpus stratified held-out TEST (thr@train FPR.046) ===")
scorers = {}
for name, build in CANDS:
    sc = build(tr_rows); scorers[name] = build
    m, sl, auc, r046, r089 = evalpoint(sc, tr_rows, te_rows)
    print(f"  {name:18s} R={m['recall']:.3f} FPR={m['fpr']:.3f} F1={m['f1']:.3f} "
          f"rsFPR={sl['real_seen_FPR']} ood={sl['real_ood_recall']} sp={sl['spam_flag']} "
          f"AUC={auc:.4f} R@.046={r046:.3f} R@.089={r089:.3f}")

print("\n=== (2) PROVENANCE HOLDOUT: train SYNTHETIC -> test REAL ===")
synth = [RICH[i] for i in ids if RICH[i]["provenance"] == "synthetic"]
real = [RICH[i] for i in ids if RICH[i]["provenance"] == "real"]
for name, build in CANDS:
    sc = build(synth)
    m, sl, auc, r046, r089 = evalpoint(sc, synth, real)
    print(f"  {name:18s} R={m['recall']:.3f} FPR={m['fpr']:.3f} rsFPR={sl['real_seen_FPR']} "
          f"ood={sl['real_ood_recall']} sp={sl['spam_flag']} AUC={auc:.4f}")

print("\n=== (3) LEAVE-ONE-FAMILY-OUT CV (new-family OOD; AUC over held-out families) ===")
fams = defaultdict(list)
for i in ids:
    fams[RICH[i]["family"]].append(i)
# only fold over families that contain BOTH classes somewhere; eval AUC needs both labels in test fold
for name, build in CANDS:
    aucs = []; flagged_legit = 0; legit_n = 0; threat_flag = 0; threat_n = 0
    # build a global threshold per fold from the training portion at FPR.046
    for fam, fids in fams.items():
        te_ids = set(fids); tr_ids = [i for i in ids if i not in te_ids]
        trr = [RICH[i] for i in tr_ids]; ter = [RICH[i] for i in fids]
        ylab = [L.y_of(r) for r in ter]
        if len(set(ylab)) < 1:
            continue
        sc = build(trr)
        thr = L.pick_threshold(trr, [sc(r) for r in trr], mode="fpr", target=0.046)
        if len(set(ylab)) == 2:
            aucs.append(roc_auc_score(ylab, [sc(r) for r in ter]))
        for r in ter:
            fl = sc(r) > thr
            if r["label"] == "legitimate":
                legit_n += 1; flagged_legit += fl
            else:
                threat_n += 1; threat_flag += fl
    mauc = np.mean(aucs) if aucs else float("nan")
    print(f"  {name:18s} mean-family-AUC={mauc:.4f}  LOFO recall={threat_flag/threat_n:.3f} "
          f"FPR={flagged_legit/legit_n:.3f}  (threat_n={threat_n} legit_n={legit_n})")
