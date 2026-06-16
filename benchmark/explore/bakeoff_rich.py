#!/usr/bin/env python3
"""bakeoff_rich.py — unified leakage-safe bakeoff of svc-08 fusion candidates over the
RICH capture (4 numeric channels + facets/class/confidence/probabilities).

Each candidate = (name, build_fn). build_fn(train_rows) -> scorer(row)->prob[0,1].
For each: fit on TRAIN (SEED=7 60/40 stratified), pick op-threshold on TRAIN at FPR<=0.046,
report held-out TEST View-B + real-world slices, ROC-AUC, recall@FPR{.046,.089}, 5-fold CV AUC.
Then a PROVENANCE holdout (train synthetic / test real) as generalization stress.

Reference bar: Plan A (config D) R=.785 P=.866 F1=.824 FPR=.046 ood=.985 spam=.83 real_seenFPR=.007
"""
import json
import sys
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parent))
import combiner_lib as L
import calor as CO
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold

FN = sys.argv[1] if len(sys.argv) > 1 else "big/raw_rich_3k.json"
RICH = L.load_rich(FN)
ids = sorted(RICH)
label_of = {i: RICH[i]["label"] for i in ids}
train, test = L.stratified_split(ids, label_of)
te_rows = [RICH[i] for i in test]
tr_rows = [RICH[i] for i in train]
print(f"=== bakeoff_rich on {FN}: {len(ids)} rows, train={len(train)} test={len(test)} ===")

BROAD = {"suspicious", "phishing", "malware", "spam"}
PLANA = {r["id"]: r["verdict"] for r in json.load(open(L.ROOT / "big/raw_big_planAlive.json"))["rows"]}


# ---------- candidate builders: train_rows -> (row -> prob[0,1]) ----------
def b_calor(channels):
    def build(trows):
        f = CO.scorer(channels)(trows)
        return lambda r: f(r) / 100.0
    return build


def b_sklearn(feat, factory, scale=True):
    def build(trows):
        Xtr = np.array([feat(r) for r in trows]); ytr = np.array([L.y_of(r) for r in trows])
        sc = StandardScaler().fit(Xtr) if scale else None
        clf = factory()
        clf.fit(sc.transform(Xtr) if sc else Xtr, ytr)
        def score(r):
            x = feat(r).reshape(1, -1)
            return float(clf.predict_proba(sc.transform(x) if sc else x)[0, 1])
        return score
    return build


CANDS = [
    ("calor_4ch (PlanA method)", b_calor([CO.CH_URL, CO.CH_HEADER, CO.CH_CONTENT, CO.CH_ATTACH])),
    ("calor_5ch_+facet", b_calor([CO.CH_URL, CO.CH_HEADER, CO.CH_CONTENT, CO.CH_ATTACH, CO.CH_FACET])),
    ("calor_5ch_+phish", b_calor([CO.CH_URL, CO.CH_HEADER, CO.CH_CONTENT, CO.CH_ATTACH, CO.CH_PHISH])),
    ("calor_6ch_+facet+phish", b_calor([CO.CH_URL, CO.CH_HEADER, CO.CH_CONTENT, CO.CH_ATTACH, CO.CH_FACET, CO.CH_PHISH])),
    ("logistic_interpretable", b_sklearn(L.feat_interpretable, lambda: LogisticRegression(max_iter=3000, C=1.0))),
    ("logistic_full", b_sklearn(L.feat_full, lambda: LogisticRegression(max_iter=3000, C=1.0))),
    ("gbm_full", b_sklearn(L.feat_full, lambda: GradientBoostingClassifier(
        n_estimators=200, max_depth=3, learning_rate=0.05, subsample=0.8, random_state=0), scale=False)),
]


def evaluate(name, build):
    scorer = build(tr_rows)
    tr_s = [scorer(r) for r in tr_rows]
    te_s = [scorer(r) for r in te_rows]
    # threshold on train at FPR<=.046 (scores in [0,1])
    thr = L.pick_threshold(tr_rows, tr_s, mode="fpr", target=0.046)
    flags = [s > thr for s in te_s]
    m = L.viewB(te_rows, flags); sl = L.slices(te_rows, flags)
    auc, pts = L.roc(te_rows, te_s)
    r046 = L.recall_at_fpr(pts, 0.046); r089 = L.recall_at_fpr(pts, 0.089)
    return scorer, m, sl, auc, r046, r089, thr


def cv_auc(build, k=5):
    X_idx = np.arange(len(ids)); y = np.array([L.y_of(RICH[i]) for i in ids])
    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=7)
    aucs = []
    for tr, te in skf.split(X_idx, y):
        trrows = [RICH[ids[j]] for j in tr]; terows = [RICH[ids[j]] for j in te]
        sc = build(trrows)
        s = [sc(r) for r in terows]; yy = [L.y_of(r) for r in terows]
        aucs.append(roc_auc_score(yy, s))
    return np.mean(aucs), np.std(aucs)


# reference
mA = L.viewB(te_rows, [PLANA.get(i) in BROAD for i in test])
slA = L.slices(te_rows, [PLANA.get(i) in BROAD for i in test])
print(f"\n[REF Plan A live]  {L.fmt(mA, slA)}\n")

print(f"{'candidate':28s} {'TEST(thr@trainFPR.046)':40s} {'AUC':>6s} {'R@.046':>6s} {'R@.089':>6s} {'cvAUC':>13s}")
saved = {}
for name, build in CANDS:
    scorer, m, sl, auc, r046, r089, thr = evaluate(name, build)
    ca, cs = cv_auc(build)
    saved[name] = scorer
    print(f"{name:28s} R={m['recall']:.3f} FPR={m['fpr']:.3f} F1={m['f1']:.3f} "
          f"rsFPR={sl['real_seen_FPR']} ood={sl['real_ood_recall']} sp={sl['spam_flag']}  "
          f"{auc:.4f} {r046:.3f} {r089:.3f}  {ca:.4f}±{cs:.4f}")

print("\n=== PROVENANCE HOLDOUT: train SYNTHETIC -> test REAL ===")
synth = [RICH[i] for i in ids if RICH[i]["provenance"] == "synthetic"]
real = [RICH[i] for i in ids if RICH[i]["provenance"] == "real"]
print(f"  synth(train)={len(synth)} real(test)={len(real)}")
for name, build in CANDS:
    sc = build(synth)
    thr = L.pick_threshold(synth, [sc(r) for r in synth], mode="fpr", target=0.046)
    fl = [sc(r) > thr for r in real]
    m = L.viewB(real, fl); sl = L.slices(real, fl)
    try:
        auc = roc_auc_score([L.y_of(r) for r in real], [sc(r) for r in real])
    except ValueError:
        auc = float("nan")
    print(f"  {name:28s} R={m['recall']:.3f} FPR={m['fpr']:.3f} rsFPR={sl['real_seen_FPR']} "
          f"ood={sl['real_ood_recall']} sp={sl['spam_flag']} AUC={auc:.4f}")
