#!/usr/bin/env python3
"""final_adjudicate.py — the decisive, comprehensive comparison on the FULL corpus.

For each candidate, two views:
  (A) STRATIFIED held-out test (SEED=7 60/40) — apples-to-apples with the published bar
      (config D = Plan A: R .785/FPR .046). With bootstrap 95% CIs on R@.046 and FPR@R.785.
  (B) MECHANISM-grouped POOLED out-of-fold (siblings merged) — the honest new-campaign OOD
      adjudicator (pAUC[0,.05], R@.046, ood, real_seen FPR).

Candidates: Plan A (calor_4ch iso) + the learned models that "won" in-corpus, so the
overfitting is shown directly under (B). Run AFTER the live capture (HistGB is heavier).
"""
import json, sys
from collections import defaultdict
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parent))
import combiner_lib as L
import adjudicate as AJ
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_curve, roc_auc_score

FN = sys.argv[1] if len(sys.argv) > 1 else "big/raw_rich_full.json"
RICH = L.load_rich(FN)
ids = sorted(RICH)
THREAT = ("phishing", "spam")
rng = np.random.default_rng(7)


def y_of(r): return 1 if r["label"] in THREAT else 0
def gv(r, k):
    v = r.get(k); return 0.0 if v is None else float(v)


# ---- learned-model feature sets ----
def feat_mono(r):
    url = r.get("url_risk_score")
    return np.array([gv(r, "content_risk_score")/100, gv(r, "header_risk_score")/100,
                     0.0 if url is None else url/100, gv(r, "phishing_probability"),
                     gv(r, "spam_probability"), gv(r, "impersonation_score"),
                     gv(r, "deception_score"), gv(r, "urgency_score")], float)


def feat_conf(r):
    c = gv(r, "content_risk_score")/100; conf = gv(r, "confidence")
    return np.concatenate([feat_mono(r), [conf, c*conf, c*(1-conf)]])


# candidate = name -> (kind, builder). builder(train_rows)->scorer(row)->prob[0,1]
def calor_builder(chans, calib):
    def b(rows): return AJ.CalOR(chans, calib).fit(rows).score
    return b


def histgb_builder(feat, cst=None):
    def b(rows):
        X = np.array([feat(r) for r in rows]); y = np.array([y_of(r) for r in rows])
        kw = dict(max_depth=3, learning_rate=0.05, max_iter=200, l2_regularization=1.0, random_state=0)
        if cst is not None: kw["monotonic_cst"] = cst
        clf = HistGradientBoostingClassifier(**kw).fit(X, y)
        return lambda r: float(clf.predict_proba(feat(r).reshape(1, -1))[0, 1])
    return b


def logit_builder(feat):
    def b(rows):
        X = np.array([feat(r) for r in rows]); y = np.array([y_of(r) for r in rows])
        sc = StandardScaler().fit(X); clf = LogisticRegression(max_iter=4000).fit(sc.transform(X), y)
        return lambda r: float(clf.predict_proba(sc.transform(feat(r).reshape(1, -1)))[0, 1])
    return b


C4 = [("url", AJ.ch_url), ("header", AJ.ch_header), ("nlp", AJ.ch_content)]
CP = C4 + [("phish", AJ.ch_phish)]
CANDS = {
    "PlanA calor_4ch/iso": ("calor", calor_builder(C4, "isotonic")),
    "calor_+phish/iso": ("calor", calor_builder(CP, "isotonic")),
    "logistic_mono": ("ml", logit_builder(feat_mono)),
    "histgb_MONO": ("ml", histgb_builder(feat_mono, cst=[1]*8)),
    "histgb_mono+conf": ("ml", histgb_builder(feat_conf, cst=[1]*8+[0,0,0])),
}


def roc_pack(rows, scores):
    y = np.array([1 if r["label"] in THREAT else (0 if r["label"] == "legitimate" else -1) for r in rows])
    s = np.array(scores); keep = y >= 0; y, s = y[keep], s[keep]
    fpr, tpr, thr = roc_curve(y, s)
    auc = roc_auc_score(y, s)
    r046 = max([t for f, t in zip(fpr, tpr) if f <= 0.046] or [0])
    fpr785 = min([f for f, t in zip(fpr, tpr) if t >= 0.785] or [1.0])
    cap = 0.05; fp = np.concatenate([fpr[fpr < cap], [cap]]); tp = np.interp(fp, fpr, tpr)
    pauc = np.trapezoid(tp, fp)/cap
    return auc, pauc, r046, fpr785


def boot_ci(rows, scores, fn, n=400):
    idx = np.arange(len(rows)); vals = []
    for _ in range(n):
        bi = rng.choice(idx, len(idx), replace=True)
        vals.append(fn([rows[j] for j in bi], [scores[j] for j in bi]))
    return np.percentile(vals, [2.5, 97.5])


def prod_point(rows, scores, thr=0.255):
    """Production band operating point: flag if calibrated P>thr (risk_score>25.5 = band-26)."""
    fl = [s > thr for s in scores]
    m = L.viewB(rows, fl); sl = L.slices(rows, fl)
    return m, sl


def strat_view(name, build):
    train, test = L.stratified_split(ids, {i: RICH[i]["label"] for i in ids})
    sc = build([RICH[i] for i in train])
    te = [RICH[i] for i in test]; s_te = [sc(r) for r in te]
    auc, pauc, r046, fpr785 = roc_pack(te, s_te)
    ci_r = boot_ci(te, s_te, lambda rr, ss: roc_pack(rr, ss)[2])
    ci_f = boot_ci(te, s_te, lambda rr, ss: roc_pack(rr, ss)[3])
    print(f"  {name:22s} AUC={auc:.4f} pAUC={pauc:.4f} R@.046={r046:.3f} [{ci_r[0]:.3f},{ci_r[1]:.3f}]  "
          f"FPR@R.785={fpr785:.3f} [{ci_f[0]:.3f},{ci_f[1]:.3f}]")
    # production band-26 point (only meaningful for calibrated calor scores)
    m, sl = prod_point(te, s_te)
    print(f"      └ band-26 (P>.255): R={m['recall']:.3f} FPR={m['fpr']:.3f} F1={m['f1']:.3f} "
          f"ood={sl['real_ood_recall']} rsFPR={sl['real_seen_FPR']} spam={sl['spam_flag']}")


def grouped_oof(build):
    groups = defaultdict(list)
    for i in ids: groups[AJ.group_of(RICH[i])].append(i)
    oof = {}
    for g, gids in groups.items():
        tr = [RICH[i] for i in ids if AJ.group_of(RICH[i]) != g]
        sc = build(tr)
        for i in gids: oof[i] = sc(RICH[i])
    return oof


def oof_view(name, build):
    oof = grouped_oof(build)
    rows = [RICH[i] for i in ids]; s = [oof[i] for i in ids]
    auc, pauc, r046, fpr785 = roc_pack(rows, s)
    # slices at thr giving fpr<=.046
    y = np.array([1 if r["label"] in THREAT else (0 if r["label"] == "legitimate" else -1) for r in rows])
    sa = np.array(s); keep = y >= 0
    fpr, tpr, thr = roc_curve(y[keep], sa[keep])
    thr046 = min([th for f, th in zip(fpr, thr) if f <= 0.046] or [1.0])
    sl = L.slices(rows, [oof[i] > thr046 for i in ids])
    print(f"  {name:22s} AUC={auc:.4f} pAUC={pauc:.4f} R@.046={r046:.3f} FPR@R.785={fpr785:.3f} "
          f"ood={sl['real_ood_recall']} rsFPR={sl['real_seen_FPR']} spam={sl['spam_flag']}")


def main():
    print(f"=== FINAL adjudication on {FN} (n={len(ids)}) ===")
    print(f"label dist: {dict((l, sum(1 for i in ids if RICH[i]['label']==l)) for l in ('legitimate','spam','phishing'))}")
    print("\n(A) STRATIFIED held-out test (apples-to-apples with config D bar) + bootstrap 95% CI:")
    for name, (kind, build) in CANDS.items():
        strat_view(name, build)
    print("\n(B) MECHANISM-grouped POOLED-OOF (honest new-campaign OOD):")
    for name, (kind, build) in CANDS.items():
        oof_view(name, build)


if __name__ == "__main__":
    main()
