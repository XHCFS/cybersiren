#!/usr/bin/env python3
"""bakeoff_4ch.py — ROC bakeoff of fusion methods over the SAME 4 captured channel
scores (with-212 maliciousness content). Establishes the 4-channel ceiling: how much
can pure fusion-math/calibration changes beat Plan A without new signals?

All fits on TRAIN (SEED=7 60/40 stratified), all metrics on held-out TEST.
"""
import sys
import numpy as np
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import evallib as E
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler

A, train, test = E.canonical_split()
ids = sorted(A)
CH = [("url", "url_risk_score"), ("header", "header_risk_score"),
      ("nlp", "content_risk_score"), ("attachment", "attachment_risk_score")]


def y_of(i):
    return 1.0 if E.is_mal(A[i]) else 0.0


# ---------- fusion methods: each returns id->continuous score [0,100] ----------

def m_weighted_avg():
    # the captured with-212 run was produced under the merged weighted_average default
    return {i: float(A[i]["risk_score"]) for i in ids}


def m_max():
    out = {}
    for i in ids:
        vals = [A[i][k] for _, k in CH if A[i][k] is not None]
        out[i] = float(max(vals)) if vals else 0.0
    return out


def m_noisy_or_raw():
    out = {}
    for i in ids:
        pnot = 1.0; present = 0
        for _, k in CH:
            v = A[i][k]
            if v is None:
                continue
            pnot *= (1 - min(0.999, v / 100.0)); present += 1
        out[i] = (1 - pnot) * 100 if present else 0.0
    return out


def _fit_iso_channels():
    iso = {}
    for ch, key in (("nlp", "content_risk_score"), ("header", "header_risk_score"),
                    ("url", "url_risk_score")):
        xs, ys = [], []
        for i in train:
            v = A[i][key]
            if v is not None:
                xs.append(float(v)); ys.append(y_of(i))
        m = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=0.999)
        m.fit(np.array(xs), np.array(ys)); iso[ch] = m
    return iso


def _calib_or_raw(iso):
    def pc(ch, v):
        if v is None:
            return None
        if ch == "attachment":
            return min(0.999, v / 100.0)
        return float(min(0.999, max(0.0, iso[ch].predict([float(v)])[0])))
    def raw_of(i):
        pnot = 1.0; present = 0
        for ch, key in (("url", "url_risk_score"), ("header", "header_risk_score"),
                        ("nlp", "content_risk_score"), ("attachment", "attachment_risk_score")):
            p = pc(ch, A[i][key])
            if p is None:
                continue
            pnot *= (1 - p); present += 1
        return None if present == 0 else (1 - pnot) * 100
    return raw_of


def m_calibrated_or():
    """Plan A: per-channel isotonic + final isotonic on raw. Fit on train."""
    iso = _fit_iso_channels()
    raw_of = _calib_or_raw(iso)
    rx, ry = [], []
    for i in train:
        rw = raw_of(i)
        if rw is not None:
            rx.append(rw); ry.append(y_of(i))
    final = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1.0)
    final.fit(np.array(rx), np.array(ry))
    out = {}
    for i in ids:
        rw = raw_of(i)
        out[i] = 0.0 if rw is None else float(final.predict([rw])[0]) * 100
    return out


def _features(i):
    """Fixed-length feature vector for learned combiners. None->0 (no evidence) + presence."""
    f = []
    for _, k in CH:
        v = A[i][k]
        f.append(0.0 if v is None else float(v))
        f.append(0.0 if v is None else 1.0)  # presence
    return f


def m_logistic():
    Xtr = np.array([_features(i) for i in train]); ytr = np.array([y_of(i) for i in train])
    sc = StandardScaler().fit(Xtr)
    clf = LogisticRegression(max_iter=2000, C=1.0).fit(sc.transform(Xtr), ytr)
    out = {}
    for i in ids:
        p = clf.predict_proba(sc.transform([_features(i)]))[0, 1]
        out[i] = p * 100
    return out


def m_gbm():
    Xtr = np.array([_features(i) for i in train]); ytr = np.array([y_of(i) for i in train])
    clf = GradientBoostingClassifier(n_estimators=200, max_depth=3, learning_rate=0.05,
                                     subsample=0.8, random_state=0).fit(Xtr, ytr)
    out = {}
    for i in ids:
        out[i] = clf.predict_proba([_features(i)])[0, 1] * 100
    return out


METHODS = {
    "weighted_avg (B)": m_weighted_avg,
    "max": m_max,
    "noisy_or_raw": m_noisy_or_raw,
    "calibrated_or (PlanA)": m_calibrated_or,
    "logistic_4ch": m_logistic,
    "gbm_4ch": m_gbm,
}


def main():
    print(f"train={len(train)} test={len(test)}\n")
    print(f"{'method':24s} {'AUC':>6s} {'R@FPR.046':>9s} {'R@FPR.089':>9s} "
          f"{'bestF1':>7s} {'prod:R/FPR/F1':>16s}")
    results = {}
    for name, fn in METHODS.items():
        sm = fn()
        auc, pts = E.roc_points(sm, A, test)
        r046 = E.recall_at_fpr(pts, 0.046)
        r089 = E.recall_at_fpr(pts, 0.089)
        bf1 = E.best_f1(pts)[0]
        prod = E.evaluate(sm, A, test, thr=25.5)
        results[name] = (sm, prod, auc)
        print(f"{name:24s} {auc:6.4f} {r046:9.3f} {r089:9.3f} {bf1:7.3f} "
              f"  {prod['recall']:.3f}/{prod['fpr']:.3f}/{prod['f1']:.3f}")
    print("\n=== production operating point (thr=25.5) — generalization slices ===")
    for name, (sm, prod, auc) in results.items():
        print(f"  {name:24s} {E.fmt(prod)}")


if __name__ == "__main__":
    main()
