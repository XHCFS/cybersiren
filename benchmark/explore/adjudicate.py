#!/usr/bin/env python3
"""adjudicate.py — the CORRECTED generalization adjudicator (per red-team).

Fixes my broken LOFO:
  - MECHANISM-grouped folds: merge near-duplicate sibling families (homoglyph/leet/
    zerowidth -> adversarial_obfusc; legit_phishy_text/url -> legit_adversarial) so a
    held-out group has NO near-twin in train (kills sibling leakage). Real D-datasets
    each their own group.
  - POOLED out-of-fold scoring: every email scored by a calor that never saw its group;
    pool ALL oof scores -> ONE global ROC (has both classes), so no n=1 single-fold AUC.
  - Adjudicate on pAUC over FPR in [0,0.05] (stable, low-FPR region that matters) +
    pooled-OOF recall@FPR.046 + FPR@recall.785.

Compares isotonic-calor (Plan A) vs beta-calor (red-team's bet) + a few channel sets.
Also reports the standard stratified held-out test for reference.
"""
import json, sys
from collections import defaultdict
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parent))
import combiner_lib as L
import cal2
from sklearn.metrics import roc_curve, roc_auc_score

FN = sys.argv[1] if len(sys.argv) > 1 else "big/raw_rich_3k.json"
RICH = L.load_rich(FN)
ids = sorted(RICH)
THREAT = L.THREAT   # View-A by default: pos=phishing; spam is a NEGATIVE (see combiner_lib)
NEG = L.NEG


def y_of(r): return 1.0 if r["label"] in THREAT else 0.0
def gv(r, k):
    v = r.get(k); return None if v is None else float(v)


# ---- channels ----
def ch_content(r): return gv(r, "content_risk_score")
def ch_header(r): return gv(r, "header_risk_score")
def ch_url(r): return gv(r, "url_risk_score")
def ch_phish(r):
    v = r.get("phishing_probability"); return None if v is None else v * 100.0
CHSETS = {
    "calor_4ch": [("url", ch_url), ("header", ch_header), ("nlp", ch_content)],
    "calor_+phish": [("url", ch_url), ("header", ch_header), ("nlp", ch_content), ("phish", ch_phish)],
}


class CalOR:
    def __init__(self, channels, calib="isotonic", cap=0.999):
        self.channels = channels; self.calib = calib; self.cap = cap
        self.cals = {}; self.final = None

    def fit(self, rows):
        Cls = cal2.CALIBRATORS[self.calib]
        for name, ext in self.channels:
            xs, ys = [], []
            for r in rows:
                v = ext(r)
                if v is not None: xs.append(v); ys.append(y_of(r))
            if len(set(xs)) < 2: continue
            self.cals[name] = Cls(self.cap).fit(xs, ys)
        rx, ry = [], []
        for r in rows:
            rw = self._raw(r)
            if rw is not None: rx.append(rw); ry.append(y_of(r))
        self.final = Cls(1.0).fit(rx, ry)
        return self

    def _raw(self, r):
        pnot = 1.0; present = 0
        for name, ext in self.channels:
            if name not in self.cals: continue
            v = ext(r)
            if v is None: continue
            p = self.cals[name].predict(v); pnot *= (1 - p); present += 1
        return None if present == 0 else (1 - pnot) * 100

    def score(self, r):
        rw = self._raw(r)
        return 0.0 if rw is None else self.final.predict(rw)  # in [0,1]


# ---- mechanism groups ----
def group_of(r):
    f = r["family"]
    if f in ("phish_adversarial_homoglyph", "phish_adversarial_leet", "phish_adversarial_zerowidth"):
        return "phish_adversarial_obfusc"
    if f in ("legit_phishy_text", "legit_phishy_url"):
        return "legit_adversarial"
    return f


def pooled_oof(channels, calib):
    groups = defaultdict(list)
    for i in ids: groups[group_of(RICH[i])].append(i)
    oof = {}
    for g, gids in groups.items():
        tr = [RICH[i] for i in ids if group_of(RICH[i]) != g]
        m = CalOR(channels, calib).fit(tr)
        for i in gids: oof[i] = m.score(RICH[i])
    return oof


def metrics(oof):
    rows = [RICH[i] for i in ids]
    y = np.array([1 if r["label"] in THREAT else (0 if r["label"] in NEG else -1) for r in rows])
    s = np.array([oof[i] for i in ids])
    keep = y >= 0; y, s = y[keep], s[keep]
    auc = roc_auc_score(y, s)
    fpr, tpr, thr = roc_curve(y, s)
    # pAUC over FPR in [0,0.05], normalized to [0,1] (avg TPR)
    cap = 0.05
    fp = np.concatenate([fpr[fpr < cap], [cap]])
    tp = np.interp(fp, fpr, tpr)
    pauc = np.trapezoid(tp, fp) / cap
    # recall@FPR<=.046  and FPR@recall>=.785
    r046 = max([t for f, t in zip(fpr, tpr) if f <= 0.046] or [0])
    fpr785 = min([f for f, t in zip(fpr, tpr) if t >= 0.785] or [1.0])
    # real-world slices at the recall@.046 threshold
    # among thresholds with fpr<=.046, the SMALLEST gives the highest recall (largest qualifying fpr)
    thr046 = min([th for f, th in zip(fpr, thr) if f <= 0.046] or [1.0])
    flags = {i: oof[i] > thr046 for i in ids}
    sl = L.slices(rows, [flags[i] for i in ids])
    return dict(auc=auc, pauc=pauc, r046=r046, fpr785=fpr785,
                ood=sl["real_ood_recall"], rsfpr=sl["real_seen_FPR"], spam=sl["spam_flag"])


def main():
    print(f"=== CORRECTED grouped pooled-OOF adjudication on {FN} (n={len(ids)}) ===")
    ng = len(set(group_of(RICH[i]) for i in ids))
    print(f"mechanism groups: {ng} (siblings merged)\n")
    print(f"{'model':22s} {'AUC':>6s} {'pAUC[0,.05]':>11s} {'R@.046':>7s} {'FPR@R.785':>9s} "
          f"{'ood':>5s} {'rsFPR':>6s} {'spam':>5s}")
    for cs_name, chans in CHSETS.items():
        for calib in ("isotonic", "beta"):
            oof = pooled_oof(chans, calib)
            m = metrics(oof)
            print(f"{cs_name+'/'+calib:22s} {m['auc']:.4f} {m['pauc']:11.4f} {m['r046']:7.3f} "
                  f"{m['fpr785']:9.3f} {m['ood']:5.3f} {str(m['rsfpr']):>6s} {str(m['spam']):>5s}")


if __name__ == "__main__":
    main()
