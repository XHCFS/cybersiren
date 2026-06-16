#!/usr/bin/env python3
"""sweep_va.py — View-A grouped-OOF sweep of svc-08 calibrated-OR fusion candidates from
ONE capture (no live re-run needed). The task is binary legit-vs-phishing: spam is a hard
NEGATIVE (folded into legit per the updated NLP model). The dedicated phishing_probability
head is the clean phishing signal; content_risk_score is a legacy "overall maliciousness"
score that over-fires on the hard negatives (spam) -> the main View-A FP source.

For each candidate we report:
  - OOF pAUC[0,.05] and OOF R@FPR<=.046 under the mechanism-grouped pooled out-of-fold
    adjudicator (the honest new-campaign generalization test), and
  - the in-corpus stratified held-out band-26 (calibrated P>0.255) operating point + slices.

Usage: python3 explore/sweep_va.py [capture.json]
"""
import sys
from collections import defaultdict
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parent))
import combiner_lib as L
import adjudicate as AJ
from sklearn.metrics import roc_curve, roc_auc_score

FN = sys.argv[1] if len(sys.argv) > 1 else "big/raw_rich_fp32_3k.json"
RICH = L.load_rich(FN)
ids = sorted(RICH)


# ---- channels (value in [0,100] or None) ----
def ch_spam(r):
    v = r.get("spam_probability"); return None if v is None else v * 100.0
def ch_facet(r):
    a, b = r.get("impersonation_score"), r.get("deception_score")
    return None if (a is None and b is None) else max(a or 0.0, b or 0.0) * 100.0
def ch_urg(r):
    v = r.get("urgency_score"); return None if v is None else v * 100.0

U, H, C, P = ("url", AJ.ch_url), ("header", AJ.ch_header), ("nlp", AJ.ch_content), ("phish", AJ.ch_phish)
F, S, G = ("facet", ch_facet), ("spam", ch_spam), ("urg", ch_urg)


# ---- builders: train_rows -> scorer(row) -> P in [0,1] ----
def calor(chans, calib="isotonic"):
    return lambda rows: AJ.CalOR(chans, calib).fit(rows).score

def calor_spamsup(chans, alpha=1.0, calib="isotonic"):
    def b(rows):
        sc = AJ.CalOR(chans, calib).fit(rows).score
        return lambda r: sc(r) * (1.0 - alpha * (r.get("spam_probability") or 0.0))
    return b

def calor_classgate(chans, k=0.3, calib="isotonic"):
    def b(rows):
        sc = AJ.CalOR(chans, calib).fit(rows).score
        return lambda r: sc(r) * (k if r.get("classification") == "spam" else 1.0)
    return b


CANDS = {
    "PlanA[u,h,c]":            calor([U, H, C]),
    "+phish[u,h,c,p]":         calor([U, H, C, P]),
    "noContent[u,h,p]":        calor([U, H, P]),
    "nlp2[c,p]":               calor([C, P]),
    "phishOnly[p]":            calor([P]),
    "+phish+facet[u,h,c,p,f]": calor([U, H, C, P, F]),
    "noContent+facet[u,h,p,f]":calor([U, H, P, F]),
    "+phish_spamsup":          calor_spamsup([U, H, C, P]),
    "+phish_classgate":        calor_classgate([U, H, C, P]),
    "+phish/beta":             calor([U, H, C, P], "beta"),
    "noContent/beta":          calor([U, H, P], "beta"),
}


def grouped_oof(build):
    groups = defaultdict(list)
    for i in ids:
        groups[AJ.group_of(RICH[i])].append(i)
    oof = {}
    for g, gids in groups.items():
        tr = [RICH[i] for i in ids if AJ.group_of(RICH[i]) != g]
        sc = build(tr)
        for i in gids:
            oof[i] = sc(RICH[i])
    return oof


def roc_pack(rows, scores):
    y = np.array([1 if r["label"] in L.THREAT else (0 if r["label"] in L.NEG else -1) for r in rows])
    s = np.array(scores); keep = y >= 0; y, s = y[keep], s[keep]
    fpr, tpr, thr = roc_curve(y, s); auc = roc_auc_score(y, s)
    cap = 0.05; fp = np.concatenate([fpr[fpr < cap], [cap]]); tp = np.interp(fp, fpr, tpr)
    pauc = np.trapezoid(tp, fp) / cap
    r046 = max([t for f, t in zip(fpr, tpr) if f <= 0.046] or [0])
    return auc, pauc, r046


def band26(build):
    tr, te = L.stratified_split(ids, {i: RICH[i]["label"] for i in ids})
    sc = build([RICH[i] for i in tr]); te_r = [RICH[i] for i in te]
    fl = [sc(r) > 0.255 for r in te_r]
    return L.viewB(te_r, fl), L.slices(te_r, fl)


def prov_holdout(build):
    """Train on synthetic, test on REAL emails (the strongest generalization stress).
    Returns (pAUC[0,.05], R@.046, band-26 metrics) on the real subset, or None if too small."""
    tr = [RICH[i] for i in ids if RICH[i]["provenance"] == "synthetic"]
    te = [RICH[i] for i in ids if RICH[i]["provenance"] == "real"]
    npos = sum(1 for r in te if r["label"] in L.THREAT)
    nneg = sum(1 for r in te if r["label"] in L.NEG)
    if npos < 5 or nneg < 5:
        return None
    sc = build(tr); s = [sc(r) for r in te]
    _, pauc, r046 = roc_pack(te, s)
    fl = [x > 0.255 for x in s]
    return dict(pauc=pauc, r046=r046, npos=npos, nneg=nneg, **L.viewB(te, fl))


def main():
    dist = {l: sum(1 for i in ids if RICH[i]["label"] == l) for l in ("legitimate", "spam", "phishing")}
    print(f"=== View-A fusion sweep on {FN} (n={len(ids)}) dist={dist} ===")
    print(f"{'candidate':26s} {'OOFpAUC':>7s} {'OOFR@.046':>9s} | {'b26R':>5s} {'b26FPR':>6s} "
          f"{'b26F1':>5s} {'prec':>5s} {'rsFPR':>6s} {'ood':>5s} {'spamFlag':>8s}")
    rows = [RICH[i] for i in ids]
    res = {}
    for name, build in CANDS.items():
        oof = grouped_oof(build)
        _, pauc, r046 = roc_pack(rows, [oof[i] for i in ids])
        m, sl = band26(build)
        res[name] = dict(pauc=pauc, r046=r046, **m, **sl)
        print(f"{name:26s} {pauc:7.4f} {r046:9.3f} | {m['recall']:5.3f} {m['fpr']:6.3f} "
              f"{m['f1']:5.3f} {m['precision']:5.3f} {str(sl['real_seen_FPR']):>6s} "
              f"{str(sl['real_ood_recall']):>5s} {str(sl['spam_flag']):>8s}")

    print("\n--- PROVENANCE holdout (train SYNTHETIC -> test REAL) ---")
    ph0 = prov_holdout(next(iter(CANDS.values())))
    if ph0 is None:
        print("  (real subset too small for a holdout on this capture)")
    else:
        print(f"  real test subset: pos(phish)={ph0['npos']} neg(legit+spam)={ph0['nneg']}")
        print(f"{'candidate':26s} {'pAUC':>6s} {'R@.046':>6s} {'b26R':>5s} {'b26FPR':>6s} {'b26F1':>5s} {'prec':>5s}")
        for name, build in CANDS.items():
            ph = prov_holdout(build)
            if ph:
                print(f"{name:26s} {ph['pauc']:6.3f} {ph['r046']:6.3f} {ph['recall']:5.3f} "
                      f"{ph['fpr']:6.3f} {ph['f1']:5.3f} {ph['precision']:5.3f}")
    return res


if __name__ == "__main__":
    main()
