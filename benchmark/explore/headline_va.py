#!/usr/bin/env python3
"""headline_va.py — the thesis-grade View-A evaluation for a capture.

For the three reference svc-08 fusions (Plan A, +phish, the chosen noContent[u,h,p]),
on ONE capture, it reports:
  1. the raw-model reweighted 3-class accuracy (vs PR #216's 0.952) + per class;
  2. held-out band-26 (calibrated P>0.255) View-A: recall / FPR(legit+spam) / F1 /
     precision with bootstrap 95% CIs, + real-world slices (real_seen FPR, real_ood
     recall, spam-flag);
  3. mechanism-grouped pooled-OOF pAUC[0,.05] + R@.046 (honest OOD);
  4. train-synthetic/test-real PROVENANCE holdout pAUC + R@.046;
  5. grouped-OOF per-family recall (text-phishing families highlighted; PR #216 target=1.0);
  6. an operating-point table for the chosen fusion (recall/FPR/precision vs threshold).

Usage: python3 explore/headline_va.py [capture.json]
"""
import sys
from collections import defaultdict
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parent))
import combiner_lib as L
import adjudicate as AJ
from sklearn.metrics import roc_curve, roc_auc_score

FN = sys.argv[1] if len(sys.argv) > 1 else "big/raw_rich_fp32_3k_v2.json"
RICH = L.load_rich(FN)
ids = sorted(RICH)
rng = np.random.default_rng(7)

U, H, C, P = ("url", AJ.ch_url), ("header", AJ.ch_header), ("nlp", AJ.ch_content), ("phish", AJ.ch_phish)
FUSIONS = {
    "PlanA[u,h,c]":      ([U, H, C], "isotonic"),
    "+phish[u,h,c,p]":   ([U, H, C, P], "isotonic"),
    "noContent[u,h,p]":  ([U, H, P], "isotonic"),
}
CHOSEN = "noContent[u,h,p]"
TEXT = {"phish_nlp_bec", "phish_obvious", "phish_adversarial_homoglyph", "phish_adversarial_leet",
        "phish_adversarial_zerowidth", "real::D6_Nazario", "real::D6_Nigerian"}
FULL_MIX = {"legitimate": 0.852, "phishing": 0.0946, "spam": 0.0534}


def build(chans, calib):
    return lambda rows: AJ.CalOR(chans, calib).fit(rows).score


def grouped_oof(chans, calib):
    g = defaultdict(list)
    for i in ids:
        g[AJ.group_of(RICH[i])].append(i)
    oof = {}
    for grp, gids in g.items():
        tr = [RICH[i] for i in ids if AJ.group_of(RICH[i]) != grp]
        sc = build(chans, calib)(tr)
        for i in gids:
            oof[i] = sc(RICH[i])
    return oof


def roc_pack(rows, scores):
    y = np.array([1 if r["label"] in L.THREAT else (0 if r["label"] in L.NEG else -1) for r in rows])
    s = np.array(scores); keep = y >= 0; y, s = y[keep], s[keep]
    if len(set(y)) < 2:
        return float("nan"), float("nan"), float("nan")
    fpr, tpr, _ = roc_curve(y, s); auc = roc_auc_score(y, s)
    cap = 0.05; fp = np.concatenate([fpr[fpr < cap], [cap]]); tp = np.interp(fp, fpr, tpr)
    return auc, np.trapezoid(tp, fp) / cap, max([t for f, t in zip(fpr, tpr) if f <= 0.046] or [0])


def band_metrics(rows, scores, thr=0.255):
    fl = [s > thr for s in scores]
    return L.viewB(rows, fl), L.slices(rows, fl)


def boot(rows, scores, fn, n=400):
    idx = np.arange(len(rows)); v = []
    for _ in range(n):
        bi = rng.choice(idx, len(idx), replace=True)
        v.append(fn([rows[j] for j in bi], [scores[j] for j in bi]))
    return np.percentile(v, [2.5, 97.5])


def oof_flag_rate(oof, pred, thr=0.255):
    sub = [i for i in ids if pred(RICH[i])]
    return (sum(oof[i] > thr for i in sub) / len(sub), len(sub)) if sub else (None, 0)


def boot_diff_realspam(oof_a, oof_b, thr=0.255, n=400):
    """Bootstrap 95% CI on the real-spam FP-rate difference (a - b)."""
    sub = [i for i in ids if RICH[i]["label"] == "spam" and RICH[i]["provenance"] == "real"]
    if len(sub) < 5:
        return None
    arr = np.array(sub)
    d = []
    for _ in range(n):
        bi = rng.choice(arr, len(arr), replace=True)
        ra = np.mean([oof_a[i] > thr for i in bi]); rb = np.mean([oof_b[i] > thr for i in bi])
        d.append(ra - rb)
    return np.percentile(d, [2.5, 97.5])


def incorpus_multiseed(seeds=(7, 13, 21, 42, 99, 123, 2024, 31, 57, 88)):
    """In-corpus held-out band-26 F1 for noContent vs +phish across seeds (skeptic check:
    is noContent's win in-corpus or only OOD?)."""
    import combiner_lib as CL
    res = {"noContent[u,h,p]": [], "+phish[u,h,c,p]": []}
    for sd in seeds:
        tr, te = CL.stratified_split(ids, {i: RICH[i]["label"] for i in ids}, seed=sd)
        te_r = [RICH[i] for i in te]
        for name in res:
            chans, calib = FUSIONS[name]
            sc = build(chans, calib)([RICH[i] for i in tr])
            fl = [sc(r) > 0.255 for r in te_r]
            res[name].append(L.viewB(te_r, fl)["f1"])
    return res


def model_accuracy():
    print("== (1) RAW MODEL 3-class accuracy (classification head) ==")
    per = {}
    for lab in FULL_MIX:
        sub = [i for i in ids if RICH[i]["label"] == lab]
        per[lab] = sum(1 for i in sub if RICH[i].get("classification") == lab) / len(sub) if sub else float("nan")
    rw = sum(FULL_MIX[l] * per[l] for l in FULL_MIX)
    raw = sum(1 for i in ids if RICH[i].get("classification") == RICH[i]["label"]) / len(ids)
    print(f"   per-class acc: { {l: round(per[l],4) for l in per} }")
    print(f"   raw (this corpus mix) = {raw:.4f} ; reweighted to full mix = {rw:.4f}  (PR #216 = 0.952)\n")


def main():
    dist = {l: sum(1 for i in ids if RICH[i]["label"] == l) for l in ("legitimate", "spam", "phishing")}
    print(f"==== HEADLINE View-A evaluation on {FN} (n={len(ids)}) dist={dist} ====\n")
    model_accuracy()

    train, test = L.stratified_split(ids, {i: RICH[i]["label"] for i in ids})
    te = [RICH[i] for i in test]

    print("== (2) held-out band-26 View-A + bootstrap 95% CI + slices ==")
    for name, (chans, calib) in FUSIONS.items():
        sc = build(chans, calib)([RICH[i] for i in train])
        s_te = [sc(r) for r in te]
        m, sl = band_metrics(te, s_te)
        ci_r = boot(te, s_te, lambda rr, ss: L.viewB(rr, [x > 0.255 for x in ss])["recall"])
        ci_f = boot(te, s_te, lambda rr, ss: L.viewB(rr, [x > 0.255 for x in ss])["fpr"])
        print(f"  {name:18s} R={m['recall']:.3f}[{ci_r[0]:.3f},{ci_r[1]:.3f}] "
              f"FPR={m['fpr']:.3f}[{ci_f[0]:.3f},{ci_f[1]:.3f}] F1={m['f1']:.3f} P={m['precision']:.3f} | "
              f"rsFPR={sl['real_seen_FPR']} ood={sl['real_ood_recall']} spam={sl['spam_flag']}")

    print("\n== (3) grouped-OOF pAUC[0,.05] + R@.046  |  (4) provenance holdout (synth->real) ==")
    oof_cache = {}
    for name, (chans, calib) in FUSIONS.items():
        oof = grouped_oof(chans, calib); oof_cache[name] = oof
        rows = [RICH[i] for i in ids]
        _, pauc, r046 = roc_pack(rows, [oof[i] for i in ids])
        # provenance holdout
        tr_s = [RICH[i] for i in ids if RICH[i]["provenance"] == "synthetic"]
        te_r = [RICH[i] for i in ids if RICH[i]["provenance"] == "real"]
        scr = build(chans, calib)(tr_s); s_r = [scr(r) for r in te_r]
        _, ppauc, pr046 = roc_pack(te_r, s_r)
        print(f"  {name:18s} OOF pAUC={pauc:.3f} R@.046={r046:.3f}  |  prov pAUC={ppauc:.3f} R@.046={pr046:.3f}")

    print(f"\n== (5) grouped-OOF per-family recall @P>0.255 for {CHOSEN} (PR target: text=1.000) ==")
    oof = oof_cache[CHOSEN]
    fams = sorted(set(RICH[i]["family"] for i in ids if RICH[i]["label"] == "phishing"))
    tmin = []
    for f in fams:
        sub = [i for i in ids if RICH[i]["family"] == f and RICH[i]["label"] == "phishing"]
        rec = sum(oof[i] > 0.255 for i in sub) / len(sub)
        tag = "TEXT" if f in TEXT else "    "
        if f in TEXT:
            tmin.append(rec)
        print(f"   {tag} {f:30s} n={len(sub):3d} recall={rec:.3f}")
    print(f"   >>> min TEXT-family recall = {min(tmin):.3f}  (target 1.000)")

    print(f"\n== (6) operating-point table for {CHOSEN} (grouped-OOF scores) ==")
    rows = [RICH[i] for i in ids]
    print(f"   {'thr':>5s} {'recall':>6s} {'FPR':>6s} {'precision':>9s} {'spamFlag':>8s} {'textRec':>7s}")
    for thr in (0.10, 0.15, 0.20, 0.255, 0.35, 0.50):
        fl = [oof[i] > thr for i in ids]
        m = L.viewB(rows, fl); sl = L.slices(rows, fl)
        tr_ = [sum(oof[i] > thr for i in ids if RICH[i]["family"] == f and RICH[i]["label"] == "phishing") /
               max(1, sum(1 for i in ids if RICH[i]["family"] == f and RICH[i]["label"] == "phishing")) for f in TEXT]
        print(f"   {thr:5.3f} {m['recall']:6.3f} {m['fpr']:6.3f} {m['precision']:9.3f} "
              f"{str(sl['spam_flag']):>8s} {min(tr_):7.3f}")

    print("\n== (7) *** CLEAN content-drop evidence: grouped-OOF FP rate on held-out spam (band-26) *** ==")
    print("   (leakage-independent: real-spam flagged-as-phishing is the honest reason to drop content)")
    print(f"   {'fusion':18s} {'real-spam FP':>12s} {'synth-spam FP':>13s} {'real-legit FP':>13s}")
    for name in FUSIONS:
        oc = oof_cache[name]
        rs = oof_flag_rate(oc, lambda r: r["label"] == "spam" and r["provenance"] == "real")
        ss = oof_flag_rate(oc, lambda r: r["label"] == "spam" and r["provenance"] == "synthetic")
        rl = oof_flag_rate(oc, lambda r: r["label"] == "legitimate" and r["provenance"] == "real")
        print(f"   {name:18s} {str(round(rs[0],3) if rs[0] is not None else None):>12s}(n={rs[1]}) "
              f"{str(round(ss[0],3) if ss[0] is not None else None):>9s}(n={ss[1]}) "
              f"{str(round(rl[0],3) if rl[0] is not None else None):>9s}(n={rl[1]})")
    ci = boot_diff_realspam(oof_cache["+phish[u,h,c,p]"], oof_cache[CHOSEN])
    if ci is not None:
        print(f"   bootstrap 95% CI on real-spam FP diff (+phish - noContent): [{ci[0]:.3f}, {ci[1]:.3f}]")

    print("\n== (8) in-corpus multi-seed band-26 F1 (skeptic check: is the win in-corpus or only OOD?) ==")
    ms = incorpus_multiseed()
    for name, fs in ms.items():
        a = np.array(fs)
        print(f"   {name:18s} F1 {a.mean():.3f} +/- {a.std():.3f}  (n_seeds={len(fs)})")
    nc, pp = np.array(ms[CHOSEN]), np.array(ms["+phish[u,h,c,p]"])
    print(f"   noContent beats +phish in-corpus in {int((nc>pp).sum())}/{len(nc)} seeds "
          f"(mean diff {(nc-pp).mean():+.4f}) -> in-corpus ~tie; noContent's edge is OOD real-spam robustness")


if __name__ == "__main__":
    main()
