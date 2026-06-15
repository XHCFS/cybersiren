"""
Finalize the aggregator on the CONSISTENT base (real current-model scores, is_malicious):
 1. confirm calibrated-OR beats NLP-alone on EVERY seed (synergy requirement),
 2. confirm calibration (not raw OR) is what neutralizes the noisy URL channel,
 3. export the SHIPPED isotonic knots + a parity fixture for the Go blender.
"""
import json, numpy as np, pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import roc_auc_score

df = pd.read_csv("benchmark/consistent_base.csv")
N, U, H = df.nlp_real.values, df.url_real.values, df.header_real.values
pN, pU, pH = ~np.isnan(N), ~np.isnan(U), ~np.isnan(H)
y = df.y.values
ood = df.clean_ood.fillna(0).astype(int).values == 1

def rec_at_fpr(s, yy, fpr=0.01):
    neg = np.sort(s[yy == 0])[::-1]; thr = neg[max(0, int(fpr*len(neg))-1)]
    return ((s > thr) & (yy == 1)).sum()/max(1, (yy == 1).sum()), thr

def calib_or(channels, isos):
    o = np.zeros(len(N))
    for i in range(len(N)):
        pnot = 1.
        for (v, p), iso in zip(channels, isos):
            if p[i]: pnot *= (1 - min(iso.predict([v[i]])[0], 0.999))
        o[i] = (1 - pnot)*100
    return o

def raw_or(channels):
    o = np.zeros(len(N))
    for i in range(len(N)):
        pnot = 1.
        for v, p in channels:
            if p[i]: pnot *= (1 - min(max(0, min(100, v[i]))/100, 0.999))
        o[i] = (1-pnot)*100
    return o

ALL = [(N, pN), (U, pU), (H, pH)]
NH = [(N, pN), (H, pH)]
print("=== synergy + ablation (5 seeds, recall@1%FPR on held-out test) ===")
agg = {"nlp_only": [], "calib_OR[N+U+H]": [], "calib_OR[N+H only]": [], "raw_OR[N+U+H]": []}
beats = {"calib_OR[N+U+H]": 0, "calib_OR[N+H only]": 0}
for seed in range(5):
    rng = np.random.default_rng(seed); idx = np.arange(len(df)); tr = np.zeros(len(df), bool)
    for lab in df.label.unique():
        ii = idx[(df.label.values == lab) & (~ood)].copy(); rng.shuffle(ii); tr[ii[:int(.6*len(ii))]] = True
    te = ~tr
    def isofit(v, p):
        m = p & tr; r = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1); r.fit(v[m], y[m]); return r
    iN, iU, iH = isofit(N, pN), isofit(U, pU), isofit(H, pH)
    s_nlp = np.where(pN, np.nan_to_num(N), 0.0)
    s_all = calib_or(ALL, [iN, iU, iH])
    s_nh = calib_or(NH, [iN, iH])
    s_raw = raw_or(ALL)
    rn = rec_at_fpr(s_nlp[te], y[te])[0]
    ra = rec_at_fpr(s_all[te], y[te])[0]
    rh = rec_at_fpr(s_nh[te], y[te])[0]
    rr = rec_at_fpr(s_raw[te], y[te])[0]
    agg["nlp_only"].append(rn); agg["calib_OR[N+U+H]"].append(ra)
    agg["calib_OR[N+H only]"].append(rh); agg["raw_OR[N+U+H]"].append(rr)
    beats["calib_OR[N+U+H]"] += ra > rn; beats["calib_OR[N+H only]"] += rh > rn
for k, v in agg.items():
    print(f"  {k:22} {np.mean(v)*100:5.1f} ± {np.std(v)*100:.1f}%")
print(f"  calib_OR[N+U+H] beats nlp_only on {beats['calib_OR[N+U+H]']}/5 seeds | N+H only: {beats['calib_OR[N+H only]']}/5")

# ---- SHIP: isotonic on ALL data, export knots ----
def knots(v, p):
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1); iso.fit(v[p], y[p])
    xs = np.asarray(iso.X_thresholds_, float); ys = np.asarray(iso.y_thresholds_, float)
    kx, ky = [xs[0]], [ys[0]]
    for x, yy in zip(xs[1:], ys[1:]):
        if x > kx[-1] + 1e-9: kx.append(x); ky.append(yy)
        else: ky[-1] = yy
    return iso, [round(float(x), 4) for x in kx], [round(float(t), 6) for t in ky]
isos = {}; art = {"version": "fusion-calibration-v2-consistent",
                  "objective": "maliciousness: positive = (label != legitimate)",
                  "method": "per-channel isotonic P(malicious|score) -> probabilistic-OR",
                  "fused_formula": "risk = 100*(1 - prod_present(1 - clip(calib_c(score_c),0,0.999)))",
                  "interpolation": "piecewise-linear; clip outside [x0,xN] to y0/yN",
                  "trained_on": f"benchmark/consistent_base.csv real current-model scores (n={len(df)}, mal={int(y.sum())})",
                  "cap": 0.999, "channels": {}}
for ch, v, p in [("nlp", N, pN), ("url", U, pU), ("header", H, pH)]:
    iso, kx, ky = knots(v, p); isos[ch] = iso
    art["channels"][ch] = {"x": kx, "y": ky, "n_fit": int(p.sum())}
    print(f"  ship {ch:7} knots={len(kx):3d}  y[{ky[0]:.3f}..{ky[-1]:.3f}]")
import os
os.makedirs("services/svc-08-decision/internal/engine/calibration", exist_ok=True)
json.dump(art, open("services/svc-08-decision/internal/engine/calibration/fusion_calibration_v1.json", "w"), indent=2)

def fuse(n, u, h):
    pnot = 1.
    for ch, val in (("nlp", n), ("url", u), ("header", h)):
        if val is None: continue
        pnot *= (1 - min(float(isos[ch].predict([val])[0]), 0.999))
    return round((1-pnot)*100, 6)
fix = []
for n, u, h in [(100, None, None), (90, 100, 10), (3, 100, 3), (0, 100, 0), (60, None, 80),
                (3, None, 45), (35, None, 3), (None, None, None), (50, 50, 50), (-5, 150, 50)]:
    fix.append({"nlp": n, "url": u, "header": h, "score": fuse(n, u, h)})
rng = np.random.default_rng(7)
for i in rng.choice(len(df), 40, replace=False):
    n = None if not pN[i] else float(N[i]); u = None if not pU[i] else float(U[i]); h = None if not pH[i] else float(H[i])
    fix.append({"nlp": n, "url": u, "header": h, "score": fuse(n, u, h)})
json.dump({"fixture": fix}, open("services/svc-08-decision/internal/engine/calibration/parity_fixture_v1.json", "w"), indent=2)
print(f"wrote artifact + {len(fix)} parity cases")
