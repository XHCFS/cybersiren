"""
Export the SHIPPED calibration artifact (corrected design) + parity fixture.
  nlp, header : isotonic P(malicious|score) from the consistent real base.
  url         : NEUTRAL placeholder (~0) — lexical/L2 URL is unmeasurable on a static
                benchmark and the lexical signal HURTS fusion; URL re-enters as an
                AUTHORITATIVE channel (TI/guard) once forwarded. Documented in-artifact.
  attachment  : identity p=score/100 — svc-05 score is already a designed risk score;
                preserves the confirmed-malware signal (no hand-set 0.60 crush).
"""
import json, numpy as np, pandas as pd, os
from sklearn.isotonic import IsotonicRegression

df = pd.read_csv("benchmark/consistent_base.csv")
y = df.y.values
N, H = df.nlp_real.values, df.header_real.values
pN, pH = ~np.isnan(N), ~np.isnan(H)

def knots(v, p):
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1); iso.fit(v[p], y[p])
    xs = np.asarray(iso.X_thresholds_, float); ys = np.asarray(iso.y_thresholds_, float)
    kx, ky = [xs[0]], [ys[0]]
    for x, t in zip(xs[1:], ys[1:]):
        if x > kx[-1] + 1e-9: kx.append(x); ky.append(t)
        else: ky[-1] = t
    return iso, [round(float(x), 4) for x in kx], [round(float(t), 6) for t in ky]

isoN, kxN, kyN = knots(N, pN)
isoH, kxH, kyH = knots(H, pH)

# final calibration: fuse raw via OR over per-channel isotonic, then isotonic raw->P(mal).
def per_channel_p(v, p, iso):
    return np.where(p, np.minimum(iso.predict(np.nan_to_num(v)), 0.999), 0.0)
pNc = per_channel_p(N, pN, isoN)
pHc = per_channel_p(H, pH, isoH)
raw = (1 - (1 - pNc) * (1 - pHc)) * 100  # url neutral, attachment absent in calib set
isoF = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1); isoF.fit(raw, y)
xsF = np.asarray(isoF.X_thresholds_, float); ysF = np.asarray(isoF.y_thresholds_, float)
kxF, kyF = [xsF[0]], [ysF[0]]
for x, t in zip(xsF[1:], ysF[1:]):
    if x > kxF[-1] + 1e-9: kxF.append(x); kyF.append(t)
    else: kyF[-1] = t
kxF = [round(float(x), 4) for x in kxF]; kyF = [round(float(t), 6) for t in kyF]

art = {
    "version": "fusion-calibration-v1",
    "objective": "maliciousness: positive = (label != legitimate)",
    "method": "per-channel calibration -> probabilistic-OR -> final isotonic calibration",
    "fused_formula": "raw = 100*(1 - prod_present(1 - clip(calib_c(score_c),0,cap))); risk = 100*final(raw)",
    "interpolation": "piecewise-linear between knots; clip below x[0]->y[0], above x[-1]->y[-1]",
    "trained_on": f"benchmark/consistent_base.csv real current-model scores (n={len(df)}, malicious={int(y.sum())})",
    "cap": 0.999,
    "final": {"kind": "isotonic", "x": kxF, "y": kyF, "comment": "maps fused raw score -> calibrated P(malicious)"},
    "channels": {
        "nlp":    {"kind": "isotonic", "x": kxN, "y": kyN, "n_fit": int(pN.sum())},
        "header": {"kind": "isotonic", "x": kxH, "y": kyH, "n_fit": int(pH.sum())},
        # NEUTRAL: lexical URL is noise on static URLs and unmeasurable for L2; contributes ~0.
        # Replace with an authoritative (TI/guard) curve once guard_hit/ti_matched is forwarded.
        "url":    {"kind": "neutral", "x": [0.0, 100.0], "y": [0.0, 0.0], "n_fit": 0,
                   "note": "placeholder; lexical URL excluded pending live-enrichment/authoritative forwarding"},
        # IDENTITY: svc-05 attachment score is already a designed risk score (malicious hash -> high).
        "attachment": {"kind": "identity", "x": [0.0, 100.0], "y": [0.0, 1.0], "n_fit": 0},
    },
}
out_dir = "services/svc-08-decision/internal/engine/calibration"
os.makedirs(out_dir, exist_ok=True)
json.dump(art, open(f"{out_dir}/fusion_calibration_v1.json", "w"), indent=2)
print(f"nlp knots={len(kxN)} y[{kyN[0]:.3f}..{kyN[-1]:.3f}]  header knots={len(kxH)} y[{kyH[0]:.3f}..{kyH[-1]:.3f}]")

# linear-interp helper that the Go code must match exactly
def interp(ch, x):
    c = art["channels"][ch]; xs, ys = c["x"], c["y"]
    if x <= xs[0]: return ys[0]
    if x >= xs[-1]: return ys[-1]
    for i in range(1, len(xs)):
        if x <= xs[i]:
            t = (x - xs[i-1]) / (xs[i] - xs[i-1]) if xs[i] != xs[i-1] else 0.0
            return ys[i-1] + t * (ys[i] - ys[i-1])
    return ys[-1]

def interp_final(x):
    xs, ys = art["final"]["x"], art["final"]["y"]
    if x <= xs[0]: return ys[0]
    if x >= xs[-1]: return ys[-1]
    for i in range(1, len(xs)):
        if x <= xs[i]:
            t = (x - xs[i-1]) / (xs[i] - xs[i-1]) if xs[i] != xs[i-1] else 0.0
            return ys[i-1] + t * (ys[i] - ys[i-1])
    return ys[-1]

def fuse(nlp, url, header, att):
    pnot = 1.0
    for ch, val in (("nlp", nlp), ("url", url), ("header", header), ("attachment", att)):
        if val is None: continue
        p = min(interp(ch, max(0.0, min(100.0, val))), 0.999)
        pnot *= (1 - p)
    raw = (1 - pnot) * 100
    return round(interp_final(raw) * 100, 6)

fix = []
for n, u, h, a in [(100,None,None,None),(90,100,10,None),(3,100,3,None),(0,100,0,None),
                   (60,None,80,None),(3,None,45,None),(35,None,3,None),(None,None,None,None),
                   (50,50,50,50),(-5,150,50,None),(None,None,None,95),(40,40,40,40),
                   (95,None,None,None),(None,None,88,None),(12,30,8,None)]:
    fix.append({"nlp":n,"url":u,"header":h,"attachment":a,"score":fuse(n,u,h,a)})
rng = np.random.default_rng(7)
for i in rng.choice(len(df), 35, replace=False):
    n = None if not pN[i] else float(N[i]); h = None if not pH[i] else float(H[i])
    u = None if np.isnan(df.url_real.values[i]) else float(df.url_real.values[i])
    fix.append({"nlp":n,"url":u,"header":h,"attachment":None,"score":fuse(n,u,h,None)})
json.dump({"fixture": fix}, open(f"{out_dir}/parity_fixture_v1.json", "w"), indent=2)
print(f"wrote artifact + {len(fix)} parity cases. sample: {fix[0]}, {fix[3]}, {fix[10]}")
