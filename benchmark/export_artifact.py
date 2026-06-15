"""
Export the SHIPPED calibration artifact + parity fixture on the CONSISTENT P(phishing)
base, objective = is_phishing. Channels:
  nlp     : isotonic P(phishing|score)  [NLP score is now P(phishing)*100, svc-06 v4]
  header  : isotonic P(phishing|score)
  url     : NEUTRAL in the shipped artifact — the composite url_score conflates an
            authoritative guard/TI 100 with lexical noise, so it stays out (the
            authoritative-guard curve is a follow-up gated on guard_hit/ti_matched
            forwarding). The guard signal is still computed below to exercise the
            URL-present path in the parity fixture.
  attachment: identity (confirmed-malware passthrough)
  final   : isotonic raw-OR (NLP+Header) -> calibrated P(phishing)
"""
import json, numpy as np, pandas as pd, os, csv
from sklearn.isotonic import IsotonicRegression
csv.field_size_limit(10**7)

base = pd.read_csv("benchmark/consistent_base.csv")
ph = pd.read_csv("benchmark/_nlp_phish.csv")[["id", "nlp_phish"]]
df = base.merge(ph, on="id")
# authoritative URL from guard
guard = pd.read_csv("benchmark/_url_guard.csv"); guard["url"] = guard["url"].str.strip()
gmap = dict(zip(guard.url, guard.guard_verdict))
rawu = pd.read_csv("benchmark/cybersiren_e2e_benchmark_representative.csv", engine="python")[["id", "urls"]]
def uo(c):
    if pd.isna(c): return []
    return [u for u in str(c).replace("|", " ").replace(",", " ").split() if u.startswith(("http", "www"))]
ua = {}
for r in rawu.itertuples(index=False):
    us = uo(r.urls); vs = [gmap.get(u.strip(), "unknown") for u in us]
    ua[r.id] = 100.0 if any(v in ("typosquat", "brand-in-subdomain") for v in vs) else (0.0 if (us and all(v == "allowlisted" for v in vs)) else np.nan)
df["url_auth"] = df.id.map(ua)

y = (df.label.values == "phishing").astype(int)   # IS_PHISHING
N, H, U = df.nlp_phish.values, df.header_real.values, df.url_auth.values
pN, pH, pU = ~np.isnan(N), ~np.isnan(H), ~np.isnan(U)

def knots(v, p):
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1); iso.fit(v[p], y[p])
    xs = np.asarray(iso.X_thresholds_, float); ys = np.asarray(iso.y_thresholds_, float)
    kx, ky = [xs[0]], [ys[0]]
    for x, t in zip(xs[1:], ys[1:]):
        if x > kx[-1] + 1e-9: kx.append(x); ky.append(t)
        else: ky[-1] = t
    return iso, [round(float(x), 4) for x in kx], [round(float(t), 6) for t in ky]

isoN, kxN, kyN = knots(N, pN); isoH, kxH, kyH = knots(H, pH)
# URL stays NEUTRAL in the shipped artifact: svc-08 receives only the composite url_score
# and cannot distinguish an authoritative guard/TI 100 from a lexical-noise 100 without
# the guard_hit/ti_matched contract change. The +1-2% from url-authoritative is a
# follow-up gated on that forwarding. final is fit on the NLP+Header OR only.
def pc(v, p, iso): return np.where(p, np.minimum(iso.predict(np.nan_to_num(v)), 0.999), 0.0)
raw = (1 - (1-pc(N,pN,isoN))*(1-pc(H,pH,isoH))) * 100
isoF = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1).fit(raw, y)
xsF = np.asarray(isoF.X_thresholds_, float); ysF = np.asarray(isoF.y_thresholds_, float)
kxF, kyF = [xsF[0]], [ysF[0]]
for x, t in zip(xsF[1:], ysF[1:]):
    if x > kxF[-1] + 1e-9: kxF.append(x); kyF.append(t)
    else: kyF[-1] = t
kxF = [round(float(x), 4) for x in kxF]; kyF = [round(float(t), 6) for t in kyF]

art = {
    "version": "fusion-calibration-v1",
    "objective": "phishing: positive = (label == phishing). Scams are phishing-labelled; benign marketing spam is negative.",
    "method": "per-channel isotonic P(phishing|score) -> probabilistic-OR -> final isotonic",
    "fused_formula": "raw=100*(1-prod_present(1-clip(calib_c(s_c),0,cap))); risk=100*final(raw)",
    "interpolation": "piecewise-linear; clip outside [x0,xN] to y0/yN",
    "trained_on": f"benchmark/consistent_base.csv + _nlp_phish (NLP=P(phishing)); n={len(df)}, phish={int(y.sum())}",
    "cap": 0.999,
    "final": {"kind": "isotonic", "x": kxF, "y": kyF},
    "channels": {
        "nlp":    {"kind": "isotonic", "x": kxN, "y": kyN, "n_fit": int(pN.sum()),
                   "note": "input is svc-06 v4 content_risk = P(phishing)*100"},
        "header": {"kind": "isotonic", "x": kxH, "y": kyH, "n_fit": int(pH.sum())},
        "url":    {"kind": "neutral", "x": [0.0, 100.0], "y": [0.0, 0.0], "n_fit": 0,
                   "note": "NEUTRAL: composite url_score conflates authoritative(guard/TI) with lexical noise; "
                           "re-enable as an authoritative curve once guard_hit/ti_matched is forwarded (follow-up)"},
        "attachment": {"kind": "identity", "x": [0.0, 100.0], "y": [0.0, 1.0], "n_fit": 0},
    },
}
out_dir = "services/svc-08-decision/internal/engine/calibration"
os.makedirs(out_dir, exist_ok=True)
json.dump(art, open(f"{out_dir}/fusion_calibration_v1.json", "w"), indent=2)
print(f"nlp knots={len(kxN)} header knots={len(kxH)} url=neutral final knots={len(kxF)}")

def interp(c, x):
    xs, ys = c["x"], c["y"]; x = max(0.0, min(100.0, x))
    if x <= xs[0]: return ys[0]
    if x >= xs[-1]: return ys[-1]
    for i in range(1, len(xs)):
        if x <= xs[i]:
            dx = xs[i]-xs[i-1]; t = 0.0 if dx == 0 else (x-xs[i-1])/dx
            return ys[i-1]+t*(ys[i]-ys[i-1])
    return ys[-1]
def fuse(n, u, h, a):
    pnot = 1.0
    for ch, v in (("nlp", n), ("url", u), ("header", h), ("attachment", a)):
        if v is None: continue
        c = art["channels"][ch]
        p = min((interp(c, v) if c["kind"] != "identity" else max(0, min(100, v))/100), art["cap"])
        pnot *= (1-p)
    if pnot == 1.0: return 0.0
    return round(interp(art["final"], (1-pnot)*100)*100, 6)
fix = []
for n, u, h, a in [(100,None,None,None),(95,None,None,None),(3,100,3,None),(0,None,80,None),
                   (3,None,45,None),(None,None,None,95),(50,50,50,50),(-5,150,50,None),
                   (None,None,None,None),(60,100,10,None)]:
    fix.append({"nlp":n,"url":u,"header":h,"attachment":a,"score":fuse(n,u,h,a)})
rng = np.random.default_rng(7)
for i in rng.choice(len(df), 40, replace=False):
    n = None if not pN[i] else float(N[i]); h = None if not pH[i] else float(H[i]); u = None if not pU[i] else float(U[i])
    fix.append({"nlp":n,"url":u,"header":h,"attachment":None,"score":fuse(n,u,h,None)})
json.dump({"fixture": fix}, open(f"{out_dir}/parity_fixture_v1.json", "w"), indent=2)
print(f"wrote artifact + {len(fix)} parity cases")
