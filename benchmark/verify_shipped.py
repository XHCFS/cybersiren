"""
MANUAL VERIFICATION — apply the SHIPPED artifact (the exact computation the Go
CalibratedORBlender runs, proven to <0.07 parity) over the consistent real-model base
and confirm it beats every individual channel and the production default.
"""
import json, numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score

art = json.load(open("services/svc-08-decision/internal/engine/calibration/fusion_calibration_v1.json"))
df = pd.read_csv("benchmark/consistent_base.csv")
y = df.y.values

def interp(curve, x):
    xs, ys = curve["x"], curve["y"]
    x = max(0.0, min(100.0, x))
    if x <= xs[0]: return ys[0]
    if x >= xs[-1]: return ys[-1]
    for i in range(1, len(xs)):
        if x <= xs[i]:
            dx = xs[i]-xs[i-1]
            t = 0.0 if dx == 0 else (x-xs[i-1])/dx
            return ys[i-1]+t*(ys[i]-ys[i-1])
    return ys[-1]

def shipped_score(nlp, url, hdr, att):
    pnot = 1.0
    for ch, v in (("nlp", nlp), ("url", url), ("header", hdr), ("attachment", att)):
        if v is None: continue
        c = art["channels"][ch]
        p = min(interp(c, v) if c["kind"] != "identity" else max(0, min(100, v))/100, art["cap"])
        pnot *= (1-p)
    if pnot == 1.0: return 0.0
    raw = (1-pnot)*100
    return interp(art["final"], raw)*100

N, U, H = df.nlp_real.values, df.url_real.values, df.header_real.values
def g(v): return None if (isinstance(v, float) and np.isnan(v)) else float(v)
fused = np.array([shipped_score(g(N[i]), g(U[i]), g(H[i]), None) for i in range(len(df))])

def rec_at_fpr(s, fpr=0.01):
    neg = np.sort(s[y == 0])[::-1]; thr = neg[max(0, int(fpr*len(neg))-1)]
    return ((s > thr) & (y == 1)).sum()/max(1, (y == 1).sum()), thr

print("="*70)
print("SHIPPED calibrated-OR vs individual channels & default (is_malicious, full base)")
print("="*70)
nlp_only = np.where(~np.isnan(N), np.nan_to_num(N), 0.0)
def wavg():
    o = np.zeros(len(N)); w = dict(url=.35, header=.30, nlp=.25)
    for i in range(len(N)):
        n = d = 0.
        if not np.isnan(N[i]): n += w["nlp"]*N[i]; d += w["nlp"]
        if not np.isnan(U[i]): n += w["url"]*U[i]; d += w["url"]
        if not np.isnan(H[i]): n += w["header"]*H[i]; d += w["header"]
        o[i] = n/d if d else 0
    return o
rows = [("NLP alone", nlp_only), ("URL alone", np.where(~np.isnan(U), np.nan_to_num(U), 0.0)),
        ("Header alone", np.where(~np.isnan(H), np.nan_to_num(H), 0.0)),
        ("weighted_avg (old default)", wavg()), ("SHIPPED calibrated-OR", fused)]
for nm, s in rows:
    r1, thr = rec_at_fpr(s)
    print(f"  {nm:28} AUC={roc_auc_score(y,s):.3f}  recall@1%FPR={r1*100:5.1f}%")

print("\n=== synergy: recall by family at the shipped operating threshold ===")
_, thr = rec_at_fpr(fused)
_, twa = rec_at_fpr(wavg())
fam = df.family.fillna("").values
print(f"  {'family':26} {'n':>4} {'NLP':>5} {'Hdr':>5} {'wavg':>6} {'SHIPPED':>8}")
for f in sorted(set(fam[y == 1])):
    m = (fam == f) & (y == 1)
    if m.sum() < 5: continue
    _, tn = rec_at_fpr(nlp_only); _, th = rec_at_fpr(rows[2][1])
    print(f"  {f:26} {m.sum():4d} {(nlp_only[m]>tn).mean()*100:4.0f}% {(H[m]>th).mean()*100 if (~np.isnan(H[m])).any() else 0:4.0f}% "
          f"{(wavg()[m]>twa).mean()*100:5.0f}% {(fused[m]>thr).mean()*100:7.0f}%")
# clean legit calibration sanity
legit = y == 0
print(f"\n  legit mean score: wavg={wavg()[legit].mean():.1f}  SHIPPED={fused[legit].mean():.1f}  (lower=better)")
print(f"  malicious mean score: wavg={wavg()[y==1].mean():.1f}  SHIPPED={fused[y==1].mean():.1f}")
