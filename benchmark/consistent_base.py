"""
THE CONSISTENT BASE. Merge REAL current-model channel scores:
  nlp_real    = current svc-06 ONNX v3 (maliciousness)
  url_real    = real svc-03 L1 model (ml/model.joblib via inference_script)
  header_real = real svc-04 Go scorer (seeded rules, FinalScore=max)
Grade against is_malicious=(label!=legitimate). Verify the drag and rank aggregators.
"""
import pandas as pd, numpy as np
from sklearn.metrics import roc_auc_score, average_precision_score
from sklearn.isotonic import IsotonicRegression

base = pd.read_csv("benchmark/cybersiren_e2e_benchmark_representative.csv", engine="python")[
    ["id", "label", "is_phishing", "family", "difficulty", "provenance", "clean_ood"]]
nlp = pd.read_csv("benchmark/_nlp_real.csv")
url = pd.read_csv("benchmark/_url_real.csv"); url["url_real"] = pd.to_numeric(url.url_real, errors="coerce")
hdr = pd.read_csv("benchmark/_header_scores.csv").rename(columns={"header_score": "header_real"})
df = base.merge(nlp, on="id").merge(url, on="id").merge(hdr, on="id")
df["y"] = (df.label != "legitimate").astype(int)   # MALICIOUSNESS objective
df.to_csv("benchmark/consistent_base.csv", index=False)
print(f"consistent base: n={len(df)}  malicious={df.y.sum()} ({df.y.mean()*100:.1f}%)  "
      f"present: nlp={df.nlp_real.notna().sum()} url={df.url_real.notna().sum()} header={df.header_real.notna().sum()}")

N, U, H, y = df.nlp_real.values, df.url_real.values, df.header_real.values, df.y.values
pN, pU, pH = ~np.isnan(N), ~np.isnan(U), ~np.isnan(H)

def rec_at_fpr(s, yy, fpr=0.01):
    neg = np.sort(s[yy == 0])[::-1]
    thr = neg[max(0, int(fpr*len(neg))-1)]
    return ((s > thr) & (yy == 1)).sum()/max(1, (yy == 1).sum()), thr

print("\n=== INDIVIDUAL real channels (where present), is_malicious ===")
for ch, v, p in [("nlp", N, pN), ("url", U, pU), ("header", H, pH)]:
    s, yy = v[p], y[p]
    if yy.sum() and (yy == 0).sum():
        print(f"  {ch:7} n={p.sum():5d} AUC={roc_auc_score(yy,s):.3f} PR={average_precision_score(yy,s):.3f} recall@1%FPR={rec_at_fpr(s,yy)[0]*100:5.1f}%")

# fusers
def weighted_avg(w=dict(url=.35, header=.30, nlp=.25)):
    o = np.zeros(len(N))
    for i in range(len(N)):
        n=d=0.
        if pN[i]: n+=w["nlp"]*N[i]; d+=w["nlp"]
        if pU[i]: n+=w["url"]*U[i]; d+=w["url"]
        if pH[i]: n+=w["header"]*H[i]; d+=w["header"]
        o[i]=n/d if d else 0
    return o
def nlp_only(): return np.where(pN, np.nan_to_num(N), 0.0)
def max_present():
    o=np.zeros(len(N))
    for i in range(len(N)):
        v=[x for x,p in ((N[i],pN[i]),(U[i],pU[i]),(H[i],pH[i])) if p]; o[i]=max(v) if v else 0
    return o

# calibrated probabilistic-OR (isotonic per channel, fit on train split, eval on test+OOD)
def run_calibrated(seeds=(0,1,2,3,4)):
    ood = df.clean_ood.fillna(0).astype(int).values==1
    res={"test":[], "ood":[]}
    for seed in seeds:
        rng=np.random.default_rng(seed); idx=np.arange(len(df)); tr=np.zeros(len(df),bool)
        for lab in df.label.unique():
            ii=idx[(df.label.values==lab)&(~ood)]; rng.shuffle(ii.copy()) if False else None
            ii=ii.copy(); rng.shuffle(ii); tr[ii[:int(.6*len(ii))]]=True
        te=~tr
        def isofit(v,p):
            m=p&tr; r=IsotonicRegression(out_of_bounds="clip",y_min=0,y_max=1); r.fit(v[m],y[m]); return r
        iN,iU,iH=isofit(N,pN),isofit(U,pU),isofit(H,pH)
        o=np.zeros(len(N))
        for i in range(len(N)):
            pnot=1.
            if pN[i]: pnot*=(1-min(iN.predict([N[i]])[0],0.999))
            if pU[i]: pnot*=(1-min(iU.predict([U[i]])[0],0.999))
            if pH[i]: pnot*=(1-min(iH.predict([H[i]])[0],0.999))
            o[i]=(1-pnot)*100
        r,thr=rec_at_fpr(o[te],y[te]); res["test"].append(r)
        mo=ood&(y==1); res["ood"].append((o[mo]>thr).mean() if mo.sum() else np.nan)
    return res

print("\n=== AGGREGATOR LEADERBOARD (is_malicious, full set unless noted) ===")
for nm, s in [("nlp_only (best single)", nlp_only()),
              ("weighted_avg (DEFAULT)", weighted_avg()),
              ("max_present", max_present())]:
    r1,_=rec_at_fpr(s,y); print(f"  {nm:26} AUC={roc_auc_score(y,s):.3f} recall@1%FPR={r1*100:5.1f}%")
cal=run_calibrated()
print(f"  {'calibrated_OR (5-seed)':26} recall@1%FPR test={np.mean(cal['test'])*100:5.1f}±{np.std(cal['test'])*100:.1f}%  OOD={np.nanmean(cal['ood'])*100:.1f}%")

print("\n=== IS THE SCORE DRAGGED DOWN? (weighted_avg vs best-present-channel) ===")
mp = max_present(); wa = weighted_avg()
pos = y == 1
dragged = (wa < mp - 1e-9) & pos
print(f"  malicious emails where weighted_avg < best single channel: {dragged.sum()}/{pos.sum()} ({dragged.mean()/pos.mean()*100:.0f}% of malicious)")
print(f"  mean drag on those: best={mp[dragged].mean():.1f} -> blended={wa[dragged].mean():.1f}  (lost {mp[dragged].mean()-wa[dragged].mean():.1f} pts)")
r_wa,thr=rec_at_fpr(wa,y); r_mp,_=rec_at_fpr(mp,y)
print(f"  recall@1%FPR: weighted_avg={r_wa*100:.1f}%  vs  max(best-channel oracle)={r_mp*100:.1f}%")
