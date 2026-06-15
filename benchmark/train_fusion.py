"""
Learned late-fusion meta-learner vs the baseline operators, on the representative
benchmark. Honest protocol:

  - Features are ONLY the channel scores + presence flags (no label, difficulty,
    provenance, or family — those would leak).
  - Meta-learners are evaluated with 5-fold STRATIFIED cross-validation
    (out-of-fold predictions only) — never trained and tested on the same row.
  - A provenance cross-check (train synthetic -> test real, and reverse) probes
    whether the learned fusion generalizes or just memorizes the synthetic
    channel-isolation structure.

Channels: NLP (cycle-12 model), URL (char-LR lexical max; NaN if no URL),
HEADER (SVC-04 rule proxy; NaN if body-only). Scores cached to features.csv.

Positive class = phishing. Negative = legitimate + spam (spam is not a threat).
"""
import os, sys, json, re, warnings
import numpy as np
warnings.filterwarnings("ignore")
sys.path.insert(0, "services/svc-06-nlp/nlp"); sys.path.insert(0, "fusion_export")
from pathlib import Path

BENCH = Path("benchmark/cybersiren_e2e_benchmark_representative.jsonl")
CACHE = Path("benchmark/fusion_features.csv")
W = {"url": 0.35, "header": 0.30, "nlp": 0.25}

# ── 1. score channels (cached) ───────────────────────────────────────────────
SUS_TLD = {"tk","top","xyz","click","online","cn","ru","info","zip","live","rest","cam"}
FREE = {"gmail.com","outlook.com","yahoo.com","hotmail.com","proton.me","icloud.com","gmx.com"}
BRANDWORDS = ["microsoft","paypal","netflix","docusign","dropbox","apple","dhl","amazon","linkedin","chase"]

def header_score(h):
    if not h: return np.nan
    s=0; auth=h.get("Authentication-Results","")
    if re.search(r"spf=fail",auth): s+=30
    elif re.search(r"spf=softfail",auth): s+=15
    if re.search(r"dkim=fail",auth): s+=15
    elif re.search(r"dkim=none",auth): s+=8
    if re.search(r"dmarc=fail",auth): s+=30
    frm=h.get("From",""); m=re.search(r"<([^>]+)>",frm); addr=m.group(1) if m else frm
    fdom=addr.split("@")[-1].lower() if "@" in addr else ""; disp=frm.split("<")[0].lower()
    ftld=fdom.rsplit(".",1)[-1] if "." in fdom else ""
    if ftld in SUS_TLD: s+=25
    for bw in BRANDWORDS:
        if bw in disp and bw not in fdom: s+=35; break
    if ("ceo" in disp or "cfo" in disp) and fdom in FREE: s+=25
    rt=h.get("Reply-To","")
    if rt:
        rm=re.search(r"@([^>]+)",rt); rdom=rm.group(1).lower() if rm else ""
        if rdom and rdom!=fdom: s+=20
    if fdom in FREE and any(w in disp for w in ["support","security","team","service","admin"]): s+=12
    recv=" ".join(h.get("Received",[]) if isinstance(h.get("Received"),list) else [h.get("Received","")])
    if any("."+t in recv for t in SUS_TLD): s+=10
    return float(min(100,s))

if CACHE.exists():
    import csv
    rows=list(csv.DictReader(open(CACHE)))
    nlp=np.array([float(r["nlp"]) for r in rows]); url=np.array([float(r["url"]) for r in rows])
    hdr=np.array([float(r["header"]) for r in rows]); y=np.array([int(r["y"]) for r in rows])
    prov=np.array([r["prov"] for r in rows])
    print(f"loaded cached features: {len(rows)}")
else:
    import joblib
    from inference import NLPInferenceEngine
    eng=NLPInferenceEngine(base_dir="scratch_build/cycle12_model"); assert eng.model_ready
    urlpipe=joblib.load("fusion_export/models/url_char_lr.joblib")["pipeline"]
    data=[json.loads(l) for l in open(BENCH)]; print(f"scoring {len(data)} emails ...")
    nlp=[]; url=[]; hdr=[]; y=[]; prov=[]
    for i,r in enumerate(data):
        subj=r.get("subject") or (r["headers"]["Subject"] if r.get("headers") else "")
        nlp.append(eng.predict(subj, r["body_plain"], "")["content_risk_score"])
        us=urlpipe.predict_proba(np.array([u.lower() for u in r["urls"]]))[:,1].max()*100 if r["urls"] else np.nan
        url.append(us); hdr.append(header_score(r.get("headers")))
        y.append(1 if r["label"]=="phishing" else 0); prov.append(r["provenance"])
        if i%2000==0: print(f"  {i}/{len(data)}", flush=True)
    nlp=np.array(nlp,float); url=np.array(url,float); hdr=np.array(hdr,float); y=np.array(y); prov=np.array(prov)
    with open(CACHE,"w") as f:
        f.write("nlp,url,header,y,prov\n")
        for a,b,c,d,e in zip(nlp,url,hdr,y,prov): f.write(f"{a},{b},{c},{d},{e}\n")
    print("cached ->", CACHE)

N=len(y); prev=y.mean()
print(f"\nN={N}  phishing prevalence={prev*100:.1f}%  (url present {np.mean(~np.isnan(url))*100:.0f}%, header present {np.mean(~np.isnan(hdr))*100:.0f}%)")

# ── 2. baseline operators ────────────────────────────────────────────────────
def present_stack(i):
    d={"nlp":nlp[i]}
    if not np.isnan(url[i]): d["url"]=url[i]
    if not np.isnan(hdr[i]): d["header"]=hdr[i]
    return d
def op_weighted_avg():
    out=np.zeros(N)
    for i in range(N):
        d=present_stack(i); out[i]=sum(W[c]*v for c,v in d.items())/sum(W[c] for c in d)
    return out
def op_max():
    return np.array([max(present_stack(i).values()) for i in range(N)])
def op_noisy_or():
    out=np.zeros(N)
    for i in range(N):
        d=present_stack(i); p=1.0
        for v in d.values(): p*=(1-min(max(v/100,0),0.999))
        out[i]=(1-p)*100
    return out

# ── 3. metrics helpers ───────────────────────────────────────────────────────
from sklearn.metrics import roc_auc_score, average_precision_score
def thr_at_fpr(scores, target_fpr=0.01):
    neg=np.sort(scores[y==0])[::-1]
    k=int(target_fpr*len(neg)); return neg[k] if k<len(neg) else neg[-1]+1e-9
def report(name, scores):
    t=thr_at_fpr(scores,0.01)
    pred=scores>t
    tp=int(((pred)&(y==1)).sum()); fp=int(((pred)&(y==0)).sum()); fn=int(((~pred)&(y==1)).sum())
    rec=tp/(tp+fn)*100; fprate=fp/(y==0).sum()*100; prec=tp/(tp+fp)*100 if tp+fp else 0
    try: auc=roc_auc_score(y,scores); ap=average_precision_score(y,scores)
    except: auc=ap=float("nan")
    print(f"  {name:24} recall@1%FPR {rec:5.1f}%   FPR {fprate:4.1f}%   precision {prec:5.1f}%   ROC-AUC {auc:.3f}  PR-AUC {ap:.3f}")
    return scores

# ── 4. learned meta-learners (5-fold CV, out-of-fold) ───────────────────────
from sklearn.model_selection import StratifiedKFold
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline

X = np.column_stack([nlp, url, hdr,
                     (~np.isnan(url)).astype(float), (~np.isnan(hdr)).astype(float)])  # +presence flags
Xlr = np.nan_to_num(X, nan=0.0)  # LogReg can't take NaN; flags carry presence
def cv_oof(model, Xin):
    oof=np.zeros(N); skf=StratifiedKFold(5,shuffle=True,random_state=0)
    for tr,te in skf.split(Xin,y):
        m=model(); m.fit(Xin[tr],y[tr]); oof[te]=m.predict_proba(Xin[te])[:,1]*100
    return oof
lr_oof  = cv_oof(lambda: make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")), Xlr)
hgb_oof = cv_oof(lambda: HistGradientBoostingClassifier(max_depth=4, learning_rate=0.1, max_iter=300), X)

print("\n=== OPERATOR BAKE-OFF (threshold set at 1% FPR; phishing prevalence "+f"{prev*100:.0f}%) ===")
print("  -- current system & rule operators --")
report("weighted-avg (SVC-08)", op_weighted_avg())
report("max (loudest wins)", op_max())
report("noisy-OR", op_noisy_or())
print("  -- learned meta-learner (5-fold CV) --")
report("logistic regression", lr_oof)
report("gradient boosting (HGB)", hgb_oof)
report("NLP-alone (reference)", nlp.astype(float))

# ── 5. provenance generalization probe (HGB) ─────────────────────────────────
print("\n=== generalization probe: train on one provenance, test on the other (HGB) ===")
for tr_p, te_p in [("synthetic","real"), ("real","synthetic")]:
    tr=prov==tr_p; te=prov==te_p
    if y[tr].sum()<5 or y[te].sum()<5: print(f"  {tr_p}->{te_p}: insufficient positives"); continue
    m=HistGradientBoostingClassifier(max_depth=4,max_iter=300); m.fit(X[tr],y[tr])
    sc=m.predict_proba(X[te])[:,1]*100
    yt=y[te]; t=np.sort(sc[yt==0])[::-1]; t=t[int(0.01*len(t))] if (yt==0).sum() else 50
    pred=sc>t; tp=((pred)&(yt==1)).sum(); fn=((~pred)&(yt==1)).sum(); fp=((pred)&(yt==0)).sum()
    print(f"  train={tr_p:9} test={te_p:9}  recall@1%FPR {tp/(tp+fn)*100:5.1f}%  FPR {fp/(yt==0).sum()*100:4.1f}%  (n_test={te.sum()})")

# ── 6. what the meta-learner learned (HGB importances + a few rules) ─────────
m=HistGradientBoostingClassifier(max_depth=4,max_iter=300).fit(X,y)
try:
    from sklearn.inspection import permutation_importance
    imp=permutation_importance(m,X,y,n_repeats=5,random_state=0,scoring="average_precision")
    names=["nlp","url","header","has_url","has_header"]
    print("\n=== feature importance (permutation, PR-AUC drop) ===")
    for n,v in sorted(zip(names,imp.importances_mean),key=lambda z:-z[1]): print(f"  {n:10} {v:.3f}")
except Exception as e: print("importance err:",e)
print("\n=== learned behaviour probes (P_phish for crafted channel patterns) ===")
def prob(nlp_,url_,hdr_):
    x=np.array([[nlp_, url_ if url_ is not None else np.nan, hdr_ if hdr_ is not None else np.nan,
                 0.0 if url_ is None else 1.0, 0.0 if hdr_ is None else 1.0]])
    return m.predict_proba(x)[0,1]*100
print(f"  url HIGH alone (nlp0,hdr clean):   {prob(0,95,0):.0f}%   <- should be LOW (lexical-only FP)")
print(f"  url HIGH + header SPOOFED:          {prob(0,95,80):.0f}%   <- should be HIGH")
print(f"  nlp HIGH alone (header clean):      {prob(95,None,0):.0f}%   <- should be HIGH (no dilution)")
print(f"  header HIGH alone (text clean):     {prob(5,None,85):.0f}%   <- should be HIGH")
print(f"  all clean:                          {prob(3,2,0):.0f}%   <- should be ~0")
