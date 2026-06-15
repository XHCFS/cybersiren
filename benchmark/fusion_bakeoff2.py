import csv, numpy as np, warnings, json
warnings.filterwarnings("ignore")
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import roc_auc_score, average_precision_score

def load(path):
    X=[]; y=[]
    for r in csv.DictReader(open(path)):
        nlp=float(r["nlp"]); url=float(r["url"]) if r["url"] else np.nan; hdr=float(r["header"]) if r["header"] else np.nan
        X.append([nlp,url,hdr]); y.append(int(r["y"]))
    return np.array(X), np.array(y)
def feats(X):  # raw + presence flags; NaN->0 for linear
    has=(~np.isnan(X)).astype(float)
    Xz=np.nan_to_num(X,nan=0.0)
    return np.column_stack([Xz, has[:,1], has[:,2]]), np.column_stack([X, has[:,1], has[:,2]])

Xr,yr = load("benchmark/fusion_corpus.csv")           # realistic (train)
Xs,ys = load("benchmark/fusion_features.csv") if False else (None,None)
# stress benchmark for cross-distribution test
Xb=[]; yb=[]
for r in csv.DictReader(open("benchmark/fusion_features.csv")):
    nlp=float(r["nlp"]); url=float(r["url"]) if r["url"] not in ("","nan") else np.nan
    hdr=float(r["header"]) if r["header"] not in ("","nan") else np.nan
    Xb.append([nlp,url,hdr]); yb.append(int(r["y"]))
Xb=np.array(Xb); yb=np.array(yb)
Xr_lin,Xr_gbm=feats(Xr); Xb_lin,Xb_gbm=feats(Xb)

def at1(s,y):
    neg=np.sort(s[y==0])[::-1]; t=neg[int(0.01*len(neg))]; p=s>t
    tp=((p)&(y==1)).sum(); fp=((p)&(y==0)).sum(); fn=((~p)&(y==1)).sum()
    return tp/(tp+fn)*100, fp/(y==0).sum()*100, average_precision_score(y,s)
def wavg(X):  # main's weighted sum over present
    W=np.array([0.25,0.35,0.30]); out=[]
    for row in X:
        present=~np.isnan(row); out.append(np.nansum(W*np.where(present,row,0))/W[present].sum()/100)
    return np.array(out)

print("=== A) 5-fold CV ON THE REALISTIC CORPUS (recall@1%FPR / PR-AUC) ===")
def cv(make,X):
    oof=np.zeros(len(yr)); 
    for tr,te in StratifiedKFold(5,shuffle=True,random_state=0).split(X,yr):
        m=make(); m.fit(X[tr],yr[tr]); oof[te]=m.predict_proba(X[te])[:,1]
    return oof
r,f,a=at1(wavg(Xr),yr); print(f"  weighted-sum (main)        recall {r:5.1f}%  PR-AUC {a:.3f}")
lr=lambda: LogisticRegression(max_iter=3000,class_weight="balanced")
oof_lr=cv(lr,Xr_lin); r,f,a=at1(oof_lr,yr); print(f"  logistic (log-odds pool)   recall {r:5.1f}%  PR-AUC {a:.3f}")
gb=lambda: HistGradientBoostingClassifier(max_depth=4,max_iter=300,monotonic_cst=[1,0,1,0,0])
oof_gb=cv(gb,Xr_gbm); r,f,a=at1(oof_gb,yr); print(f"  monotonic GBM              recall {r:5.1f}%  PR-AUC {a:.3f}")

print("\n=== B) GENERALIZATION: train on REALISTIC corpus -> test on the (different) STRESS benchmark ===")
LR=lr().fit(Xr_lin,yr); GB=gb().fit(Xr_gbm,yr)
r,f,a=at1(wavg(Xb),yb); print(f"  weighted-sum               recall {r:5.1f}%  FPR {f:4.1f}%  PR-AUC {a:.3f}")
r,f,a=at1(LR.predict_proba(Xb_lin)[:,1],yb); print(f"  logistic   (cross-dist)    recall {r:5.1f}%  FPR {f:4.1f}%  PR-AUC {a:.3f}")
r,f,a=at1(GB.predict_proba(Xb_gbm)[:,1],yb); print(f"  GBM        (cross-dist)    recall {r:5.1f}%  FPR {f:4.1f}%  PR-AUC {a:.3f}")

print("\n=== C) logistic coefficients (monotonic check: channel weights should be >=0) ===")
names=["nlp","url","header","has_url","has_header"]
for n,c in zip(names,LR.coef_[0]): print(f"   {n:11} {c:+.4f}")
print(f"   intercept   {LR.intercept_[0]:+.4f}")

print("\n=== D) ADVERSARIAL FUSION BATTERY (P_phish %, logistic) ===")
def P(model,islin,nlp,url,hdr):
    row=[nlp, 0 if url is None else url, 0 if hdr is None else hdr, 0 if url is None else 1, 0 if hdr is None else 1]
    return model.predict_proba(np.array([row]))[0,1]*100
for nm,(n,u,h) in [("text-only phish (BEC)",(92,None,5)),("url-only phish",(3,95,5)),("header-only phish",(3,None,88)),
   ("legit + ONE noisy url",(3,92,3)),("legit + MANY noisy urls(max~95)",(4,95,3)),("legit forwarded(hdr 45)",(3,None,45)),
   ("multi-channel phish",(85,90,80)),("all clean",(3,2,2))]:
    print(f"   {nm:34} logistic={P(LR,1,n,u,h):5.1f}%   GBM={P(GB,0,n,u,h):5.1f}%")

# save logistic coefficients (pure-Go) at 1% FPR threshold from CV
neg=np.sort(oof_lr[yr==0])[::-1]; thr=float(neg[int(0.01*len(neg))])
json.dump({"version":"logodds-fusion-v1","coef":dict(zip(names,LR.coef_[0].tolist())),
  "intercept":float(LR.intercept_[0]),"threshold_p":thr,"features":names,
  "trained_on":"fusion_corpus (realistic correlated, NLP grounded in real scores, multi-URL max)",
  "note":"P=sigmoid(intercept+Σ coef·feature). channel coefs >=0 => monotonic. URL coef low => distrusted."},
  open("benchmark/artifacts/logodds_fusion_v1.json","w"),indent=2)
print("\nsaved -> benchmark/artifacts/logodds_fusion_v1.json (pure-Go coefficients)")
