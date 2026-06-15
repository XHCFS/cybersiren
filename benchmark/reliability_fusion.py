"""
Reliability-weighted NOISY-OR fusion — the reliable, generalizable aggregator.
  P(phish) = 1 - Π_present ( 1 - reliability_c · score_c/100 )
A clean channel is NEUTRAL (never dilutes a confident one); each channel can only ADD
risk; reliabilities (from measured channel precision) down-weight the unreliable lexical
URL so 'url alone' defers to the URL service instead of false-positiving on legit links.
Monotonic, interpretable, generalizes (structural — not fit to an ambiguous joint dist),
and pure arithmetic -> drops into Go.
"""
import csv, numpy as np, json
from sklearn.metrics import average_precision_score
R = {"nlp": 1.00, "url": 0.22, "header": 0.78}
def fuse(nlp, url, hdr):
    pnot = (1 - R["nlp"]*min(max(nlp,0),100)/100)
    if url is not None: pnot *= (1 - R["url"]*min(max(url,0),100)/100)
    if hdr is not None: pnot *= (1 - R["header"]*min(max(hdr,0),100)/100)
    return 1 - pnot
def load(p):
    out=[]
    for r in csv.DictReader(open(p)):
        out.append((float(r["nlp"]), float(r["url"]) if r["url"] not in ("","nan") else None,
                    float(r["header"]) if r["header"] not in ("","nan") else None, int(r["y"])))
    return out
def ev(rows,name):
    s=np.array([fuse(*r[:3]) for r in rows]); y=np.array([r[3] for r in rows])
    neg=np.sort(s[y==0])[::-1]; t=neg[int(0.01*len(neg))]; p=s>t
    tp=((p)&(y==1)).sum(); fp=((p)&(y==0)).sum(); fn=((~p)&(y==1)).sum()
    print(f"  {name:30} recall@1%FPR {tp/(tp+fn)*100:5.1f}%  FPR {fp/(y==0).sum()*100:4.1f}%  PR-AUC {average_precision_score(y,s):.3f}  (op.thr={t:.2f})")
print("=== reliability NOISY-OR (fit-free; reliabilities from precision) ===")
ev(load("benchmark/fusion_corpus.csv"),"realistic corpus")
ev(load("benchmark/fusion_features.csv"),"stress benchmark (cross-dist)")
print("\n=== ADVERSARIAL FUSION BATTERY (threshold 0.5) ===")
bat=[("text-only phish (BEC)",(92,None,5),1),("header-only phish",(3,None,88),1),
 ("multi-channel phish",(85,90,80),1),("soft multi (nlp55,hdr60)",(55,None,60),1),
 ("url-only phish [URL-svc job]",(3,95,5),1),("legit + ONE noisy url",(3,92,3),0),
 ("legit + MANY noisy urls",(4,97,3),0),("legit forwarded (hdr 45)",(3,None,45),0),
 ("legit security-notice (nlp 35)",(35,None,3),0),("legit OTP/transactional (nlp 12)",(12,30,8),0),
 ("all clean",(3,2,2),0)]
ok=0
for nm,(n,u,h),lab in bat:
    p=fuse(n,u,h)*100; v=p>50; g=(v==bool(lab)); ok+=g
    print(f"   {nm:34} P={p:5.1f}% -> {'PHISH' if v else 'benign':6} {'OK' if g else 'XX  '+('FP' if lab==0 else '(miss: URL-svc resolves)')}")
print(f"   battery: {ok}/{len(bat)} (url-only 'miss' is by-design deferral to the URL service)")
json.dump({"version":"reliability-noisy-or-v1","reliabilities":R,"threshold":0.5,
  "formula":"P = 1 - Π_present (1 - reliability_c · score_c/100)",
  "rationale":"clean channel neutral (no dilution); reliabilities from measured channel precision; URL down-weighted (lexical-only) so url-alone defers to URL service; raise URL reliability once it runs op_p+allowlist."},
  open("benchmark/artifacts/reliability_fusion_v1.json","w"),indent=2)
print("\nsaved -> benchmark/artifacts/reliability_fusion_v1.json")
