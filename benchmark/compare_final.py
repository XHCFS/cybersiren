#!/usr/bin/env python3
"""compare_final.py — LIVE Plan A (real svc-08 calibrated-OR + #212 svc-06) vs
without-212 / with-212 / PR-213, on the leakage-safe held-out TEST split (SEED=7, 40%).
Also reports fidelity: live Plan A verdicts vs the offline-predicted Plan A."""
import json, random, sys
from collections import Counter
from pathlib import Path
ROOT = Path(__file__).resolve().parent
BROAD = {"suspicious", "phishing", "malware", "spam"}

def load(fn): return {r["id"]: r for r in json.loads((ROOT/fn).read_text())["rows"]}

def prf(tp,fp,fn,tn):
    p=tp/(tp+fp) if tp+fp else 0; r=tp/(tp+fn) if tp+fn else 0
    f=2*p*r/(p+r) if p+r else 0; fpr=fp/(fp+tn) if fp+tn else 0
    return dict(precision=round(p,3),recall=round(r,3),f1=round(f,3),fpr=round(fpr,3))

def view(items,pos,neg):
    tp=fp=fn=tn=0
    for lab,fl in items:
        if lab in pos: tp+=fl; fn+=not fl
        elif lab in neg: fp+=fl; tn+=not fl
    return prf(tp,fp,fn,tn)

def main():
    A=load("big/raw_big_with212.json"); B=load("big/raw_big_without212.json")
    P213=load("big/raw_big_213.json"); LIVE=load("big/raw_big_planAlive.json")
    # offline Plan A prediction (validated blender + exported calib on bigA scores)
    from offline_fusion import blend, band
    cal=json.loads((ROOT/"calib/fusion_calibration_planA.json").read_text())
    OFF={i:band(blend(cal,{"nlp":A[i]["content_risk_score"],"url":A[i]["url_risk_score"],
        "header":A[i]["header_risk_score"],"attachment":A[i]["attachment_risk_score"]})) for i in A}

    ids=sorted(set(A)&set(B)&set(P213)&set(LIVE))
    rng=random.Random(7); by={}
    for i in ids: by.setdefault(A[i]["label"],[]).append(i)
    train=set()
    for lab,lst in by.items():
        lst=list(lst); rng.shuffle(lst); train|=set(lst[:int(len(lst)*0.6)])
    test=[i for i in ids if i not in train]

    # fidelity: live vs offline Plan A (flagged agreement) over ALL common ids
    fa=sum(1 for i in ids if (LIVE[i]["verdict"] in BROAD)==(OFF[i] in BROAD))
    eb=sum(1 for i in ids if LIVE[i]["verdict"]==OFF[i])
    print(f"[FIDELITY] live Plan A vs offline-predicted: flagged-agree {fa}/{len(ids)} ({100*fa/len(ids):.1f}%)  exact-band {100*eb/len(ids):.1f}%", file=sys.stderr)

    def items(src): return [(A[i]["label"], src[i]["verdict"] in BROAD) for i in test]
    runs={"without-212":items(B),"with-212":items(A),"PR-213":items(P213),"PLAN A (live)":items(LIVE)}
    print(f"\n=== HELD-OUT TEST n={len(test)} (leakage-safe) ===")
    for v,vn in (("B","View B THREAT (phish|spam vs legit)"),("A","View A PHISHING only")):
        pos,neg=({"phishing","spam"},{"legitimate"}) if v=="B" else ({"phishing"},{"legitimate","spam"})
        print(f"\n-- {vn} --")
        for name,it in runs.items():
            m=view(it,pos,neg); print(f"  {name:15s} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} FPR={m['fpr']:.3f}")
    print("\n-- real_ood recall / spam-flag / legit-FPR (test) --")
    for name,it in runs.items():
        ood=[(lab,fl) for (lab,fl),i in zip(it,test) if A[i]["difficulty"]=="real_ood" and lab=="phishing"]
        oodr=round(sum(f for _,f in ood)/len(ood),3) if ood else None
        spam=[(l,f) for l,f in it if l=="spam"]; sp=round(sum(f for _,f in spam)/len(spam),3) if spam else None
        leg=[(l,f) for l,f in it if l=="legitimate"]; fp=round(sum(f for _,f in leg)/len(leg),3) if leg else None
        print(f"  {name:15s} ood={str(oodr):6s} spam_flag={str(sp):6s} legit_FPR={fp}")

if __name__=="__main__": main()
