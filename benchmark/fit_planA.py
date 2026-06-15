#!/usr/bin/env python3
"""fit_planA.py — Plan A done right: calibrated-OR fusion fit on the LIVE component
scores (which bigA captured under #212 maliciousness content), on a leakage-safe 60/40
stratified split. Evaluate Plan A on the held-out TEST split and compare to without-212
/ with-212 / PR-213 on the SAME test emails.

calibrated-OR:  p_c = isotonic_c(score_c);  raw = 100*(1-Π(1-p_c));  P = final(raw);  band by 26/51/76.
Objective = maliciousness (positive = phishing|spam) — matches View B."""
import json, random, sys
from collections import Counter
from pathlib import Path
import numpy as np
from sklearn.isotonic import IsotonicRegression
ROOT = Path(__file__).resolve().parent
BROAD = {"suspicious", "phishing", "malware", "spam"}
SEED = 7

def load(fn): return {r["id"]: r for r in json.loads((ROOT / fn).read_text())["rows"]}
def is_mal(r): return r["label"] != "legitimate"

def band(score):
    s = round(score)
    return "benign" if s <= 25 else "suspicious" if s <= 50 else "phishing" if s <= 75 else "malware"

def prf(tp, fp, fn, tn):
    p = tp/(tp+fp) if tp+fp else 0.0; r = tp/(tp+fn) if tp+fn else 0.0
    f = 2*p*r/(p+r) if p+r else 0.0; fpr = fp/(fp+tn) if fp+tn else 0.0
    return dict(precision=round(p,3), recall=round(r,3), f1=round(f,3), fpr=round(fpr,3))

def view(rows_verdict, pos, neg):  # rows_verdict: list of (label, flagged_bool)
    tp=fp=fn=tn=0
    for lab, fl in rows_verdict:
        if lab in pos: tp+=fl; fn+=not fl
        elif lab in neg: fp+=fl; tn+=not fl
    return prf(tp,fp,fn,tn)

def main():
    A = load("big/raw_big_with212.json")    # Plan A scores (maliciousness content)
    B = load("big/raw_big_without212.json")  # without-212 verdicts
    P213 = load("big/raw_big_213.json")      # PR-213 verdicts
    ids = sorted(set(A)&set(B)&set(P213))

    # stratified 60/40 split by label
    rng = random.Random(SEED)
    by_lab = {}
    for i in ids: by_lab.setdefault(A[i]["label"], []).append(i)
    train, test = [], []
    for lab, lst in by_lab.items():
        rng.shuffle(lst); k=int(len(lst)*0.6); train+=lst[:k]; test+=lst[k:]
    train, test = set(train), set(test)
    print(f"train={len(train)} test={len(test)}", file=sys.stderr)

    def col(ids_, key):
        xs, ys = [], []
        for i in ids_:
            v = A[i][key]
            if v is not None: xs.append(float(v)); ys.append(1.0 if is_mal(A[i]) else 0.0)
        return np.array(xs), np.array(ys)

    # fit per-channel isotonic on TRAIN
    iso = {}
    for ch, key in (("nlp","content_risk_score"),("header","header_risk_score"),("url","url_risk_score")):
        x,y = col(train, key)
        m = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=0.999); m.fit(x,y); iso[ch]=m
    def pc(ch, score):
        if score is None: return None
        if ch=="attachment": return min(0.999, score/100.0)
        return float(min(0.999, max(0.0, iso[ch].predict([float(score)])[0])))

    def raw_of(r):
        pnot=1.0; present=0
        for ch,key in (("url","url_risk_score"),("header","header_risk_score"),
                       ("nlp","content_risk_score"),("attachment","attachment_risk_score")):
            p = pc(ch, r[key])
            if p is None: continue
            pnot*=(1-p); present+=1
        return None if present==0 else (1-pnot)*100

    # fit final isotonic (raw -> is_mal) on TRAIN
    rx,ry=[],[]
    for i in train:
        rw=raw_of(A[i])
        if rw is not None: rx.append(rw); ry.append(1.0 if is_mal(A[i]) else 0.0)
    final = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1.0); final.fit(np.array(rx),np.array(ry))

    def planA_score(r):
        rw=raw_of(r)
        return 0.0 if rw is None else float(final.predict([rw])[0])*100

    # ---- evaluate on TEST ----
    testids = sorted(test)
    # Plan A verdicts on test
    planA = {i: band(planA_score(A[i])) for i in testids}

    def rows_for(verdict_map):
        return [(A[i]["label"], verdict_map[i] in BROAD) for i in testids]
    def verds(src):  # src is a loaded map with 'verdict'
        return [(A[i]["label"], src[i]["verdict"] in BROAD) for i in testids]

    runs = {"without-212": verds(B), "with-212": verds(A), "PR-213": verds(P213), "PLAN A": rows_for(planA)}
    print(f"\n=== HELD-OUT TEST (n={len(testids)}) — leakage-safe ===")
    for v,vn in (("B","View B THREAT (phish|spam vs legit)"),("A","View A PHISHING only")):
        pos,neg = ({"phishing","spam"},{"legitimate"}) if v=="B" else ({"phishing"},{"legitimate","spam"})
        print(f"\n-- {vn} --")
        for name,rv in runs.items():
            m=view(rv,pos,neg); print(f"  {name:13s} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} FPR={m['fpr']:.3f}")

    # real_ood recall + spam flag + legit fpr (test)
    print("\n-- real_ood recall / spam-flagged / legit-FPR (test) --")
    for name,rv in runs.items():
        ood=[(A[i]["label"],fl) for (lab,fl),i in zip(rv,testids) if A[i]["difficulty"]=="real_ood" and lab=="phishing"]
        oodr=round(sum(fl for _,fl in ood)/len(ood),3) if ood else None
        spam=[(lab,fl) for lab,fl in rv if lab=="spam"]; spamr=round(sum(fl for _,fl in spam)/len(spam),3) if spam else None
        leg=[(lab,fl) for lab,fl in rv if lab=="legitimate"]; fpr=round(sum(fl for _,fl in leg)/len(leg),3) if leg else None
        print(f"  {name:13s} ood_recall={str(oodr):6s} spam_flag={str(spamr):6s} legit_FPR={fpr}")

    # Plan A operating-curve: recall@FPR sweep (View B) by varying the benign threshold
    print("\n-- PLAN A operating curve (View B; vary flag threshold on P(mal)*100) --")
    scores=[(planA_score(A[i]), is_mal(A[i]), A[i]["label"]) for i in testids]
    for thr in (10,20,26,30,40,50):
        tp=sum(1 for s,m,l in scores if s>=thr and m); fn=sum(1 for s,m,l in scores if s<thr and m)
        fp=sum(1 for s,m,l in scores if s>=thr and l=="legitimate"); tn=sum(1 for s,m,l in scores if s<thr and l=="legitimate")
        rec=tp/(tp+fn) if tp+fn else 0; fpr=fp/(fp+tn) if fp+tn else 0
        print(f"   thr>={thr:3d}: recall={rec:.3f} FPR={fpr:.3f}")

if __name__=="__main__":
    main()
