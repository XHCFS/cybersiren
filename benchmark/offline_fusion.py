#!/usr/bin/env python3
"""offline_fusion.py — faithful Python reimplementation of svc-08's calibrated-OR
blender (calibrated_blender.go), used to (1) VALIDATE against the real big213 pipeline
run, then (2) compute Plan A = calibrated-OR fusion on with-212 (maliciousness) scores.

Plan A only changes the FUSION, not the channel scores — bigA already captured the
maliciousness-content channel scores, so Plan A = blend(bigA.components, malicious-cal)."""
import json, sys
from collections import Counter
from pathlib import Path
ROOT = Path(__file__).resolve().parent
BROAD = {"suspicious", "phishing", "malware", "spam"}


def load_cal(fn):
    return json.loads((ROOT / "calib" / fn).read_text())


def interp(x, X, Y):  # np.interp w/ clamp — matches pieceWiseLinear.predict
    n = len(X)
    if n == 0: return 0.0
    if x <= X[0]: return Y[0]
    if x >= X[-1]: return Y[-1]
    for i in range(1, n):
        if x <= X[i]:
            dx = X[i] - X[i-1]
            if dx == 0: return Y[i]
            t = (x - X[i-1]) / dx
            return Y[i-1] + t*(Y[i]-Y[i-1])
    return Y[-1]


def channel_prob(cal, name, score):
    s = max(0.0, min(100.0, float(score)))
    ch = cal["channels"].get(name)
    p = interp(s, ch["x"], ch["y"]) if ch else s/100.0
    return max(0.0, min(cal.get("cap", 0.999), p))


def blend(cal, comps):  # comps: dict name->score(int) or None
    pNot = 1.0; present = 0
    for name in ("url", "header", "nlp", "attachment"):
        sc = comps.get(name)
        if sc is None: continue
        pNot *= (1 - channel_prob(cal, name, sc)); present += 1
    if present == 0: return 0.0
    raw = (1 - pNot) * 100
    score = interp(raw, cal["final"]["x"], cal["final"]["y"]) * 100
    return max(0.0, min(100.0, score))


def band(score):
    s = round(score)
    return "benign" if s <= 25 else "suspicious" if s <= 50 else "phishing" if s <= 75 else "malware"


def comps_of(r):
    return {"nlp": r["content_risk_score"], "url": r["url_risk_score"],
            "header": r["header_risk_score"], "attachment": r["attachment_risk_score"]}


def fuse_run(raw_fn, cal):
    rows = json.loads((ROOT / raw_fn).read_text())["rows"]
    out = {}
    for r in rows:
        v = band(blend(cal, comps_of(r)))
        out[r["id"]] = dict(r, verdict=v)
    return out


def main():
    cal_phish = load_cal("cal_phish_v4.json")
    cal_mal = load_cal("cal_malicious_v3.json")

    # ---- VALIDATION: offline calibrated-OR (P-phish cal) on bigB scores ?= real big213 ----
    real213 = {r["id"]: r["verdict"] for r in json.loads((ROOT/"big/raw_big_213.json").read_text())["rows"]}
    off213 = fuse_run("big/raw_big_without212.json", cal_phish)  # bigB = same P(phish) svc-06 as 213
    common = set(real213) & set(off213)
    match = sum(1 for i in common if off213[i]["verdict"] == real213[i])
    # binary (flagged) agreement is what matters for metrics
    bmatch = sum(1 for i in common if (off213[i]["verdict"] in BROAD) == (real213[i] in BROAD))
    print(f"[VALIDATION] offline(P-phish cal, bigB scores) vs real big213: "
          f"exact-band {match}/{len(common)} ({100*match/len(common):.1f}%)  "
          f"flagged-agree {bmatch}/{len(common)} ({100*bmatch/len(common):.1f}%)", file=sys.stderr)

    # ---- PLAN A: calibrated-OR (maliciousness cal) on bigA (with-212) scores ----
    planA = fuse_run("big/raw_big_with212.json", cal_mal)
    (ROOT/"big/raw_big_planA.json").write_text(json.dumps({"label":"planA","rows":list(planA.values())}, indent=2))
    print(f"[PLAN A] wrote big/raw_big_planA.json  verdicts={dict(Counter(r['verdict'] for r in planA.values()))}", file=sys.stderr)


if __name__ == "__main__":
    main()
