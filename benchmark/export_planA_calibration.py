#!/usr/bin/env python3
"""export_planA_calibration.py — fit the calibrated-OR on the LIVE component scores
(bigA, #212 maliciousness content) and export a fusion_calibration_v1.json in svc-08's
schema. Fit on the SAME 60% train split as fit_planA.py (SEED=7) so the live A/B's
held-out 40% test metrics stay leakage-safe. Channels fit by isotonic; attachment =
identity; curves exported as the interpolation knots np.interp/predict() consumes."""
import json, random, sys
from pathlib import Path
import numpy as np
from sklearn.isotonic import IsotonicRegression
ROOT = Path(__file__).resolve().parent
SEED = 7
OUT = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "calib" / "fusion_calibration_planA.json")

A = {r["id"]: r for r in json.loads((ROOT/"big/raw_big_with212.json").read_text())["rows"]}
ids = sorted(A)
rng = random.Random(SEED)
by_lab = {}
for i in ids: by_lab.setdefault(A[i]["label"], []).append(i)
train = []
for lab, lst in by_lab.items():
    lst = list(lst); rng.shuffle(lst); train += lst[:int(len(lst)*0.6)]
train = set(train)
is_mal = lambda r: r["label"] != "legitimate"

def fit_channel(key, ymax=0.999):
    xs, ys = [], []
    for i in train:
        v = A[i][key]
        if v is not None:
            xs.append(float(v)); ys.append(1.0 if is_mal(A[i]) else 0.0)
    m = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=ymax)
    m.fit(np.array(xs), np.array(ys))
    return m, len(xs)

iso = {}
nfit = {}
for ch, key in (("nlp","content_risk_score"), ("header","header_risk_score"), ("url","url_risk_score")):
    iso[ch], nfit[ch] = fit_channel(key)

def pc(ch, score):
    if score is None: return None
    if ch == "attachment": return min(0.999, score/100.0)
    return float(min(0.999, max(0.0, iso[ch].predict([float(score)])[0])))

# fit final on train raw
rx, ry = [], []
for i in train:
    pnot = 1.0; present = 0
    for ch, key in (("url","url_risk_score"),("header","header_risk_score"),
                    ("nlp","content_risk_score"),("attachment","attachment_risk_score")):
        p = pc(ch, A[i][key])
        if p is None: continue
        pnot *= (1-p); present += 1
    if present:
        rx.append((1-pnot)*100); ry.append(1.0 if is_mal(A[i]) else 0.0)
final = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
final.fit(np.array(rx), np.array(ry))

def knots(m):
    return [round(float(x), 6) for x in m.X_thresholds_], [round(float(y), 6) for y in m.y_thresholds_]

chans = {}
for ch in ("nlp", "header", "url"):
    x, y = knots(iso[ch])
    chans[ch] = {"kind": "isotonic", "x": x, "y": y, "n_fit": nfit[ch]}
chans["attachment"] = {"kind": "identity", "x": [0.0, 100.0], "y": [0.0, 1.0], "n_fit": 0}
fx, fy = knots(final)

artifact = {
    "version": "planA-v1",
    "objective": "maliciousness: positive = (label != legitimate). Calibrated-OR fusion on #212 (1-P(legit)) content; fit on LIVE pipeline component scores.",
    "method": "per-channel isotonic -> probabilistic-OR -> final isotonic",
    "fused_formula": "raw=100*(1-prod(1-clip(calib_c(score_c),0,cap))); risk=100*final(raw)",
    "interpolation": "piecewise-linear over (x,y) knots (np.interp/clip)",
    "trained_on": f"raw_big_with212.json train split (SEED=7, 60 pct); n_train={len(train)}",
    "cap": 0.999,
    "final": {"kind": "isotonic", "x": fx, "y": fy},
    "channels": chans,
}
Path(OUT).write_text(json.dumps(artifact, indent=2))
print(f"wrote {OUT}", file=sys.stderr)
print(f"  nlp knots={len(chans['nlp']['x'])} header={len(chans['header']['x'])} url={len(chans['url']['x'])} final={len(fx)}", file=sys.stderr)
print(f"  nlp y-range [{min(chans['nlp']['y'])},{max(chans['nlp']['y'])}]  header y-range [{min(chans['header']['y'])},{max(chans['header']['y'])}]", file=sys.stderr)
