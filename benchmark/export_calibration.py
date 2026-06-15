"""
CYCLE 2 — export the isotonic per-channel calibration as a portable, Go-interpolatable
artifact (linear-interp knots = sklearn IsotonicRegression's own interpolation), plus a
parity fixture (input -> expected fused score) so the Go blender can be proven identical.

Two calibrators are produced:
  * SHIPPED  : fit on ALL representative rows (max calibration quality for production).
  * The held-out generalization estimate (96.1%@1%FPR) is established in select_aggregator.py.
"""
import json, numpy as np, pandas as pd
from sklearn.isotonic import IsotonicRegression

df = pd.read_csv("benchmark/cybersiren_e2e_benchmark_representative.csv", engine="python")
y = df.is_phishing.values.astype(int)
COLS = {"nlp": df.nlp_score.values, "url": df.url_score.values, "header": df.header_score.values}

def knots(v, present_y, present_v):
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    iso.fit(present_v, present_y)
    xs = np.asarray(iso.X_thresholds_, float)
    ys = np.asarray(iso.y_thresholds_, float)
    # dedup identical consecutive (x) to keep the knot list minimal & strictly increasing
    keep_x, keep_y = [xs[0]], [ys[0]]
    for x, yy in zip(xs[1:], ys[1:]):
        if x > keep_x[-1] + 1e-9:
            keep_x.append(x); keep_y.append(yy)
        else:
            keep_y[-1] = yy
    return iso, [round(float(x), 4) for x in keep_x], [round(float(v), 6) for v in keep_y]

artifact = {
    "version": "fusion-calibration-v1",
    "method": "per-channel isotonic -> reliability-free probabilistic-OR",
    "fused_formula": "risk = 100 * (1 - prod_present(1 - clip(calib_c(score_c), 0, 0.999)))",
    "interpolation": "piecewise-linear between knots; clip below x[0] to y[0], above x[-1] to y[-1]",
    "trained_on": "benchmark/cybersiren_e2e_benchmark_representative.csv (n=%d, phish=%d)" % (len(df), int(y.sum())),
    "cap": 0.999,
    "channels": {},
}
isos = {}
for ch, v in COLS.items():
    p = ~np.isnan(v)
    iso, kx, ky = knots(v, y[p], v[p])
    isos[ch] = iso
    artifact["channels"][ch] = {"x": kx, "y": ky, "n_fit": int(p.sum())}
    print(f"{ch:7} knots={len(kx):3d}  x[{kx[0]:.1f}..{kx[-1]:.1f}]  y[{ky[0]:.3f}..{ky[-1]:.3f}]")

import os
os.makedirs("services/svc-08-decision/internal/engine/calibration", exist_ok=True)
out = "services/svc-08-decision/internal/engine/calibration/fusion_calibration_v1.json"
json.dump(artifact, open(out, "w"), indent=2)
print("wrote", out)

# ---- parity fixture: fuse with the SHIPPED isotonic, dump (n,u,h)->score ----
def fuse(n, u, h):
    pnot = 1.0
    for ch, val in (("nlp", n), ("url", u), ("header", h)):
        if val is None: continue
        p = min(float(isos[ch].predict([val])[0]), 0.999)
        pnot *= (1 - p)
    return round((1 - pnot) * 100, 6)

fixture = []
cases = [
    (100, None, None), (95, 5, None), (3, 95, 3), (4, 97, 3), (0, 100, 0),
    (3, None, 45), (35, None, 3), (55, None, 60), (40, 40, 40), (85, 90, 80),
    (3, 2, 2), (92, 5, None), (3, None, 88), (None, None, None), (70, 10, 10),
    (50, 50, 50), (49, None, 49), (100, 100, 100), (-5, 150, 50), (12, 30, 8),
]
for n, u, h in cases:
    fixture.append({"nlp": n, "url": u, "header": h, "score": fuse(n, u, h)})
# plus 40 real rows sampled from the benchmark
rng = np.random.default_rng(7)
sample = rng.choice(len(df), 40, replace=False)
for i in sample:
    n = None if np.isnan(COLS["nlp"][i]) else float(COLS["nlp"][i])
    u = None if np.isnan(COLS["url"][i]) else float(COLS["url"][i])
    h = None if np.isnan(COLS["header"][i]) else float(COLS["header"][i])
    fixture.append({"nlp": n, "url": u, "header": h, "score": fuse(n, u, h)})
json.dump({"fixture": fixture}, open("services/svc-08-decision/internal/engine/calibration/parity_fixture_v1.json", "w"), indent=2)
print("wrote parity fixture:", len(fixture), "cases")
print("sample:", fixture[0], fixture[2], fixture[4])
