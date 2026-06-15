"""
CYCLE 1 — robust aggregator selection on CS-E2E-Bench (representative).
Multi-seed held-out evaluation. Channel scores: NLP=real cycle-12, URL=real lexical
char-LR, Header=SVC-04 rule proxy. Goal: pick the aggregator that (a) beats every
individual channel and (b) generalizes (held-out + clean-OOD), without overfitting.
"""
import numpy as np, pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, average_precision_score

df = pd.read_csv("benchmark/cybersiren_e2e_benchmark_representative.csv", engine="python")
y = df.is_phishing.values.astype(int)
N, U, H = df.nlp_score.values, df.url_score.values, df.header_score.values
pN, pU, pH = ~np.isnan(N), ~np.isnan(U), ~np.isnan(H)
ood = df.clean_ood.fillna(0).astype(int).values == 1
labels = df.label.values

def recall_at_fpr(score, yy, fpr=0.01):
    neg = np.sort(score[yy == 0])[::-1]
    if not len(neg): return np.nan, np.nan
    thr = neg[max(0, int(fpr * len(neg)) - 1)]
    return ((score > thr) & (yy == 1)).sum() / max(1, (yy == 1).sum()), thr

# ---------- calibrators ----------
def iso_fit(v, p, tr):
    m = p & tr
    r = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1); r.fit(v[m], y[m]); return r
def platt_fit(v, p, tr):
    m = p & tr
    lr = LogisticRegression(max_iter=1000); lr.fit(v[m].reshape(-1, 1), y[m]); return lr
def iso_pred(r, x): return float(r.predict([x])[0])
def platt_pred(r, x): return float(r.predict_proba([[x]])[0, 1])

# ---------- fusers (return score 0..100) ----------
def f_nlp_only():    return np.where(pN, np.nan_to_num(N), 0.0)
def f_url_only():    return np.where(pU, np.nan_to_num(U), 0.0)
def f_header_only(): return np.where(pH, np.nan_to_num(H), 0.0)
def f_weighted_avg(w=dict(url=.35, header=.30, nlp=.25)):
    o = np.zeros(len(N))
    for i in range(len(N)):
        n = d = 0.
        if pN[i]: n += w["nlp"] * N[i]; d += w["nlp"]
        if pU[i]: n += w["url"] * U[i]; d += w["url"]
        if pH[i]: n += w["header"] * H[i]; d += w["header"]
        o[i] = n / d if d else 0
    return o
def f_noisy_or(R=dict(nlp=1.0, url=0.22, header=0.78)):
    o = np.zeros(len(N))
    for i in range(len(N)):
        pnot = 1.
        for v, r in ((N[i], R["nlp"]), (U[i], R["url"]), (H[i], R["header"])):
            if not np.isnan(v): pnot *= (1 - min(r * max(0, min(100, v)) / 100, 0.999))
        o[i] = (1 - pnot) * 100
    return o
def f_calib_or(cal, pred):
    cN, cU, cH = cal
    o = np.zeros(len(N))
    for i in range(len(N)):
        pnot = 1.
        if pN[i]: pnot *= (1 - min(pred(cN, N[i]), 0.999))
        if pU[i]: pnot *= (1 - min(pred(cU, U[i]), 0.999))
        if pH[i]: pnot *= (1 - min(pred(cH, H[i]), 0.999))
        o[i] = (1 - pnot) * 100
    return o
def f_logreg(cal, pred, tr):
    cN, cU, cH = cal
    def feats():
        fn = np.array([pred(cN, v) if p else 0 for v, p in zip(N, pN)])
        fu = np.array([pred(cU, v) if p else 0 for v, p in zip(U, pU)])
        fh = np.array([pred(cH, v) if p else 0 for v, p in zip(H, pH)])
        return np.column_stack([fn, fu, fh, pN, pU, pH])
    X = feats(); clf = LogisticRegression(max_iter=2000).fit(X[tr], y[tr])
    return clf.predict_proba(X)[:, 1] * 100

SEEDS = [0, 1, 2, 3, 4]
agg = {k: {"test": [], "ood": []} for k in
       ["nlp_only", "url_only", "header_only", "weighted_avg", "noisy_or(handset)",
        "calib_OR(isotonic)", "calib_OR(platt)", "logreg_stack(iso)"]}

for seed in SEEDS:
    rng = np.random.default_rng(seed); idx = np.arange(len(df)); tr = np.zeros(len(df), bool)
    for lab in np.unique(labels):
        ii = idx[(labels == lab) & (~ood)]; rng.shuffle(ii); tr[ii[:int(.6 * len(ii))]] = True
    te = ~tr
    iso = (iso_fit(N, pN, tr), iso_fit(U, pU, tr), iso_fit(H, pH, tr))
    plt = (platt_fit(N, pN, tr), platt_fit(U, pU, tr), platt_fit(H, pH, tr))
    scores = {
        "nlp_only": f_nlp_only(), "url_only": f_url_only(), "header_only": f_header_only(),
        "weighted_avg": f_weighted_avg(), "noisy_or(handset)": f_noisy_or(),
        "calib_OR(isotonic)": f_calib_or(iso, iso_pred),
        "calib_OR(platt)": f_calib_or(plt, platt_pred),
        "logreg_stack(iso)": f_logreg(iso, iso_pred, tr),
    }
    for name, s in scores.items():
        r_te, _ = recall_at_fpr(s[te], y[te], 0.01)
        # OOD recall measured at the test-set global 1% FPR threshold (real operating point)
        _, thr = recall_at_fpr(s[te], y[te], 0.01)
        mo = ood & (y == 1)
        r_ood = (s[mo] > thr).mean()
        agg[name]["test"].append(r_te); agg[name]["ood"].append(r_ood)

print(f"{'aggregator':22} {'recall@1%FPR test':>22} {'OOD recall@op-thr':>20}")
print("-" * 66)
best = None
for name, d in agg.items():
    t = np.array(d["test"]) * 100; o = np.array(d["ood"]) * 100
    print(f"{name:22} {t.mean():8.1f} ± {t.std():4.1f} %        {o.mean():8.1f} ± {o.std():4.1f} %")
print("-" * 66)
nlp = np.array(agg["nlp_only"]["test"]).mean() * 100
for cand in ["calib_OR(isotonic)", "calib_OR(platt)"]:
    c = np.array(agg[cand]["test"]).mean() * 100
    wins = all(a > b for a, b in zip(agg[cand]["test"], agg["nlp_only"]["test"]))
    print(f"{cand}: mean {c:.1f}% vs nlp_only {nlp:.1f}%  | beats nlp_only on ALL {len(SEEDS)} seeds: {wins}")
