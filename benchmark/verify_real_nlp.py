"""
BASE-OF-TRUTH check: run the CURRENT real svc-06 NLP model (ONNX cycle-12, v3 scoring)
on benchmark emails and compare to the nlp_score stored in the representative CSV.
Goal: determine if the CSV is stale / inconsistent with main, and whether current
scoring is superior or inferior for the benchmark's phishing-vs-rest task.
"""
import sys, os, numpy as np, pandas as pd
sys.path.insert(0, "services/svc-06-nlp/nlp")
from inference import NLPInferenceEngine

eng = NLPInferenceEngine(base_dir="services/svc-06-nlp/nlp")
assert eng.model_ready, "NLP model not ready"

df = pd.read_csv("benchmark/cybersiren_e2e_benchmark_representative.csv", engine="python")
# stratified sample for speed + tracing
rng = np.random.default_rng(0)
idx = []
for lab in ["legitimate", "spam", "phishing"]:
    ii = df.index[df.label == lab].to_numpy().copy()
    rng.shuffle(ii); idx += list(ii[:200])
sub = df.loc[idx].copy()

def score(row):
    subj = "" if pd.isna(row.subject) else str(row.subject)
    body = "" if pd.isna(row.body_plain) else str(row.body_plain)
    html = "" if pd.isna(row.body_html) else str(row.body_html)
    out = eng.predict(subj, body, html)
    return out.get("content_risk_score", out.get("content_risk", np.nan))

sub["nlp_current"] = [score(r) for r in sub.itertuples(index=False)]
print("=== stored CSV nlp_score vs CURRENT model nlp_current, by label ===")
g = sub.groupby("label").agg(
    n=("nlp_score", "size"),
    csv_med=("nlp_score", "median"), csv_hi=("nlp_score", lambda s: (s > 50).mean()),
    cur_med=("nlp_current", "median"), cur_hi=("nlp_current", lambda s: (s > 50).mean()),
).round(3)
print(g)
print("\n=== per-row disagreement (|csv - current| > 30) ===")
sub["delta"] = (sub.nlp_score - sub.nlp_current).abs()
print(f"rows with |delta|>30: {(sub.delta>30).sum()}/{len(sub)}  ({(sub.delta>30).mean()*100:.0f}%)")
print("\n=== effect on phishing-vs-rest separability (is_phishing) ===")
from sklearn.metrics import roc_auc_score
y = sub.is_phishing.values
for col in ["nlp_score", "nlp_current"]:
    print(f"  {col:12} ROC-AUC(is_phishing) = {roc_auc_score(y, sub[col]):.3f}   "
          f"spam>50 = {(sub[sub.label=='spam'][col]>50).mean()*100:.0f}%")
sub[["id","label","is_phishing","nlp_score","nlp_current","delta"]].to_csv("benchmark/_nlp_verify.csv", index=False)
print("\nwrote benchmark/_nlp_verify.csv")
