"""Score the FULL representative set with the CURRENT real svc-06 ONNX model (v3)."""
import sys, numpy as np, pandas as pd
sys.path.insert(0, "services/svc-06-nlp/nlp")
from inference import NLPInferenceEngine
eng = NLPInferenceEngine(base_dir="services/svc-06-nlp/nlp"); assert eng.model_ready
df = pd.read_csv("benchmark/cybersiren_e2e_benchmark_representative.csv", engine="python")
def s(row):
    subj = "" if pd.isna(row.subject) else str(row.subject)
    body = "" if pd.isna(row.body_plain) else str(row.body_plain)
    html = "" if pd.isna(row.body_html) else str(row.body_html)
    o = eng.predict(subj, body, html)
    return o.get("content_risk_score", np.nan)
out = []
for i, row in enumerate(df.itertuples(index=False)):
    out.append(s(row))
    if i % 1000 == 0: print(f"  nlp {i}/{len(df)}", flush=True)
pd.DataFrame({"id": df.id, "nlp_real": out}).to_csv("benchmark/_nlp_real.csv", index=False)
print("done -> benchmark/_nlp_real.csv")
