"""
Score the benchmark URLs with the REAL svc-03 model (ml/model.joblib via
inference_script.py), exactly as the Go service drives it: one {"url":...} per
line over the subprocess stdin. Email url_score = max over the email's URLs.
"""
import json, subprocess, sys, csv, numpy as np, pandas as pd
csv.field_size_limit(10**7)

df = pd.read_csv("benchmark/cybersiren_e2e_benchmark_representative.csv", engine="python")

def parse_urls(cell):
    if pd.isna(cell) or not str(cell).strip():
        return []
    s = str(cell)
    # the column may be a JSON list or a space/comma-separated string
    try:
        v = json.loads(s)
        if isinstance(v, list):
            return [str(u) for u in v if u]
    except Exception:
        pass
    return [u for u in s.replace("|", " ").replace(",", " ").split() if u.startswith(("http://", "https://", "www."))]

rows = []
for r in df.itertuples(index=False):
    rows.append((r.id, parse_urls(r.urls)))

# unique URLs -> one subprocess pass
uniq = sorted({u for _, us in rows for u in us})
print(f"emails={len(rows)} url-bearing={sum(1 for _,us in rows if us)} unique_urls={len(uniq)}", flush=True)

proc = subprocess.Popen(
    [sys.executable, "services/svc-03-url-analysis/ml/inference_script.py"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
)
score = {}
for u in uniq:
    proc.stdin.write(json.dumps({"url": u}) + "\n"); proc.stdin.flush()
    line = proc.stdout.readline()
    try:
        score[u] = json.loads(line).get("score", np.nan)
    except Exception:
        score[u] = np.nan
proc.stdin.close(); proc.wait()

out = []
for eid, us in rows:
    if not us:
        out.append((eid, ""))
    else:
        vals = [score.get(u) for u in us if score.get(u) is not None and not (isinstance(score.get(u), float) and np.isnan(score.get(u)))]
        out.append((eid, max(vals) if vals else ""))
pd.DataFrame(out, columns=["id", "url_real"]).to_csv("benchmark/_url_real.csv", index=False)
print("done -> benchmark/_url_real.csv", flush=True)
