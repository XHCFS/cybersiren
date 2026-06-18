"""Validate live enrichment + L2 operational model on the curated live URL sets.
Proves L1 alone vs L1+L2(enriched) fusion. Run from fusion_export/."""
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "scripts"))
from serve import Scorer
import numpy as np
from sklearn.metrics import roc_auc_score

def load(p):
    return [l.strip() for l in open(p) if l.strip() and not l.startswith("#")]
phish = load("live_phishing_urls.txt"); benign = load("live_benign_urls.txt")
urls = phish + benign
y = np.array([1]*len(phish) + [0]*len(benign))
print(f"scoring {len(urls)} live URLs (enrich+L1+L2)... this hits the network", flush=True)

sc = Scorer(models_dir=Path("models"), fusion_mode="mean", threshold=0.5,
            content_gate=False, workers=8, feed_tag="live_eval", url_model="char")
t0 = time.time()
res = sc.score(urls)
print(f"done in {time.time()-t0:.0f}s")
url_p = np.array([r["url_p"] for r in res])
op_p  = np.array([r["op_p"] for r in res])
dep   = np.array([r["deploy_p"] for r in res])
def auc(s):
    try: return roc_auc_score(y, s)
    except Exception: return float("nan")
print(f"\n  L1 (url_p, lexical only)   AUC={auc(url_p):.3f}  phish_med={np.median(url_p[y==1]):.2f} benign_med={np.median(url_p[y==0]):.2f}")
print(f"  L2 (op_p, ENRICHED)        AUC={auc(op_p):.3f}  phish_med={np.median(op_p[y==1]):.2f} benign_med={np.median(op_p[y==0]):.2f}")
print(f"  fusion (deploy_p)          AUC={auc(dep):.3f}  phish_med={np.median(dep[y==1]):.2f} benign_med={np.median(dep[y==0]):.2f}")
# how many enriched successfully (op_p != prior/degraded)
enriched = np.sum(~np.isclose(op_p, op_p[0]))  # rough
print(f"\n  op_p distinct values: {len(set(np.round(op_p,3)))}/{len(op_p)} (low = enrichment mostly failed)")
