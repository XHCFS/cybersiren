"""
Realistic fusion-training corpus (score-triples). Fixes the stress-benchmark flaws:
 (1) CORRELATED channels like reality (phishing usually bad on >1 channel; 'signal is
     somewhere'); (2) every email has a header; URLs on a realistic subset, MULTIPLE per
     email -> URL channel = MAX over links (so legit w/ many links is noisier); (3) NLP
     grounded in REAL email scores. Includes the lexical-URL false-positive behaviour so
     the aggregator learns to distrust an uncorroborated URL.
"""
import csv, numpy as np
rng = np.random.default_rng(7)
rows = list(csv.DictReader(open("benchmark/fusion_features.csv")))
_pn = [float(r["nlp"]) for r in rows if r["prov"] == "real" and r["y"] == "1"]
_bn = [float(r["nlp"]) for r in rows if r["prov"] == "real" and r["y"] == "0"]
phish_nlp = np.array(_pn if _pn else [80.0]); benign_nlp = np.array(_bn if _bn else [2.0])
def draw(pool): return float(pool[rng.integers(len(pool))])
def beta(a, b): return float(rng.beta(a, b)) * 100
def clip(x): return float(min(100, max(0, x)))

def url_max(present, threat):
    """Email may carry MULTIPLE links; channel score = max over them."""
    if not present: return None
    k = 1 + int(rng.poisson(1.1))                       # 1..~5 links
    if threat:  draws = [beta(6, 2)] + [beta(3, 4) for _ in range(k - 1)]   # >=1 malicious
    else:       draws = [beta(3, 4) for _ in range(k)]                       # all noisy-lexical
    return max(draws)

def phishing():
    nlp = draw(phish_nlp); has_url = rng.random() < 0.6; strong = nlp > 50
    url_threat = (rng.random() < 0.55) if strong else (has_url and rng.random() < 0.8)
    hdr_threat = (rng.random() < 0.65) if strong else (rng.random() < 0.85 if not url_threat else rng.random() < 0.5)
    return nlp, url_max(has_url, url_threat), (beta(6, 2) if hdr_threat else beta(1.5, 8)), 1

def legit():
    nlp = draw(benign_nlp)
    header = beta(2, 5) * 0.7 if rng.random() < 0.12 else beta(1.2, 12)
    return nlp, url_max(rng.random() < 0.30, False), header, 0

def spam():
    nlp = clip(draw(benign_nlp) * 0.5 + rng.normal(20, 12))
    return nlp, url_max(rng.random() < 0.6, False), beta(1.3, 10), 0

def adversarial():
    k = rng.integers(5)
    hp = phish_nlp[phish_nlp > 60]; tp = float(hp[rng.integers(len(hp))]) if len(hp) else 90.0
    if k == 0: return tp, None, beta(1.2, 12), 1                  # text-only phish (BEC)
    if k == 1: return beta(1, 12), url_max(True, True), beta(1.2, 12), 1   # url-only phish
    if k == 2: return beta(1, 12), None, beta(7, 1.5), 1          # header-only phish
    if k == 3: return beta(1.2, 12), url_max(True, False), beta(1.3, 12), 0  # legit, noisy URL alone -> NOT phish
    return beta(1.2, 12), None, beta(3, 4) * 0.8, 0              # legit forwarded (moderate header)

N = 18000
data = []
for fn, frac in [(phishing, .10), (legit, .80), (spam, .05), (adversarial, .05)]:
    for _ in range(int(N * frac)): data.append(fn())
rng.shuffle(data)
with open("benchmark/fusion_corpus.csv", "w") as f:
    f.write("nlp,url,header,y\n")
    for nlp, url, hdr, y in data:
        f.write(f"{clip(nlp):.2f},{'' if url is None else f'{clip(url):.2f}'},{clip(hdr):.2f},{y}\n")
ys = [d[3] for d in data]
print(f"wrote {len(data)} triples -> benchmark/fusion_corpus.csv | phishing {np.mean(ys)*100:.1f}%  url-present {np.mean([d[1] is not None for d in data])*100:.0f}%")
ph = [d for d in data if d[3] == 1 and d[1] is not None]
nl = np.array([d[0] for d in ph]); ur = np.array([d[1] for d in ph]); he = np.array([d[2] for d in ph])
print(f"phishing channel correlation: nlp~url={np.corrcoef(nl,ur)[0,1]:.2f} nlp~header={np.corrcoef(nl,he)[0,1]:.2f} url~header={np.corrcoef(ur,he)[0,1]:.2f}")
lg = [d for d in data if d[3] == 0 and d[1] is not None]
print(f"legit url score: mean={np.mean([d[1] for d in lg]):.0f}  >50={np.mean([d[1]>50 for d in lg])*100:.0f}% (lexical-FP, realistic)")
