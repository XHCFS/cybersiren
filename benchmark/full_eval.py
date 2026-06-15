"""
Full multi-channel evaluation of the CyberSiren pipeline on the representative
benchmark. Tests every runnable channel and fuses at SVC-08 weights, then reports
prevalence-aware conclusions (recall/FPR are intrinsic; precision/alert-volume at
the ~85/5/10 representative prevalence reflect deployment reality).

Channels:
  NLP    = the real cycle-12 model (services/svc-06-nlp/nlp/inference.py).
  URL    = the real char-LR lexical model (fusion_export/models/url_char_lr.joblib),
           max url_p over the email's URLs. (Operational op_p needs live enrichment.)
  Header = a rule scorer that mirrors SVC-04's signals (SPF/DKIM/DMARC, brand-display
           vs from-domain mismatch, free-provider exec impersonation, Reply-To
           mismatch, suspicious TLD, relay anomaly). Proxy for the Go service; runs
           on records that carry headers (the synthetic layer). Real body-only
           records expose no headers, so their header channel is absent (SVC-08
           normalises over PRESENT components, exactly as in production).
"""
import os, sys, json, re, numpy as np
from collections import defaultdict
sys.path.insert(0, "services/svc-06-nlp/nlp")
sys.path.insert(0, "fusion_export")
import joblib
from inference import NLPInferenceEngine

THR = 50  # phishing-verdict threshold (content_risk style)
W = {"url": 0.35, "header": 0.30, "nlp": 0.25}  # SVC-08 DefaultWeights (no attachment here)

eng = NLPInferenceEngine(base_dir="scratch_build/cycle12_model"); assert eng.model_ready
urlpipe = joblib.load("fusion_export/models/url_char_lr.joblib")["pipeline"]

SUS_TLD = {"tk", "top", "xyz", "click", "online", "cn", "ru", "info", "zip", "live", "rest", "cam"}
FREE = {"gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "proton.me", "icloud.com", "gmx.com"}
BRANDWORDS = ["microsoft", "paypal", "netflix", "docusign", "dropbox", "apple", "dhl", "amazon", "linkedin", "chase"]


def header_score(h):
    """Mirror SVC-04 signals -> 0..100. None headers -> channel absent."""
    if not h:
        return None
    s = 0
    auth = h.get("Authentication-Results", "")
    if re.search(r"spf=fail", auth): s += 30
    elif re.search(r"spf=softfail", auth): s += 15
    if re.search(r"dkim=fail", auth): s += 15
    elif re.search(r"dkim=none", auth): s += 8
    if re.search(r"dmarc=fail", auth): s += 30
    frm = h.get("From", "")
    m = re.search(r"<([^>]+)>", frm); addr = m.group(1) if m else frm
    fdom = addr.split("@")[-1].lower() if "@" in addr else ""
    disp = frm.split("<")[0].lower()
    ftld = fdom.rsplit(".", 1)[-1] if "." in fdom else ""
    if ftld in SUS_TLD: s += 25
    # brand impersonation: brand word in display but from-domain isn't that brand
    for bw in BRANDWORDS:
        if bw in disp and bw not in fdom:
            s += 35; break
    if ("ceo" in disp or "cfo" in disp or "president" in disp) and fdom in FREE:
        s += 25
    rt = h.get("Reply-To", "")
    if rt:
        rm = re.search(r"@([^>]+)", rt); rdom = rm.group(1).lower() if rm else ""
        if rdom and rdom != fdom: s += 20
    if fdom in FREE and any(w in disp for w in ["support", "security", "team", "service", "admin"]): s += 12
    recv = " ".join(h.get("Received", []) if isinstance(h.get("Received"), list) else [h.get("Received", "")])
    if any("." + t in recv for t in SUS_TLD): s += 10
    return min(100, s)


def url_score(urls):
    if not urls:
        return None
    p = urlpipe.predict_proba(np.array([u.lower() for u in urls]))[:, 1]
    return float(p.max()) * 100


def fuse(parts):
    """parts: dict channel->score (only present channels). Weighted avg over present."""
    num = sum(W[c] * v for c, v in parts.items())
    den = sum(W[c] for c in parts)
    return num / den if den else 0.0


rows = [json.loads(l) for l in open("benchmark/cybersiren_e2e_benchmark_representative.jsonl")]
N = len(rows)
print(f"scoring {N} emails ...", flush=True)
for i, r in enumerate(rows):
    subj = r.get("subject") or (r["headers"]["Subject"] if r.get("headers") else "")
    nlp = eng.predict(subj, r["body_plain"], "")["content_risk_score"]
    hs = header_score(r.get("headers"))
    us = url_score(r.get("urls"))
    parts = {"nlp": nlp}
    if hs is not None: parts["header"] = hs
    if us is not None: parts["url"] = us
    r["_nlp"], r["_hdr"], r["_url"], r["_fused"] = nlp, hs, us, fuse(parts)
    if i % 2000 == 0: print(f"  {i}/{N}", flush=True)

# ── helpers ──────────────────────────────────────────────────────────────────
def ci(p, n):
    p /= 100; return 1.96 * np.sqrt(max(p * (1 - p), 1e-9) / max(n, 1)) * 100

def recall(rs, col):
    a = [r[col] > THR for r in rs if r["label"] == "phishing"]; return (np.mean(a) * 100 if a else 0), len(a)
def fpr(rs, col):
    a = [r[col] > THR for r in rs if r["label"] == "legitimate"]; return (np.mean(a) * 100 if a else 0), len(a)
def spam_as_threat(rs, col):
    a = [r[col] > THR for r in rs if r["label"] == "spam"]; return (np.mean(a) * 100 if a else 0), len(a)

L = "=" * 72
print("\n" + L + f"\nREPRESENTATIVE BENCHMARK — {N} emails  (~85/5/10 legit/spam/phish)\n" + L)

# 1. Standalone channels
print("\n[1] STANDALONE CHANNEL PERFORMANCE (where the channel applies)")
nd, nP = recall(rows, "_nlp"); nf, nL = fpr(rows, "_nlp")
print(f"  NLP    (n_all)         phishing recall {nd:5.1f}% (±{ci(nd,nP):.1f})   legit FPR {nf:4.1f}% (±{ci(nf,nL):.1f})")
urs = [r for r in rows if r["_url"] is not None]
ud, uP = recall(urs, "_url"); uf, uL = fpr(urs, "_url")
print(f"  URL    (url-bearing)   phishing recall {ud:5.1f}% (n={uP})           legit FPR {uf:4.1f}% (n={uL})  [lexical-only; op_p not run]")
hrs = [r for r in rows if r["_hdr"] is not None]
hd, hP = recall(hrs, "_hdr"); hf, hL = fpr(hrs, "_hdr")
print(f"  HEADER (header-bearing) phishing recall {hd:5.1f}% (n={hP})           legit FPR {hf:4.1f}% (n={hL})  [SVC-04 rule proxy; synthetic layer]")

# 2. Fusion vs NLP-alone
print("\n[2] SYSTEM (FUSED) vs NLP-ALONE")
for name, col in [("NLP-alone", "_nlp"), ("FUSED (SVC-08)", "_fused")]:
    d, _ = recall(rows, col); f, _ = fpr(rows, col); s, _ = spam_as_threat(rows, col)
    print(f"  {name:16} phishing recall {d:5.1f}%   legit FPR {f:4.1f}%   spam->threat {s:4.1f}%")

# 3. Prevalence-aware system metrics (fused)
print("\n[3] DEPLOYMENT METRICS AT REPRESENTATIVE PREVALENCE (fused, threshold>50)")
tp = sum(r["label"] == "phishing" and r["_fused"] > THR for r in rows)
fn = sum(r["label"] == "phishing" and r["_fused"] <= THR for r in rows)
fp = sum(r["label"] == "legitimate" and r["_fused"] > THR for r in rows)
sp = sum(r["label"] == "spam" and r["_fused"] > THR for r in rows)
alerts = tp + fp + sp
prec = tp / alerts * 100 if alerts else 0
print(f"  caught {tp} phishing, missed {fn}; {fp} legit + {sp} spam wrongly alerted")
print(f"  precision (PPV) = {prec:.1f}%   |   alerts per 1,000 emails = {alerts/N*1000:.1f}   |   phishing recall = {tp/(tp+fn)*100:.1f}%")

# 4. by difficulty
print("\n[4] FUSED BY DIFFICULTY")
for d in ["trivial", "easy", "medium", "hard", "adversarial", "real_ood", "real_seen"]:
    rs = [r for r in rows if r["difficulty"] == d]
    if not rs: continue
    nph = sum(r["label"] == "phishing" for r in rs); nlg = sum(r["label"] == "legitimate" for r in rs)
    line = f"  {d:12} n={len(rs):5}"
    if nph: dd, _ = recall(rs, "_fused"); line += f"  phishDR={dd:5.1f}%"
    if nlg: ff, _ = fpr(rs, "_fused"); line += f"  legitFPR={ff:4.1f}%"
    print(line)

# 5. channel-owner: complementarity (NLP-alone vs fused on synthetic phish)
print("\n[5] COMPLEMENTARITY — phishing DR by owning channel (synthetic, channel-attributed)")
own = defaultdict(list)
for r in rows:
    if r["label"] == "phishing" and r["provenance"] == "synthetic":
        own[("+".join(r["channels_expected"]) or "none")].append((r["_nlp"] > THR, r["_fused"] > THR))
for k in sorted(own):
    v = own[k]; na = np.mean([a for a, _ in v]) * 100; fa = np.mean([b for _, b in v]) * 100
    print(f"  owner={k:16} NLP-alone {na:5.1f}%  ->  FUSED {fa:5.1f}%   (n={len(v)})")

# 6. honest leakage-free slice
print("\n[6] HONEST SLICES")
co = [r["_nlp"] > THR for r in rows if r["clean_ood"]]
print(f"  clean-OOD real-phishing recall (NLP, leakage-free): {np.mean(co)*100:.1f}% (n={len(co)})")
for prov in ["real", "synthetic"]:
    rs = [r for r in rows if r["provenance"] == prov]
    d, _ = recall(rs, "_fused"); f, _ = fpr(rs, "_fused")
    print(f"  {prov:9} fused: phishing recall {d:5.1f}%   legit FPR {f:4.1f}%")
print(L)
