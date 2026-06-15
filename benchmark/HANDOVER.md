# svc-08 fusion benchmark — VPS handover

You are continuing a whole-system detection-benchmark effort for the CyberSiren email
pipeline. A model-deployment bug was just found and fixed; the benchmark must be re-run on the
**corrected model**, the best svc-08 decision/fusion re-found, and the result driven to the best
possible numbers for a thesis report. Everything you need is on this branch.

## 0. TL;DR of what happened (read this first)

- The svc-06 NLP service was silently running the **wrong model**: a stale 66.8 MB INT8 export
  instead of the canonical **266 MB fp32 cycle-12** DistilBERT. The INT8 export is unfaithful
  (max|logit-diff| ≈ 82) — it scored intent-based phishing (BEC / wire-fraud / "send me your
  password") as **benign**. That made an earlier benchmark conclude "the NLP model has a ceiling,
  nothing beats the current fusion (Plan A)". **That conclusion was a bug artifact.**
- The model packaging is now fixed on this branch (`make check-nlp-model` verifies the deployed
  model's sha256 == the committed Git-LFS oid of the 266 MB fp32 and reinstalls on any mismatch;
  `inference.py` invalidates the stale ORT optimized-graph cache). So a fresh `make full-up` here
  deploys the **correct fp32 model**.
- A quick re-run on the corrected model (3,000-email subset) already shows the headline improves a
  lot **just from the model fix**, and the best fusion shifts slightly. Your job: reproduce that,
  fix/optimize the svc-07+svc-08 decision on the corrected scores, run the full 10,677 corpus, and
  converge on the best generalizable result.

## 1. Mission

1. Bring up the stack and **verify svc-06 is serving the fp32 model** (do not trust any number until
   this is confirmed — that is the whole point).
2. Re-run the **small (3k) bench** to confirm the corrected-model picture and to **compare every
   candidate svc-08 fusion** on the new score distribution (the aggregator/fusion balance changed).
3. Run the **full (10,677) bench** for tight, thesis-grade numbers (real slices: real_seen FPR,
   real_ood / clean_ood recall, spam).
4. **Keep optimizing** — try structurally different fusions / calibrations / operating points — until
   several rounds yield no real, *generalizable* improvement. Validate every gain on the
   leakage-safe adjudicator, never on an in-corpus number (the overfitting trap).
5. **Correct PR #215** (`bench/svc08-fusion-search`) — its FINDINGS.md says "nothing beats Plan A /
   NLP intent ceiling", which is now wrong. Update it with the corrected-model results + frontier.
6. Produce a clean, honest thesis-ready write-up + the comparison table.

## 2. Environment & setup (the VPS has only docker, gh (logged in), git, claude)

```bash
# clone + this branch (has the model fix + the whole benchmark bundle)
gh repo clone XHCFS/cybersiren    # or: git clone https://github.com/XHCFS/cybersiren
cd cybersiren
git checkout bench/vps-rerun
git lfs install && git lfs pull   # CRITICAL: fetches the 266 MB fp32 model + .joblib/.mmdb

# python deps for the offline analysis (the VPS has none)
python3 -m pip install --user numpy scikit-learn pandas    # or a venv

# verify + install the canonical model at the service path (the fix in action)
make check-nlp-model
#   expect: "source verified == committed LFS model (oid fffedbeef..., 254M)"
#           "ONNX model ready (real file, 254M, sha fffedbeef...)"
#   254M is MiB of the 266 MB (decimal) fp32 — correct. NOT 66.8M (that is the broken INT8).

# bring up the full 23-container stack (first build is slow: Go builds + image pulls)
make full-up    # if this target name differs, see Makefile; it depends on check-nlp-model

# extract the pre-rendered benchmark corpus (no rendering deps needed)
cd benchmark && tar xzf corpus.tar.gz     # -> big/corpus, bigfull/corpus, big/manifest.jsonl, bigfull/manifest.jsonl
```

### VERIFY THE MODEL IS fp32 (gate everything on this)

```bash
# (a) container loaded the 266 MB model, not 66.8 MB:
docker logs cybersiren-nlp-inference 2>&1 | grep -i "ONNX model loaded"   # expect ~265.6 MB
# (b) the model now CATCHES intent-based BEC (the INT8 bug scored these ~2/benign):
docker exec cybersiren-nlp-inference python3 - <<'PY'
import urllib.request, json
for name,subj,body in [
 ("subtle BEC","Quick request","Hi, are you at your desk? I need you to process a wire transfer to a new supplier today. I will send bank details shortly. Keep this confidential."),
 ("benign biz","Q3 review","Hi, could you review the Q3 report before our meeting tomorrow? Thanks."),
]:
    r=json.load(urllib.request.urlopen(urllib.request.Request("http://localhost:8001/predict",
        data=json.dumps({"subject":subj,"body_plain":body}).encode(),
        headers={"Content-Type":"application/json"}),timeout=30))
    print(f"{name:12s} content_risk={r['content_risk_score']:3} class={r['classification']}")
PY
# EXPECT: subtle BEC -> content_risk ~78-100 / phishing ;  benign biz -> ~0 / legitimate
# If subtle BEC is ~2/legitimate, the WRONG model is deployed — STOP and fix before benchmarking.
```

## 3. The benchmark harness (all under `benchmark/`)

- `explore/capture_rich.py` — submits a manifest of .eml through the **live** pipeline and reads back
  per-email component scores (content/url/header/attachment) + the rich svc-06 signals
  (classification / confidence / phishing_probability / #210 facets) by consuming the
  `emails.scored` Kafka topic and joining on `internal_id`. **This is regime B (a live pass).**
- `explore/final_adjudicate.py <capture.json>` — the decisive comparison: (A) stratified held-out
  test (apples-to-apples with the old bar) with bootstrap 95% CIs, and (B) **mechanism-grouped
  pooled out-of-fold** (the honest new-campaign OOD test) on **pAUC over FPR∈[0,0.05]**. This is how
  you tell a real fusion improvement from synthetic-family memorization.
- `explore/adjudicate.py <capture.json>` — calibrated-OR family + isotonic-vs-beta calibration under
  the grouped-OOF adjudicator.
- `explore/bakeoff_rich.py`, `round2.py`, `round3.py` — the fusion design sweeps (calibrated-OR,
  +facet/+phish channels, logistic, GBM, monotone, confidence-interaction).
- `explore/rich_analysis.py`, `missed_anatomy.py` — diagnostics (do the rich signals carry
  orthogonal info? what is missed and why?).
- `explore/{evallib,combiner_lib,calor,cal2}.py` — libs (split, metrics, slices, calibrated-OR with
  pluggable channels + calibrators). Loaders are gz-aware (read the committed `*.json.gz` directly).
- Committed captures (reference): `big/raw_rich_fp32_3k.json.gz` (corrected-model 3k, already run),
  `big/raw_rich_3k.json.gz` + `big/raw_rich_full.json.gz` (the OLD **broken-INT8** captures — keep
  for fp32-vs-int8 comparison), `big/raw_big_*.json.gz` (the old config A/B/C/D captures).

### Metric of record — IMPORTANT: spam is an intended NEGATIVE
Leaving marketing spam **benign is intentional product behaviour** — the threat the system detects is
PHISHING. So the metric is **View-A: positive = phishing, negative = legitimate + spam** (flagging
spam is a FALSE POSITIVE, not a missed threat). Do NOT use View-B (phishing|spam vs legit) and do NOT
chase spam recall — that penalises the system for correctly leaving spam benign. Flagged = verdict ≠
benign (production band: calibrated risk > 25). Fit on TRAIN, evaluate held-out (SEED=7 60/40
stratified). Report the real-world slices separately (real_seen FPR, real_ood / clean_ood phishing
recall) AND the spam-flag rate (LOWER is better — spam should be benign). Corpus ~85% legit / 10%
phishing / 5% spam.

The harness defaults to View-B — switch it to View-A: in `explore/combiner_lib.py` set
`THREAT = ("phishing",)`, and in the view/slice/roc helpers + `final_adjudicate.py` / `adjudicate.py`
use pos={'phishing'}, neg={'legitimate','spam'}. Quick one-off View-A check for Plan A:
```bash
python3 - <<'PY'
import sys; sys.path.insert(0,'explore'); import combiner_lib as L, adjudicate as AJ
RICH=L.load_rich('big/raw_rich_fp32_3k.json'); ids=sorted(RICH)
tr,te=L.stratified_split(ids,{i:RICH[i]['label'] for i in ids}); te=[RICH[i] for i in te]
m=AJ.CalOR([('url',AJ.ch_url),('header',AJ.ch_header),('nlp',AJ.ch_content)],'isotonic').fit([RICH[i] for i in tr])
fl=[m.score(r)>0.255 for r in te]
tp=sum(f for r,f in zip(te,fl) if r['label']=='phishing'); fn=sum(not f for r,f in zip(te,fl) if r['label']=='phishing')
fp=sum(f for r,f in zip(te,fl) if r['label'] in('legitimate','spam')); tn=sum(not f for r,f in zip(te,fl) if r['label'] in('legitimate','spam'))
p=tp/(tp+fp); r=tp/(tp+fn); print(f"View-A phishing: recall={r:.3f} FPR(legit+spam)={fp/(fp+tn):.3f} F1={2*p*r/(p+r):.3f} prec={p:.3f}")
PY
```

## 4. The loop (what to actually run)

```bash
cd benchmark    # scripts expect to run from here; ROOT = this dir

# (1) FAST READ: re-capture the 3k with the corrected model (live, ~10-20 min on 12 cores)
#     NOTE: a FRESH --label each run (svc-02 dedups on Message-ID); jaeger eats RAM (see gotchas).
python3 explore/capture_rich.py --label fp3k --manifest big/manifest.jsonl --out big/raw_rich_fp32_3k.json
python3 explore/final_adjudicate.py big/raw_rich_fp32_3k.json     # which fusion wins; vs the old bar

# (2) Compare ALL fusions / fix the aggregator on the corrected scores. Sweep:
python3 explore/bakeoff_rich.py big/raw_rich_fp32_3k.json
python3 explore/adjudicate.py   big/raw_rich_fp32_3k.json         # isotonic vs beta; calor variants
python3 explore/round2.py big/raw_rich_fp32_3k.json ; python3 explore/round3.py big/raw_rich_fp32_3k.json
#   Add your own candidates in calor.py (channels) / final_adjudicate.py (CANDS). The decision
#   space: fusion math, calibration (isotonic/beta/Platt), which signals (the #210 facets,
#   phishing/spam prob, confidence), per-class operating points, the verdict bands, svc-07
#   degraded/missing-component handling. The current best on the corrected 3k is calibrated-OR +
#   phishing_probability channel (see §5) — try to beat it, generalizably.

# (3) FULL BENCH (thesis): one full live pass with the corrected model (~25-40 min on 12 cores)
python3 explore/capture_rich.py --label fpfull --manifest bigfull/manifest.jsonl --out big/raw_rich_fp32_full.json
python3 explore/final_adjudicate.py big/raw_rich_fp32_full.json   # HEADLINE numbers + bootstrap CIs

# (4) Iterate (2)-(3) until convergence; keep a running_best.json + progress.md.
```

## 5. Current findings on the corrected model (3k) — your starting point

The model fix is a big win, and it is BIGGER on the correct metric (View-A phishing detection),
because the broken INT8 model over-flagged spam (which are View-A false positives).

View-A (PHISHING detection, band-26), Plan A calibrated-OR fusion, broken-INT8 → corrected-fp32:

| metric (View-A) | INT8 (broken) | fp32 (corrected) |
|---|---|---|
| phishing recall | 0.935 | 0.922 |
| FPR (legit+spam) | 0.276 | **0.082** |
| F1 | 0.603 | **0.812** |
| precision | 0.445 | **0.726** |
| spam-flag rate (lower=better) | 0.94 | 0.54 |
| OOD phishing recall | ~0.99 | 1.00 |

Fixing the model lifts phishing-detection F1 from ~0.60 to ~0.81 (precision 0.44→0.73): the INT8
model flagged 94% of spam (false positives) while fp32 leaves much more spam benign. The earlier
"spam recall regression" was a View-B artifact — under the correct View-A it is an IMPROVEMENT.
(Absolute band-26 numbers are calibration-sensitive — a freshly-fit isotonic calor here; do the
rigorous View-A adjudication with bootstrap CIs on the full corpus.)

Best fusion on the corrected 3k under the grouped-OOF adjudicator (this run was View-B — REDO on
View-A): calor_+phish (calibrated-OR + phishing_probability channel) edged Plan A calor_4ch; the
learned combiners (GBM/HistGB/confidence-interaction) were again best in-corpus and worst OOD
(synthetic-family memorization) — confirm they still lose under grouped-OOF on View-A and do NOT
ship them on an in-corpus number.

OPTIMIZATION HEADROOM (View-A): the fp32 model still flags ~54% of spam, which are View-A false
positives inflating FPR(legit+spam). Pushing spam further toward benign (calibration / a spam-class-
aware band / fusion that down-weights spam-class content) is a legitimate lever to improve View-A
precision — provided it does not cost phishing recall and survives grouped-OOF. real_seen-legit FPR
must stay low (it is the real-world FP slice).

## 6. Methodology & integrity (do not skip — this is what makes the result trustworthy)

- Fit calibration/models on TRAIN only; evaluate held-out. Use the **mechanism-grouped pooled-OOF +
  pAUC** adjudicator (`final_adjudicate.py`/`adjudicate.py`) as the standard — single-point recall@FPR
  is threshold-placement noise; per-family AUC is meaningless here (24/25 families are single-class).
- The corpus is partly synthetic and partly overlaps the model's training data; the hard cases are
  synthetic-adversarial. **Any gain that shows up only in-corpus and collapses under grouped-OOF /
  provenance-holdout is overfitting — reject it.** Prefer structural/calibrated/interpretable fusion.
- For any candidate you want to ship, run an adversarial check (a skeptic pass / a refit on a fresh
  split) to find the leakage or artifact that would explain the gain.

## 7. Gotchas (learned the hard way)

- **jaeger is a RAM hog** (in-memory trace store; grew to >10 GB over a long run). It is
  observability-only (not in the detection path). Restart it when it climbs:
  `docker restart cybersiren-jaeger`. Easiest: run a background guard that restarts it past ~6 GB.
- **svc-02 dedups on Message-ID** — use a FRESH `--label` per capture run or re-submits are dropped.
- Throughput is the **sequential svc-06 NLP inference** (~3/s fp32, slower than int8). The lever is
  scaling `svc-06-nlp-pipeline` replicas across the 6 Kafka partitions (+ concurrent inference). The
  capture has RAM/CPU guards and paces submission.
- `capture_rich.py` reads the topic via `docker exec cybersiren-redpanda rpk ...` and the DB via
  `docker exec cybersiren-postgres psql ...` — no host rpk/psql needed.
- Default API `http://localhost:8081`, key `cs_demokey000000000000000000000DEMO` (the demo stack
  seeds it). Adjust `--api/--api-key` if your compose differs.
- Don't run two live pipeline passes at once (one machine). Do offline analysis between passes.

## 8. Deliverable

- Corrected `running_best.json` + `progress.md` (checkpoint as you go — survive context resets).
- The headline full-corpus comparison (corrected model) with the real-world slices + bootstrap CIs,
  the Pareto frontier of generalizable fusions, and the best svc-08 design — pushed as an update to
  **PR #215** (and/or a fresh PR) with an honest write-up. No AI/agent attribution in anything that
  leaves the machine (commits, PRs, comments).
- Be very sure: re-run, cross-check fp32-vs-int8, adversarially verify the winner, and only then call
  it. Spend the time to get the best honest result for the thesis.
```
