# svc-08 fusion search — findings (corrected-model re-run)

> **This supersedes the previous FINDINGS.** The earlier conclusion — *"no svc-08 fusion beats
> Plan A; the residual headroom is an NLP intent-detection ceiling (the model misses BEC /
> intent-based phishing)"* — was a **bug artifact**, measured against a **mis-deployed model**.
> Re-run on the **corrected fp32 model**: (1) the NLP model is excellent and is **not** the ceiling,
> and (2) a structurally simpler fusion beats the shipped Plan A — for a **narrower, honest reason**
> than a first pass suggests (see §3, §5).

_Headline numbers below are the **full corpus (n=10,677)** from a single live pass on the corrected
model; the 3k subset agrees throughout._

## 0. What was actually wrong (the model was never the problem)

svc-06 served a **dangling-symlink / stale INT8 export**, not the canonical 266 MB fp32 cycle-12
DistilBERT (PR #216). It emitted a neutral fallback `content_risk` for every email and scored
intent-based phishing (BEC / wire-fraud) as **benign (~2)** — which produced the old "NLP intent
ceiling" conclusion.

On the **corrected fp32 model** (verified live before any measurement):
- `make check-nlp-model` → 254 MiB, sha `fffedbeef…`; container log "ONNX model loaded … 265.6 MB".
- `/predict`: subtle BEC, credential-phish, gift-card BEC → **phishing, content_risk 100** (INT8 bug
  scored these ~2); benign business / newsletter → legitimate, 0.
- Re-evaluated (PR #216): **95.2% 3-class accuracy, 100% recall on every text-phishing family**.
  Reproduced here: 3-class accuracy **0.9518** (full corpus, natural mix; per-class legit 0.997 /
  phishing 0.794 / spam 0.512).

**Cross-check (fp32 vs INT8):** on the old broken-INT8 capture the phishing-probability head is dead
(phish_p < 0.255 for 100% of *phishing*), so the new fusion collapses there and content-based fusion
looks better — i.e. the finding below is genuinely a property of the **corrected** model, not the harness.

## 1. Metric of record — View-A (phishing)

Leaving marketing **spam benign is intended product behaviour**, so the detected threat is
**phishing**. **View-A: positive = phishing, negative = legitimate + spam** (flagging spam is a false
positive; lower spam-flag is better). The NLP model is 3-class (legit/spam/phishing); "legit-vs-phishing"
is the product framing. Fit on TRAIN, evaluate held-out (SEED=7, 60/40). Operating point = calibrated
**P > 0.255** ("band-26").

## 2. Method

- **Mechanism-grouped pooled out-of-fold** (`adjudicate.py`/`final_adjudicate.py`): sibling families
  merged into mechanism groups; every email scored by a calibrated-OR that never saw its group.
- **The honest discriminator is the held-out spam false-positive rate at the operating point**, not a
  ranking metric. pAUC[0,0.05] turned out to be misleading here (it rewards isotonic-vs-beta
  calibration shape, not the channel choice — see §5), so it is *not* the headline.
- One **live capture** records every per-channel score + svc-06 signal; all fusion shapes are scored
  **offline** from it. calibrated-OR = noisy-OR of per-channel calibrated P(phishing); channels
  U=url_risk, H=header_risk, C=content_risk, P=phishing_probability.

## 3. The decisive result: drop `content_risk`, use the `phishing_probability` head

Chosen svc-08 design: **`noContent[u,h,p]`** = calibrated-OR over {url, header, phishing_probability}.

### 3a. The clean, leakage-free reason — held-out real-spam false positives (grouped-OOF, band-26)

| fusion | **real-spam → phishing** | synth-spam → phishing | real-legit → phishing |
|---|---|---|---|
| Plan A `[u,h,c]` (shipped) | **0.939** (n=330) | 0.000 (n=240) | 0.015 (n=8177) |
| +phish `[u,h,c,p]` | **0.545** | 0.000 | 0.006 |
| **noContent `[u,h,p]`** | **0.036** | 0.000 | 0.009 |

_(Full corpus, grouped-OOF. Bootstrap 95% CI on the +phish − noContent real-spam-FP gap: [0.455, 0.567].)_

`content_risk = 1 − P(legit) = P(spam) + P(phishing)` fires on **real spam** (median content_risk 99;
300/330 ≥ 50) → Plan A flags **94%** of held-out real spam as phishing; +phish 55%; **noContent 3.6%**.
This is **leakage-independent** (it does not depend on the phishing head at all) and is the honest
reason to drop content. The synthetic spam happens to score content≈0, so an **in-corpus test cannot
see this** — synth-spam FP is 0.000 for every fusion. It only appears out-of-mechanism on real spam
(TREC / SpamAssassin): a fusion trained on a real-spam sample *memorises* it (in-corpus spam-flag is
~0 for +phish), but a fusion facing a **new** real-spam campaign over-flags. That is the whole point
of the grouped-OOF test.

### 3b. Dropping content costs no recall

Only **4 / 1010** phishing emails are "content-only rescuable" (content_risk ≥ 80 while phish_p < 0.5,
url < 50, header < 50) — 0.4%. Even on `phish_hard_soft`, where content is the strongest single
channel, noContent gets *higher* grouped-OOF recall (0.52) than +phish — adding content raises the FP
floor and the effective threshold, suppressing soft phish.

### 3c. Held-out band-26 View-A (full corpus, SEED=7, with bootstrap 95% CI)

| fusion | recall | FPR(legit+spam) | F1 | precision | spam-flag |
|---|---|---|---|---|---|
| Plan A `[u,h,c]` (shipped) | 0.898 [0.866,0.926] | 0.044 [0.037,0.050] | 0.774 | 0.680 | 0.58 |
| +phish `[u,h,c,p]` | 0.844 [0.807,0.880] | 0.001 [0.000,0.002] | 0.912 | 0.991 | 0.004 |
| **noContent `[u,h,p]`** | 0.881 [0.846,0.912] | 0.005 [0.003,0.007] | **0.914** | 0.949 | 0.004 |

Plan A keeps high recall but at **FPR 0.044 / precision 0.680** — it flags **58% of spam**. noContent
gets the **best F1 (0.914)** with FPR 0.005 and **+3.7 pts recall over +phish** (0.881 vs 0.844). (For
reference, broken-INT8 Plan A on View-A was F1 ~0.60 / precision ~0.44 / FPR ~0.28 — the model fix
alone lifts F1 to ~0.81; the fusion fix to ~0.91.)

Real-world slices at this operating point (held-out band-26):

| fusion | real_seen-legit FPR | real_ood phishing recall | spam-flag rate |
|---|---|---|---|
| Plan A `[u,h,c]` | 0.010 | 0.993 | 0.579 |
| +phish `[u,h,c,p]` | 0.001 | 0.979 | 0.004 |
| **noContent `[u,h,p]`** | 0.005 | 0.979 | 0.004 |

(real_ood recall here is subject to the training-contamination caveat §5.1; the spam-flag column is
the in-corpus number — the out-of-mechanism real-spam FP is §3a.)

### 3d. noContent vs +phish: a tie in-corpus, a win out-of-distribution

Across 10 stratified-split seeds, in-corpus band-26 F1 is a **statistical tie / slight edge to
+phish**: noContent 0.913 ± 0.013 vs +phish 0.927 ± 0.011 (noContent wins 1/10). **noContent's
advantage is entirely out-of-distribution**: the held-out real-spam FP rate (§3a) and grouped-OOF
pAUC[0,0.05] (noContent 0.902 vs +phish 0.862 vs Plan A 0.597). So the case for noContent is
robustness to a **new** real-spam campaign, *not* an in-corpus number.

### 3e. The whole system reaches the model's ceiling on text phishing

grouped-OOF recall on the text-phishing families: synthetic families (homoglyph, leet, zero-width,
BEC, obvious) = **1.000**; real families Nazario **0.976**, Nigerian **0.996** — i.e. the whole
system realizes essentially all of the raw model's text-phishing recall. header_spoof (a non-text
family) is also caught at 1.000 by the header channel. The synthetic adversarial families are
mechanism-grouped, so the 1.000 is **not** sibling leakage. **Caveat (§5):** the *real* text families
(Nazario/Nigerian) are public corpora plausibly in the model's training data, so their recall is
partly memorization, not generalization. The remaining gaps are non-text and at their ceilings:
`phish_hard_soft` 0.52 (≈ the model's own classification ceiling) and `phish_url_only` 0.02 (degraded
url channel — §5.3).

## 4. What did NOT pan out

- **Learned combiners** (logistic / HistGBM / +confidence): best in-corpus, worst out-of-mechanism
  (family memorization). Never ship on an in-corpus number.
- **Keeping content_risk** (Plan A, +phish): real-spam false positives (§3a).
- **Facet channels** (impersonation/deception/urgency) in the OR: hurt (sparse/noisy → FPs).
- **`spam_probability` channel / spam-suppressor / spam-class gate**: marginal, and `spam_probability`
  in the capture is reconstructed (`max(0, content/100 − phish)`) → no independent info. Dropped.
- **pAUC[0,0.05] as the headline metric**: misleading here — `+phish/beta` (which *keeps* content)
  tops it (0.984 > noContent 0.963) yet flags 96% of real spam. The operating-point spam-FP rate is
  the honest discriminator.

## 5. Honest caveats (must read)

1. **Real-phishing training contamination.** Real phishing (D6 Nigerian/Nazario) are classic public
   corpora plausibly in the NLP training set; their phish_p is memorized-high (100% > 0.255). A
   counterfactual that degrades real-phish phish_p to the synthetic distribution drops the
   provenance-holdout pAUC 0.963 → 0.758 and band-26 real recall 1.000 → 0.875. **So "100% real-phish
   recall" is not evidence of generalization.** The content-drop result (§3a) is *independent* of this
   (it is a real-**spam** FP effect).
2. **Synthetic→real header domain shift.** The synthetic-trained operating point does not transfer:
   at band-26 on a synth→real holdout, *every* fusion (incl. noContent) shows ≈21% FPR, because the
   synth-calibrated header channel maps the baseline value (header=10, on 99.9% of real legit) to a
   non-trivial P. **The 0.255 threshold must be re-calibrated on real traffic before deployment.**
3. **url channel non-determinism.** svc-03's live DNS/WHOIS/TLS/HTTP enrichment times out on
   historical/synthetic URLs and, under capture-time CPU saturation, misses svc-07's aggregation
   window → url_risk degraded. Impact: grouped-OOF unchanged; only ~3 pts of in-corpus band-26 recall
   (the ~13 `phish_url_only`); no text family affected. Raising the L2 budget made it *worse* (slower
   svc-03 misses the window) — reverted. Live enrichment on dead URLs is inherently non-reproducible;
   treated as a methodology caveat. `phish_url_only` and `phish_hard_soft` are therefore below 100%.

## 6. Bottom line

- The model is **not** the ceiling; the old "NLP intent ceiling" was the symlink/INT8 packaging bug.
- **The shipped Plan A fusion is not the generalizable best**: its `content_risk` channel flags ~94%
  of held-out real spam as phishing (and gives the worst full-corpus operating point: FPR 0.044,
  precision 0.680, F1 0.774). **`noContent[u,h,p]`** (calibrated-OR over url + header + calibrated
  `phishing_probability`) gets the **best full-corpus F1 (0.914)**, ties +phish in-corpus, and is
  materially more robust to a **new** real-spam campaign (held-out real-spam FP **3.6%** vs +phish 55%
  / Plan A 94%), at equal-or-better phishing recall.
- svc-08 design: a **3-channel calibrated blender** on {url_risk, header_risk, phishing_probability};
  drop content_risk from the phishing decision. **Re-calibrate the operating threshold on real
  traffic** (caveat 5.2).
