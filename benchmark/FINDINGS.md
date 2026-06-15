# svc-08 fusion search — findings

**Question.** Find the svc-08 decision/fusion design that makes the whole CyberSiren detector
score best on the leakage-safe whole-system benchmark (View-B threat = phishing|spam vs legit;
flagged = verdict ≠ benign). Bar to beat: **Plan A / PR #214** ("config D"): R 0.785 · P 0.866 ·
F1 0.824 · FPR 0.046 · real_ood recall 0.985 · real_seen FPR 0.007 (3,000-email subset, SEED=7
60/40 stratified held-out test, n=1202).

**Answer.** After an exhaustive, multi-round search across the fusion design space — re-run on the
full 10,677-email corpus with a deliberately strengthened, leakage-safe adjudicator — **no svc-08
design beats Plan A in a way that generalizes.** Plan A's calibrated probabilistic-OR is at the
**generalizable ceiling** of this system. The residual benchmark headroom is bottlenecked by the
**NLP model's inability to detect intent-based phishing**, an error class that no score fusion can
repair because the information never reaches svc-08. Every design that beats Plan A on the in-corpus
split does so by **memorizing synthetic generator families** and collapses out-of-family. This is
the objective's explicitly-sanctioned outcome, reported here with the root cause, the frontier, and
the real-world per-slice numbers.

---

## 1. The root cause (why nothing beats Plan A)

We traced a single missed email end-to-end instead of only sweeping fusion math. The result reframes
the problem:

- **It is not parsing.** svc-02 decodes the quoted-printable body correctly and stores the full
  text in Postgres (verified).
- **It is not plumbing.** Scoring that exact body through the live NLP model returns the same low
  score the pipeline produced — the model receives the text and rates it benign.
- **It is the NLP model, on a specific error class.** On *novel* text (no benchmark leakage) the
  deployed DistilBERT behaves like this:

  | email (novel, hand-written) | content_risk | verdict |
  |---|---|---|
  | Obvious phish — URL + "confirm your password" + urgency | 98 | caught |
  | **Subtle BEC** — "process a wire transfer to a new supplier; keep this confidential" | **2** | **missed** |
  | Credential-harvest — "reply with your username and password" | 76 | caught |
  | Benign business request | 0 | — |
  | Benign favor | 1 | — |

  The model detects phishing through **surface lexical / spam cues**. Pure social-engineering
  (business-email-compromise, wire-fraud) carries no such cue — it is **lexically identical to a
  legitimate business request** — so the model, and every signal derived from it, scores it benign.

- **"The NLP model was good when trained on its own"** is exactly right and exactly the trap: its
  own evaluation was in-distribution (lexically-obvious phishing/spam, which it nails). The
  benchmark's hard slice is out-of-distribution intent-based BEC, which it cannot. The corpus CSV's
  precomputed `nlp_score = 99` on these came from a model that had seen the synthetic BEC family
  (leakage); the honestly-evaluated deployed model scores them ≈ 2.

- **All svc-06 signals fail together.** content, classification, confidence, phishing/spam
  probabilities and the impersonation/deception/intent facets all derive from the same DistilBERT,
  so on a fooled email they are *all* wrong simultaneously. There is no independent second opinion
  for svc-08 to fuse — the URL and header channels are silent on text-only mail. This is an
  information-theoretic ceiling: **svc-08 can combine information, it cannot create it.**

- **The obvious upstream lever doesn't help on this benchmark.** A From display-name↔address
  mismatch (the classic BEC tell) fires on **84% of legitimate** emails too (the synthetic generator
  does not correlate display names with addresses), so it cannot separate the classes here; the real
  SPF/DKIM-fail signal (≈29% of misses) is already in svc-04's header channel, which calibrated-OR
  weights conservatively to hold FPR. The recall ceiling holds even accounting for sender-auth.

The 286 NLP-missed phishing on the full corpus are `phish_hard_soft` / `phish_nlp_bec` /
`phish_header_spoof` / `phish_url_only` — synthetic BEC/social-engineering. **Real out-of-distribution
phishing (`real_ood`) is already caught at 0.96, and real legitimate FPR is ≈0.015** — Plan A is
already near-perfect where it matters for deployment.

## 2. Method (and the methodology fix that makes this trustworthy)

- **Rich-signal capture** (`capture_rich.py`): the prior harness read only the 4 numeric channel
  scores from Postgres. The classification / confidence / phishing-probability / #210 facets are
  **only on the `emails.scored` Kafka topic, never persisted**, so we capture them by consuming the
  topic during a live pass and joining on `internal_id`. Full corpus captured once (10,677 emails).
- **Leakage-safe split / metric.** Fit any calibration or model on TRAIN only; evaluate on held-out
  TEST. View-B threat metrics plus the real-world slices (real_seen FPR, real_ood recall, spam-flag)
  reported separately every time.
- **The load-bearing control — a corrected generalization adjudicator.** A naive stratified split
  lets synthetic generator families leak across train/test, so an over-fit model looks like a winner.
  An earlier leave-one-family-out had two flaws (caught by an adversarial review): 24/25 families are
  single-class so per-fold AUC was n=1, and near-duplicate siblings (`homoglyph`/`leet`/`zerowidth`;
  `legit_phishy_text`/`url`) leaked across folds. The corrected adjudicator
  (`adjudicate.py` / `final_adjudicate.py`):
  - **merges sibling families** into mechanism groups (no near-twin in train),
  - scores every email with a model that **never saw its group** (pooled out-of-fold),
  - adjudicates on **pAUC over FPR ∈ [0, 0.05]** (the stable low-FPR region that actually matters)
    plus pooled-OOF recall@FPR.046, and cross-checks with a **provenance holdout** (train synthetic
    → test real). pAUC is used because single-point recall@FPR is threshold-placement noise.

## 3. The decisive result (full corpus, n = 10,677)

**(A) Standard stratified held-out test** (apples-to-apples with the bar), bootstrap 95% CI on R@.046:

| candidate | AUC | R@FPR.046 [95% CI] | band-26 R / FPR / F1 |
|---|---|---|---|
| **Plan A — calibrated-OR** | 0.961 | 0.824 [0.790, 0.852] | 0.824 / 0.039 / 0.805 |
| calor + phish-prob channel | 0.977 | 0.824 [0.793, 0.856] | 0.824 / 0.038 / 0.806 |
| logistic (monotone feats) | 0.955 | 0.810 [0.774, 0.842] | 0.797 / 0.042 / 0.783 |
| HistGBM monotone | 0.979 | 0.828 [0.799, 0.858] | 0.817 / 0.032 / 0.817 |
| **HistGBM monotone + confidence** | 0.984 | **0.864 [0.837, 0.896]** | 0.845 / 0.034 / 0.827 |

On the in-corpus test the confidence-interaction model *beats* Plan A (lower CI bound 0.837 above
Plan A's point 0.824). **This is the trap.**

**(B) Corrected mechanism-grouped pooled out-of-fold** (the honest new-campaign OOD test):

| candidate | **OOD pAUC[0,.05]** | OOD R@.046 | OOD FPR@R.785 | ood-recall |
|---|---|---|---|---|
| **Plan A — calibrated-OR** | **0.662** | 0.718 | 0.050 | 0.888 |
| calor + phish-prob channel | 0.661 | 0.806* | 0.045 | 0.945 |
| logistic (monotone feats) | 0.555 | 0.761 | 0.052 | 0.950 |
| HistGBM monotone | 0.588 | 0.665 | 0.150 | 0.915 |
| **HistGBM monotone + confidence** | **0.589** | 0.651 | **0.162** | 0.888 |

- **The best in-corpus model is the worst out-of-mechanism.** `HistGBM monotone+confidence` drops
  from R@.046 0.864 → 0.651 and its FPR@R.785 balloons to 0.162 (3× Plan A). Its in-corpus win was
  family-memorization. Rejected — exactly the failure mode the team flagged for the "99% on
  synthetic" GBM.
- **On the stable metric (pAUC), Plan A is tied for best** (0.662) and beats every learned model.
  `calor + phish-prob` ties (0.661); its apparent R@.046 "win" (0.806*) is threshold-placement noise
  — pAUC is identical and on the 3k subset it was *worse* (sign-flip between subsets ⇒ not robust).
- **No design clears Plan A on the stable OOD metric.**

## 4. Everything tried (and why each fails)

All leakage-safe, over the captured scores.

- **Fusion math (4 numeric channels):** weighted-avg (dilutes — the recall bug), max, raw noisy-OR
  (over-flags, FPR 0.27 — calibration is load-bearing), **calibrated-OR (Plan A — best
  generalizable)**, log-odds. GBM scores higher in-corpus but is the overfit trap.
- **Richer signals into fusion:** facets do not fire on the missed phishing (model blind-spots);
  confidence / spam-prob separate FP-legit in-corpus (AUC ≈ 0.89) but are correlated with content
  and add no robust lift; phishing-probability as a 5th channel ties Plan A on OOD pAUC (no gain).
- **Learned combiners** (logistic, GBM, HistGBM, monotone-constrained, confidence-interaction): all
  win in-corpus, all collapse under grouped-OOF / provenance holdout.
- **Calibration method:** isotonic (Plan A) vs **beta** (an adversarial reviewer's top bet) — under
  the corrected adjudicator isotonic wins (beta's smooth extrapolation under-scores threats at low
  FPR).
- **Authoritative URL (Plan B):** only 3 of 71 missed threats (3k) carry any URL signal → recall
  ceiling +0.9 pt. Near-useless.
- **Operating point / bands:** the ROC is flat from FPR 0.046 to 0.089 — the remaining threats are
  unrecoverable at any FPR in that range.

## 5. Frontier (for operating-point selection)

| approach (3k bar) | recall | FPR | F1 | note |
|---|---|---|---|---|
| without-212 (config A) | 0.342 | 0.014 | 0.497 | content = P(phish); spam under-scored |
| PR-213 (config C) | 0.297 | 0.007 | 0.452 | P(phish) + calib-OR; collapses |
| with-212 (config B) | 0.827 | 0.089 | 0.802 | maliciousness + weighted-avg (dilutes) |
| **Plan A (config D)** | **0.785** | **0.046** | **0.824** | **maliciousness + calibrated-OR — best generalizable** |

The Pareto frontier among *generalizable* designs is owned by the calibrated-OR family; Plan A's
point dominates A and C and trades ~4 recall points vs B for roughly half the FPR. Every in-corpus
"win" above Plan A is non-generalizing.

## 6. Bottom line & recommendation

Plan A (calibrated probabilistic-OR on the #212 maliciousness content) is the **best generalizable
svc-08 fusion** for this system. The whole-system recall ceiling is an **NLP intent-detection limit**,
not a fusion deficiency: closing it requires a better content model or an **out-of-band signal**
(sender reputation, first-contact-asking-for-money, conversation anomaly) — or a 3-way `needs_review`
verdict for the all-signals-silent region — none of which are svc-08, and all of which are
overfit-prone on this corpus's synthetic hard slice.

**Recommend: adopt Plan A (#214).** This benchmark strengthening (rich-signal capture +
mechanism-grouped pooled-OOF + pAUC adjudicator) is contributed so future fusion claims are held to
an OOD-generalization standard, not an in-corpus number.

---
*Reproduce:* `capture_rich.py` (live pass → rich capture), `build_subset.py` (corpus → manifest),
`final_adjudicate.py` (the table in §3), `adjudicate.py` (grouped-OOF), `bakeoff_rich.py` /
`round2.py` / `round3.py` (the design sweeps). See `README.md`.
