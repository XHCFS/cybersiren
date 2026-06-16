# CyberSiren whole-system fusion benchmark

A leakage-safe, whole-system benchmark for the svc-08 decision/fusion stage, plus the
exhaustive search that produced **[FINDINGS.md](./FINDINGS.md)**.

**Headline:** no svc-08 fusion design beats Plan A (calibrated probabilistic-OR, PR #214) in a
way that generalizes. The whole-system recall ceiling is an NLP intent-detection limit, not a
fusion deficiency. See FINDINGS.md for the root cause, the full-corpus comparison, and the frontier.

## Why this exists

The earlier harness read only the four numeric channel scores from Postgres and used a stratified
split that lets synthetic generator families leak across train/test. This benchmark adds the two
things needed to tell a real fusion improvement from corpus-memorization:

1. **Rich-signal capture** — the classification / confidence / phishing-probability / #210 facets
   are only on the `emails.scored` Kafka topic, never persisted. `explore/capture_rich.py` consumes
   the topic during a live pass and joins on `internal_id`.
2. **A corrected generalization adjudicator** — `explore/adjudicate.py` / `final_adjudicate.py`
   merge near-duplicate sibling families into mechanism groups, score every email with a model that
   never saw its group (pooled out-of-fold), and adjudicate on **pAUC over FPR∈[0,0.05]** plus a
   provenance holdout. Single-point recall@FPR is threshold-placement noise; pAUC is stable.

## Layout

```
FINDINGS.md                 the report (read this)
build_subset.py             render a stratified subset of the corpus CSV -> manifest + .eml
run_pass.py                 submit a manifest through the live pipeline, read back 4 channel scores
explore/capture_rich.py     live pass that ALSO captures the rich svc-06 signals (Kafka join)
explore/evallib.py          eval infra: split, View-B metrics, real-world slices, ROC
explore/combiner_lib.py     feature builders + metrics for combiner candidates
explore/calor.py            calibrated probabilistic-OR (the shipped architecture), pluggable channels
explore/cal2.py             pluggable calibrators (isotonic / beta)
explore/adjudicate.py       CORRECTED mechanism-grouped pooled-OOF adjudicator (isotonic vs beta)
explore/final_adjudicate.py the decisive full-corpus comparison (table in FINDINGS §3)
explore/bakeoff_4ch.py      fusion-math bakeoff over the 4 numeric channels
explore/bakeoff_rich.py     candidate bakeoff over the rich capture
explore/round2.py round3.py the monotone / confidence-interaction design sweeps
explore/rich_analysis.py    do the rich signals carry orthogonal information? (they don't)
explore/missed_anatomy.py   anatomy of the missed threats (the recall ceiling)
calib/                      calibration artifacts
big/  bigfull/              captured component+rich scores (gzipped) + manifests
```

## Reproduce

The offline analysis runs from the committed (gzipped) captures — no live stack needed; the loaders
read the `.gz` files transparently:

```bash
python3 explore/final_adjudicate.py big/raw_rich_full.json   # FINDINGS §3 (full corpus, ~3 min)
python3 explore/adjudicate.py        big/raw_rich_3k.json    # grouped-OOF: isotonic vs beta
python3 explore/bakeoff_rich.py      big/raw_rich_3k.json    # rich candidate bakeoff
python3 explore/rich_analysis.py     big/raw_rich_3k.json    # orthogonal-signal diagnostic
python3 explore/missed_anatomy.py                            # the recall-ceiling anatomy
```

Regenerating a capture needs the live 23-container stack (`make full-up`) and the benchmark corpus
(`cybersiren_e2e_benchmark_representative.csv`, external):

```bash
python3 build_subset.py --rate 1.0 --floor 1 --cap 1000000 --outdir bigfull   # full corpus -> manifest + .eml
# stop cybersiren-jaeger first (in-memory trace store; it is the RAM hog on long runs)
python3 explore/capture_rich.py --label run1 --manifest bigfull/manifest.jsonl --out big/raw_rich_full.json
```

The metric of record is **View-B threat** (positive = phishing|spam, negative = legitimate;
flagged = verdict ≠ benign), reported with the real-world slices (real_seen FPR, real_ood recall,
spam-flag) separately every time.
