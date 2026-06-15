# CyberSiren Aggregator — Consistent-Base Findings (real current models)

Objective: MALICIOUSNESS  (positive = label != legitimate). Matches deployed NLP v3
and the verdict pipeline (no auto-spam label). Graded on cybersiren_e2e_benchmark_representative.

## Real per-channel quality (current models, is_malicious)
| channel | real model | AUC | recall@1%FPR | note |
|---|---|---|---|---|
| NLP | svc-06 ONNX v3 | 0.869 | 71.6% | strong; scores spam high (by design) |
| Header | svc-04 Go (seeded rules, max-blend) | 0.657 | 39.3% | catches header_spoof 100% |
| URL L1 | svc-03 inference_script (model.joblib) | 0.562 | 0.0% | NOISE on static URLs (legit fires 91%) |
| URL guard+L1 | + Cisco top-10K guard | 0.628 | — | guard clears top-10K only |
| URL L2 operational | hgb_operational (44 live-enrichment features) | n/a offline | — | needs live SSL/WHOIS/page; unmeasurable here |

## The drag (verified)
- DEFAULT weighted_average: recall@1%FPR 58.4% — WORSE than NLP alone (71.6%).
- 65% of malicious emails land below their best single channel; mean 72.4 -> 51.3 (lose 21 pts).
- Cause: (1) dilution — NLP (strong) has lowest weight 0.25, URL (noise) highest 0.35;
          (2) noise injection — L1 URL fires >50 on 91% of legit.

## Best aggregator (calibrated probabilistic-OR, 5-seed held-out)
| channels | recall@1%FPR |
|---|---|
| NLP only | 79.4% |
| NLP+Header | 83.8% |
| NLP+Header+URL(L1) | 83.3% (lexical noise hurts) |
| NLP+Header+URL(authoritative guard/TI) | 84.2% (best) |
- raw OR without calibration: 29.4% (URL noise destroys it -> calibration is essential).
- Beats NLP-alone on 5/5 seeds. OOD (real held-out phishing) ~99.6%.

## Design decision
Fuse NLP+Header via calibrated-OR; URL as an AUTHORITATIVE channel (TI/guard -> reliability~1.0).
Do NOT calibrate lexical URL on this static benchmark. URL lexical/L2 re-enters once live
enrichment provides a real validation set. Requires forwarding ti_matched/guard_hit SVC-03->07->08.
