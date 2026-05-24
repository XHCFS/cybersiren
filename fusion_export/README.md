# Fusion export bundle (URL string model + operational HGB + enrichment)

Self-contained slice of the **phishing-detector** research repo: everything needed to **enrich a URL**, **score** it with two models, and **fuse** scores for deployment-style evaluation in **another repository**.

## Layout

| Path | Role |
|------|------|
| `fusion_kit/enrich.py` | Full URL enrichment pipeline (vendored from the parent project). |
| `fusion_kit/operational.py` | Feature column list + `EnrichmentData` → operational row + `ml_ready` row reader. |
| `fusion_kit/scoring.py` | HGB preprocessing, load bundles, URL scores, operational scores, `max`/`mean` fusion. |
| `fusion_kit/url_normalize.py` | URL canonicalization for the char n-gram model (pickle-safe). |
| `models/url_char_lr.joblib` | `HashingVectorizer` + `LogisticRegression` on URL characters. |
| `models/hgb_operational.joblib` | `HistGradientBoostingClassifier` on enriched tabular features. |
| `scripts/score_batch.py` | CLI: enrich + dual scores + fusion for a URL list. |
| `scripts/eval_bootstrap.py` | CLI: stratified benchmark from `ml_ready` CSV + bootstrap + *p*-values. |
| `scripts/train_url_model.py` | CLI: retrain URL model from a `url`,`label` CSV. |
| `MODELING_AND_EVALUATION.md` | Full narrative: features, trial/error, sanity checks, statistics. |

## Copy into your other repo

1. Copy the entire `fusion_export/` directory (rename if you like).
2. Ensure `PYTHONPATH` includes the directory **above** `fusion_kit` (i.e. the folder that contains `fusion_kit/` and `scripts/`). The scripts add their parent automatically.
3. `pip install -r requirements.txt` (trim optional packages if you only use cached features).
4. For live enrichment quality, add **GeoLite2** `.mmdb` databases next to `fusion_kit/enrich.py` (see comments at top of `enrich.py` for paths).

## Quick commands

```bash
# From this directory (fusion_export/)
python scripts/score_batch.py --urls my_urls.txt --workers 6

python scripts/eval_bootstrap.py --ml-ready /path/to/ml_ready_dataset.csv \
  --per-class 400 --bootstrap 100 --use-ml-ready-features

python scripts/train_url_model.py --csv /path/to/ml_ready_dataset.csv --out models/url_char_lr.joblib
```

## Portable URL model artifact

The shipped `url_char_lr.joblib` was **rewritten** so the sklearn `FunctionTransformer` references `fusion_kit.url_normalize.canonicalize_url_batch` instead of `utils.url_hash_transforms` (otherwise `joblib.load` fails outside the original repo). See `MODELING_AND_EVALUATION.md`.

## Documentation

Read **`MODELING_AND_EVALUATION.md`** for methodology, evaluation numbers, sanity-check matrix, and interpretation of bootstrap *p*-values.
