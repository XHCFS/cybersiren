# ONNX Model Directory

The SVC-06 NLP service loads `model_int8.onnx` from this directory at startup.

## File

| File | Size | Format | Source |
|------|------|--------|--------|
| `model_int8.onnx` | ~266 MB | **fp32 (faithful)** | Kaggle training notebook (`nlp-cybersiren-finetune-v2`), cycle-12 |

> **Why "int8" if it's fp32?** The filename keeps the legacy `_int8` suffix for
> path / Makefile / loader stability. INT8 quantization was **abandoned** for v2:
> on this model it destroyed fidelity (max|logit-diff| ≈ 82) and FP16 produced an
> unloadable graph. The shipped fp32 export is exact (**max|logit-diff| = 0**).
> Correctness over size for a security classifier. See model spec §8.1.

## Getting the model

The canonical, **LFS-tracked source of truth** lives at
`python/svc-06-nlp/onnx/model_int8.onnx`. This service path is **gitignored** and
populated on demand. After cloning:

```bash
git lfs pull                      # fetch the real model (not the LFS pointer)
make check-nlp-model              # copies it here if missing / a placeholder
```

To ship a newly trained model, replace the LFS source (not this path):

```bash
cp /path/to/notebook_out/onnx/model_int8.onnx python/svc-06-nlp/onnx/model_int8.onnx
git add python/svc-06-nlp/onnx/model_int8.onnx        # tracked via Git LFS
git commit -m "feat(svc-06): update NLP model"
```

## Notes

- `model_int8_opt.onnx` is the ORT-optimized graph cache generated automatically
  on first run — gitignored, never committed.
- Without a real model the service starts but `/predict` returns `503`; loading
  progress is visible at `GET /status`.
- Thresholds (temperature, `phish_threshold`) and the label map live in
  `../config.json`; measured metrics in `../metrics.json`.
