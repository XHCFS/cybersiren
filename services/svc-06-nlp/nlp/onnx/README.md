# ONNX Model Directory

Place the INT8-quantised DistilBERT model here before running the NLP service.

## File

| File | Size | Source |
|------|------|--------|
| `model_int8.onnx` | ~66–132 MB | Kaggle notebook output: `cybersiren_nlp_out/onnx/model_int8.onnx` |

## Getting the model

The model is tracked via **Git LFS**. After cloning the repo:

```bash
git lfs pull
```

If you have the model from the Kaggle training notebook, copy it here:

```bash
cp /path/to/cybersiren_nlp_out/onnx/model_int8.onnx services/svc-06-nlp/nlp/onnx/
git add services/svc-06-nlp/nlp/onnx/model_int8.onnx
git commit -m "chore: add NLP ONNX model (via LFS)"
git push
```

## Notes

- `model_int8_opt.onnx` is the ORT-optimized graph cache generated automatically
  on first run — it is gitignored and should not be committed.
- Without the model, the service starts but `/predict` returns `503`.
  Loading progress is visible at `GET /status`.
