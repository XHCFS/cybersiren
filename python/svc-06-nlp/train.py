"""
CyberSiren NLP Model Training — SVC-06
=======================================
Training is performed in Kaggle notebooks, not this file.

Notebooks (in order of execution):
    1. nlp-cybersiren-model.ipynb
       - Loads and merges datasets D1/D2/D4/D6n/D6f/D7 (see datasets/README.md)
       - Deduplication, label conflict resolution, 40/40/20 class balance
       - Exports: cybersiren_nlp_dataset_v1.parquet

    2. nlp-cybersiren-finetune.ipynb
       - Fine-tunes distilbert-base-uncased on cybersiren_nlp_dataset_v1
       - 5-fold CV + held-out test evaluation (results in metrics.json)
       - Temperature calibration via LBFGS (Cell 11)
       - Threshold optimisation for phishing recall >= 0.96 (spec §5.4)
       - INT8 dynamic quantisation via onnxruntime.quantization (Cell 14)
       - Exports to cybersiren_nlp_out/:
             onnx/model_int8.onnx   (66.8 MB — place in python/svc-06-nlp/onnx/)
             tokenizer/             (copy to python/svc-06-nlp/tokenizer/)
             config.json            (already committed)
             metrics.json           (already committed)

After running the notebooks, copy the artifacts:
    cp -r /kaggle/working/cybersiren_nlp_out/onnx/    python/svc-06-nlp/onnx/
    cp -r /kaggle/working/cybersiren_nlp_out/tokenizer/ python/svc-06-nlp/tokenizer/

The ONNX model binary (~66 MB) is excluded from git via .gitignore (*.onnx).
Tokenizer JSON files are committed to the repo (see python/svc-06-nlp/tokenizer/).

Model spec: docs/internals/CyberSiren_NLP_Email_Classification_Model_Specification.html
"""
