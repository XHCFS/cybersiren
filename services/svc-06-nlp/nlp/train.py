"""
CyberSiren NLP Model Training — SVC-06
=======================================
Training is performed in Kaggle notebooks, not this file.

Notebooks (in order of execution):
    1. nlp-cybersiren-model.ipynb
       - Loads and merges datasets D1/D2/D4/D6n/D6f/D7 (see datasets/README.md)
       - Deduplication, label conflict resolution, real phishing moved into
         training with a per-corpus cap, paired contrastive + adversarial
         augmentation (~188K train rows)
       - Exports: cybersiren_nlp_dataset_v2.parquet

    2. nlp-cybersiren-finetune-v2.ipynb
       - Fine-tunes distilbert-base-uncased on cybersiren_nlp_dataset_v2 (cycle-12)
       - 5-fold CV + held-out test evaluation (results in metrics.json)
       - Temperature calibration via LBFGS (Cell 11)
       - Threshold optimisation for phishing recall >= 0.96 (spec §5.4)
       - fp32 ONNX export (faithful, max|logit-diff|=0 vs PyTorch). INT8
         quantisation was EVALUATED and REJECTED — it destroyed score fidelity
         (see model spec §8.5). The exported file keeps the legacy model_int8
         name for path/Makefile stability; its contents are fp32.
       - Exports to cybersiren_nlp_out/:
             onnx/model_int8.onnx   (~266 MB fp32 — place in python/svc-06-nlp/onnx/)
             tokenizer/             (copy to python/svc-06-nlp/tokenizer/)
             config.json            (already committed)
             metrics.json           (already committed)

After running the notebooks, copy the artifacts:
    cp -r /kaggle/working/cybersiren_nlp_out/onnx/    python/svc-06-nlp/onnx/
    cp -r /kaggle/working/cybersiren_nlp_out/tokenizer/ python/svc-06-nlp/tokenizer/

The ONNX model binary (~266 MB fp32) is committed via Git LFS under
python/svc-06-nlp/onnx/ (*.onnx is an LFS filter, see .gitattributes); fetch it
with `git lfs pull`. Tokenizer JSON files are committed normally
(see python/svc-06-nlp/tokenizer/).

Model spec: docs/internals/CyberSiren_NLP_Email_Classification_Model_Specification.html
"""
