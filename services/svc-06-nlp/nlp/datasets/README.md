# CyberSiren NLP Dataset Sources

Training data for the DistilBERT phishing email classifier (NLP-SPEC-v1.0 §2.1).

Final dataset: **149,998 rows**, 3-class {legitimate=0, spam=1, phishing=2}, 40/40/20 balance.
See `nlp-cybersiren-model.ipynb` for the full construction notebook.

## Included Datasets

| ID   | Name                                       | Source                                                                                                                             | Rows    | Labels used       |
|------|--------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|---------|-------------------|
| D1   | Biggest Phishing Spam Ham Dataset          | [kaggle.com/datasets/akshatsharma2/the-biggest-spam-ham-phish-email-dataset-300000](https://www.kaggle.com/datasets/akshatsharma2/the-biggest-spam-ham-phish-email-dataset-300000) | 365,448 | Ham→0, Spam→1, Phish→2 |
| D2   | EduPhish — Education-Targeted Phishing     | [kaggle.com/datasets/tanvirahmed0981/education-targeted-phishing-email-dataset](https://www.kaggle.com/datasets/tanvirahmed0981/education-targeted-phishing-email-dataset) | 16,942  | Safe→0, Phish→2   |
| D4   | Human vs LLM Generated Phishing Emails    | [kaggle.com/datasets/francescogreco97/human-llm-generated-phishing-legitimate-emails](https://www.kaggle.com/datasets/francescogreco97/human-llm-generated-phishing-legitimate-emails) | 3,595   | Phish→2, Legit→0  |
| D6n  | Nazario Phishing Corpus (sub-file)        | [kaggle.com/datasets/naserabdullahalam/phishing-email-dataset](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset) — `Nazario.csv` | 1,565   | All phishing→2    |
| D6f  | Nigerian 419 Fraud (sub-file)             | [kaggle.com/datasets/naserabdullahalam/phishing-email-dataset](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset) — `Nigerian_Fraud.csv` | 3,332   | All phishing→2    |
| D7   | Seven Phishing Email Datasets             | [huggingface.co/datasets/puyang2025/seven-phishing-email-datasets](https://huggingface.co/datasets/puyang2025/seven-phishing-email-datasets) | 162,413 | Legit→0, Spam→1   |

## Excluded Datasets

| Name                                       | Reason                                                                                   |
|--------------------------------------------|------------------------------------------------------------------------------------------|
| D3: Phishing & Legitimate Emails 2026 (kuladeep19) | **Synthetic.** Only 873 unique words across 10K texts (TTR 0.0023, CV 0.26). Template-generated, will not generalise. |
| D5: Urgency/Authority/Persuasion (ahmadtijjani) | **79 unique texts** (92.1% duplicates). Short template phrases, not real email text. |
| D6 combined file (`text_combined`)         | **Pre-processed.** Zero uppercase, zero punctuation, zero stopwords — unusable for raw-email model. |

## Key Notes

- **D7 label=1 is SPAM, not phishing.** All 7 sub-corpora (TREC-05/06/07, CEAS-08, Enron, SpamAssassin, LingSpam) are historically spam. Map to class 1 (spam).
- **D1 label conflicts:** 12,477 rows with same text but different labels — resolved by majority vote.
- **D6 sub-file selection:** Only Nazario and Nigerian Fraud used; CEAS_08/SpamAssassin/Enron/Ling already present in D7.
- Exact class balance, deduplication logic, and sampling methodology are in `nlp-cybersiren-model.ipynb`.

## Preprocessed Dataset

The merged, cleaned, and balanced dataset is exported as:
- `cybersiren_nlp_dataset_v1.parquet` / `cybersiren_nlp_dataset_v1.csv`

These are the training artefacts consumed by `nlp-cybersiren-finetune.ipynb`.
