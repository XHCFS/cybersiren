// Package nlp — text preprocessing for the SVC-06 Go wrapper.
//
// IMPORTANT (train/serve parity): the CANONICAL model-input preprocessing lives
// in the Python module `nlp/text_preprocess.py` (preprocess_email): URL + bare-
// email stripping (URLs are SVC-03's job, scored separately), NFKC + zero-width
// removal, whitespace collapse, and the "Subject: …\n\nBody: …" composition.
// The model was TRAINED on exactly that pipeline, so any divergence here causes
// train/serve skew and silent accuracy loss.
//
// Current design: this Go wrapper forwards raw subject/body_plain/body_html to
// the Python service unchanged; ALL preprocessing happens once, in Python. Keep
// it that way. If preprocessing is ever moved/duplicated into Go (e.g. for
// throughput, or if SVC-02 starts pre-stripping the analysis.text body), it MUST
// mirror nlp/text_preprocess.py byte-for-byte — strip the same URL/email spans,
// keep phone numbers, apply the same normalization — or be validated against it.
//
// TODO: implement only if a measured need arises; otherwise leave forwarding-only.
package nlp
