# CyberSiren — Key Technical Decisions

## Last Updated
March 24, 2026

## Python/Go Integration Strategy

**Decision:** ML inference runs in Python subprocesses called from Go

**Implementation:**
- Go spawns Python process with stdin/stdout communication
- Features passed as JSON via stdin
- Predictions returned as JSON via stdout
- Process pooling to avoid spawn overhead (configurable, default 3 processes)
- 5s timeout for LightGBM URL model, 10s timeout for NLP (DistilBERT/ONNX)

**Fallback Plan:**
If subprocess approach proves unreliable in production:
- Containerize Python inference as HTTP microservice
- Use REST API from Go instead of subprocess
- Add retry logic and circuit breaker

**Note:** NLP (SVC-06) already uses the HTTP microservice approach (FastAPI + ONNX Runtime). The subprocess pattern applies only to SVC-03 URL model inference.

---

## URL Model Selection: LightGBM (Champion)

**Decision:** LightGBM selected as champion model over XGBoost

**Evidence (ML-SPEC-v1.1):**
- Test MCC: 0.99645 (vs XGBoost 0.99542)
- Test Accuracy: 99.824%
- Single-inference latency: 1,582 μs (vs XGBoost 4,385 μs)
- Model size: 0.8 MB (joblib-compressed)
- 28 active features (F04 `has_ip_address` and F24 `double_slash_in_path` pruned — zero splits)

**Model Artifacts:**
- `services/svc-03-url-analysis/ml/model.joblib` — trained LightGBM classifier
- `python/url-ml/feature_engineering.py` — Python reference implementation
- `services/svc-03-url-analysis/internal/url/feature_extractor.go` — Go production implementation

**Known Delta:** ARCH-SPEC-v2.1 Step 3a and the error handling table (§6) still reference "XGBoost". These references are superseded by ML-SPEC-v1.1 which establishes LightGBM as champion. The ARCH-SPEC will be updated in a future revision.

---

## Feature Extraction Parity

**Decision:** Features implemented in both Go (production) and Python (training)

**Requirements:**
- Python `feature_engineering.py` must produce identical output to Go `feature_extractor.go`
- Unit test validates parity on 100 test URLs
- Features must match within 0.001 tolerance
- Any divergence must be documented with justification
- Feature order must match Python column order exactly

**Why:**
- Training happens in Python (scikit-learn, LightGBM ecosystem)
- Production runs in Go (performance, single binary deployment)
- Must ensure model sees same features in production as during training

---

## TI Materialized View Refresh

**Decision:** Refresh after each sync cycle completes

**Implementation:**
- TI sync runs every 6 hours
- After bulk insert completes: `REFRESH MATERIALIZED VIEW CONCURRENTLY` for all 5 MVs
- CONCURRENT mode allows queries during refresh
- Refresh takes ~5 minutes, queries may see stale data during this window
- On refresh failure: log error but continue (will retry next cycle)

**Materialized Views (defined in 004_add_materialized_view.up.sql):**
- `mv_threat_summary` (15 min refresh)
- `mv_campaign_summary` (5 min refresh)
- `mv_feed_health` (10 min refresh)
- `mv_rule_performance` (30 min refresh)
- `mv_org_ingestion_summary` (5 min refresh)

**Trade-off:** Accept up to 5 minutes of stale TI data vs blocking all queries

---

## Worker Concurrency Limits

**Decision:** Limit concurrent external operations to prevent rate limiting

**Limits:**
- Max 5 concurrent URL enrichments (SSL/WHOIS/HTTP calls)
- Reason: External services rate limit aggressive requests
- Max 3 retries per failed job
- Default risk score 50 (int, 0-100 scale) on timeout/error

**Why:**
- Email with 50 URLs would spawn 50 goroutines without limit
- WHOIS servers ban IPs making too many requests
- Better to be slow and reliable than fast and banned

---

## Model Versioning

**Decision:** Manual model promotion with filesystem versioning

**Current Implementation:**
- URL model: `services/svc-03-url-analysis/ml/model.joblib`
- NLP model: `python/svc-06-nlp/` (ONNX export from DistilBERT fine-tune)
- Version specified in service config
- Manual validation before promoting new model

**Future Enhancement:**
- Implement A/B testing framework
- Add model registry with rollback capability
- Track model performance metrics over time

---

## Error Handling Philosophy

**Decision:** Fail gracefully with default scores, never fail entire scan

**Implementation:**
- On URL enrichment failure: use cached data or empty enrichment
- On ML inference timeout: return score 50 (neutral, 0-100 scale)
- On partial failures: complete scan with available data, set `partial_analysis: true`
- Log all failures for debugging
- SVC-07 aggregator: 30s timeout emits partial result with missing component list

**Why:**
- Better to give partial analysis than no analysis
- Score 50 means "unknown risk" — doesn't bias verdict
- Users get results even when services degrade

---

## Campaign Fingerprinting

**Decision:** Deterministic campaign grouping via SHA256 fingerprint

**Algorithm (ARCH-SPEC §8.1):**
```
sender_domain  = lower(email.sender_domain)
url_domain     = lower(domain_of(email.riskiest_url)) OR "" if no URLs
subject_tpl    = template(email.subject)  // replace names/nums with placeholders
intent         = nlp_facets.intent_label

fingerprint    = SHA256(sender_domain + "|" + url_domain + "|" + SHA256(subject_tpl) + "|" + intent)
```

**Near-duplicate:** SimHash (64-bit) with Hamming distance ≤ 3, per-org scoped via Redis.

---

## Questions/Discussions

Add new decisions here as they're made during development.
