# PhishGuard - Key Technical Decisions

## Last Updated
December 8, 2024

## Python/Go Integration Strategy

**Decision:** ML inference runs in Python subprocesses called from Go

**Implementation:**
- Go spawns Python process with stdin/stdout communication
- Features passed as JSON via stdin
- Predictions returned as JSON via stdout
- Process pooling to avoid spawn overhead
- 5s timeout for XGBoost, 10s timeout for NLP

**Fallback Plan:**
If subprocess approach proves unreliable in production:
- Containerize Python inference as HTTP microservice
- Use REST API from Go instead of subprocess
- Add retry logic and circuit breaker

---

## Feature Extraction Parity

**Decision:** Features implemented in both Go (production) and Python (training)

**Requirements:**
- Python version (Issue #19) must produce identical output to Go version (Issue #13)
- Unit test validates parity on 100 test URLs
- Features must match within 0.001 tolerance
- Any divergence must be documented with justification

**Why:** 
- Training happens in Python (scikit-learn, XGBoost ecosystem)
- Production runs in Go (performance, single binary deployment)
- Must ensure model sees same features in production as during training

---

## TI Materialized View Refresh

**Decision:** Refresh after each sync cycle completes

**Implementation:**
- TI sync runs every 6 hours
- After bulk insert completes: `REFRESH MATERIALIZED VIEW CONCURRENTLY ti_current`
- CONCURRENT mode allows queries during refresh
- Refresh takes ~5 minutes, queries may see stale data during this window
- On refresh failure: log error but continue (will retry next cycle)

**Trade-off:** Accept up to 5 minutes of stale TI data vs blocking all queries

---

## Worker Concurrency Limits

**Decision:** Limit concurrent external operations to prevent rate limiting

**Limits:**
- Max 5 concurrent URL enrichments (SSL/WHOIS/HTTP calls)
- Reason: External services rate limit aggressive requests
- Max 3 retries per failed job
- Default risk score 0.5 on timeout/error

**Why:** 
- Email with 50 URLs would spawn 50 goroutines without limit
- WHOIS servers ban IPs making too many requests
- Better to be slow and reliable than fast and banned

---

## Model Versioning

**Decision:** Manual model promotion with filesystem versioning

**Current Implementation:**
- Models stored in `ml/nlp_model/model/` and `ml/url_model/model.pkl`
- Version specified in `config.yaml`
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
- On ML inference timeout: return score 0.5 (neutral)
- On partial failures: complete scan with available data
- Log all failures for debugging

**Why:**
- Better to give partial analysis than no analysis
- 0.5 score means "unknown risk" - doesn't bias verdict
- Users get results even when services degrade

---

## Questions/Discussions

Add new decisions here as they're made during development.
