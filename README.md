# PhishGaurd-v7.0-AI-TI
The hybrid detection engine that integrates 4+ TI feeds, and an ensemble ML model. Part of a of a commercial-grade, full-cycle Phishing Defense and Resiliance Platform

**ASER [TI]:** Threat intel feeds + URL enrichment  
**SAIF [LEAD]:** Database, ML models, API, orchestration  
**OMAR [NLP]:** Email content analysis

---

```
PhishGuard/
│
├── cmd/                                    # Service entry points
│   ├── api/main.go                         # [LEAD] API server bootstrap
│   ├── worker/main.go                      # [LEAD] Background job processor
│   └── ti_sync/main.go                     # [TI] Threat intel sync service
│
├── internal/
│   ├── api/
│   │   ├── handlers/                       # [LEAD] All API endpoints
│   │   ├── middleware/                     # [LEAD] Auth, rate limiting, logging
│   │   └── routes.go                       # [LEAD] Route definitions
│   │
│   ├── detection/
│   │   ├── url/
│   │   │   ├── ti_checker.go              # [TI] Check if URL in TI database
│   │   │   ├── enricher.go                # [TI] SSL/WHOIS/redirects
│   │   │   ├── feature_extractor.go       # [LEAD] Extract 30 URL features
│   │   │   └── model.go                   # [LEAD] XGBoost inference wrapper
│   │   │
│   │   ├── nlp/
│   │   │   ├── preprocessor.go            # [NLP] Clean email text
│   │   │   └── classifier.go              # [NLP] Call NLP model
│   │   │
│   │   ├── domain/
│   │   │   ├── typosquatting.go           # [LEAD] Check domain similarity
│   │   │   └── reputation.go              # [LEAD] Domain age checks
│   │   │
│   │   └── aggregator.go                  # [LEAD] Combine all risk scores
│   │
│   ├── email/
│   │   ├── parser.go                       # [LEAD + NLP] Extract URLs/body/headers
│   │   └── sanitizer.go                    # [NLP] Strip HTML, clean text
│   │
│   ├── ti/
│   │   ├── feeds.go                        # [TI] Define feed structs (PhishTank, etc)
│   │   └── sync.go                         # [TI] Fetch feeds, dedupe, insert to DB
│   │
│   ├── storage/
│   │   ├── postgres.go                     # [LEAD] DB connection
│   │   └── repository/                     # Data access layer
│   │       ├── email_repo.go              # [LEAD] Email CRUD
│   │       ├── url_repo.go                # [LEAD] URL CRUD
│   │       ├── ti_repo.go                 # [TI] TI database operations
│   │       ├── enrichment_repo.go         # [TI] Enrichment cache
│   │       └── user_repo.go               # [LEAD] Users/orgs/API keys
│   │
│   └── worker/
│       ├── jobs.go                         # [LEAD] Job definitions
│       └── orchestrator.go                 # [LEAD] Scan workflow: parse→TI→enrich→ML→NLP→aggregate
│
├── pkg/                                    # [LEAD] Shared utilities
│   ├── config/config.go                    # Config loader (Viper)
│   ├── logger/logger.go                    # Structured logging (zerolog)
│   ├── queue/redis.go                      # Redis queue wrapper
│   ├── httputil/                           # HTTP helpers
│   └── models/                             # Data structures (Email, URL, Verdict, User)
│
├── ml/                                     # Python ML code
│   ├── url_model/
│   │   ├── train.py                        # [LEAD] Train XGBoost on URL features
│   │   ├── feature_engineering.py         # [LEAD] Feature extraction (Python version)
│   │   └── inference.py                   # [LEAD] CLI script for Go to call
│   │
│   ├── nlp_model/
│   │   ├── train.py                        # [NLP] Fine-tune DistilBERT
│   │   ├── inference.py                   # [NLP] CLI or Flask service
│   │   └── app.py                         # [NLP] Optional Flask API
│   │
│   └── datasets/                           # [NLP] Find phishing email datasets
│
├── web/                                    # [LEAD - later] React dashboard
│   └── src/components/                     # Login, scan submission, results display
│
├── migrations/                             # [LEAD] SQL schema files
│   ├── 001_initial_schema.sql             # All tables (emails, urls, ti_entries, users, etc)
│   ├── 002_add_users_orgs.sql
│   ├── 003_add_enrichments.sql
│   └── 004_add_materialized_view.sql      # Fast TI lookup view
│
├── deploy/
│   ├── docker-compose.yml                  # [LEAD] All services (postgres, redis, api, worker, ti_sync)
│   └── Dockerfile.*                        # [LEAD] One per service
│
└── scripts/
    ├── setup_db.sh                         # [LEAD] Run migrations
    └── seed_ti.sh                          # [TI] Initial TI feed sync
```

---

## Start Order

**Week 1-2:**
- Lead: `migrations/001_*.sql`, `pkg/*`, `internal/storage/*`
- TI: `internal/ti/feeds.go` (define feed structs)
- NLP: Find datasets on Kaggle

**Week 3-4:**
- Lead: `internal/detection/url/feature_extractor.go`, `internal/api/routes.go`
- TI: `internal/ti/sync.go`, `internal/detection/url/enricher.go`
- NLP: `ml/nlp_model/train.py`

**Week 5-6:**
- Lead: `ml/url_model/train.py`, `internal/detection/url/model.go`
- TI: Finish enrichment + caching
- NLP: `ml/nlp_model/inference.py`, `internal/detection/nlp/classifier.go`

**Week 7-8:**
- Lead: `internal/worker/orchestrator.go`, `internal/detection/aggregator.go`
- All: Integration testing

**Week 9-12:**
- All: Bug fixes, dashboard, docs, demo prep
