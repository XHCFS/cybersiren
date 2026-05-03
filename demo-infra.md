# CyberSiren — Infrastructure Spine v0 Smoke Test

End-to-end smoke for the Kafka-based pipeline backbone. Distinct from the per-service standalone demos in [DEMO.md](DEMO.md): those run one real service against its own UI; this one runs **all 10 pipeline services as stubs** and proves a fake email can flow `emails.raw → emails.verdict` through Redpanda with a single linked trace.

---

## How to run it

From the repo root:

```bash
make smoke
```

That single command:

1. Brings up the infra stack via Docker Compose: Postgres, Valkey, Redpanda + topic-init, Jaeger, pgAdmin, Redpanda Console.
2. Builds the 10 pipeline binaries with `go build`.
3. Starts each binary natively, each on its own metrics port (`9101..9110`).
4. Polls every `/healthz` until all 10 return 200.
5. POSTs a fake email to `svc-01-ingestion:8081/ingest`.
6. Polls Redpanda's `emails.verdict` topic for a record with the same `email_id`.
7. Tears the stubs down (infra stays up; `make down` to stop the rest).

Cold first run takes ~30 s end-to-end (mostly the Go build); subsequent runs ~10 s.

If you want to keep the stubs alive after smoke (to inspect logs or scrape `/metrics`), run the two scripts directly instead of `make smoke`:

```bash
./scripts/dev/run_pipeline.sh start         # boots stubs, returns when /healthz green
./scripts/dev/inject_fake_email.sh          # one synthetic email, prints the verdict
EMAIL_ID=foo ./scripts/dev/inject_fake_email.sh   # custom id
./scripts/dev/run_pipeline.sh stop          # tear down when done
```

Per-stub log files land in `.smoke-logs/<svc-name>.log`.

---

## What "good" looks like

### 1. Console output

```
==> POST http://localhost:8081/ingest  email_id=smoke-...
    {"email_id":"smoke-...","status":"accepted"}
==> Waiting up to 30s for emails.verdict for smoke-...
==> PASS
{"meta":{"email_id":"smoke-...","org_id":"org-smoke", ...},
 "internal_id":"fake-internal-smoke-...",
 "risk_score":53,
 "verdict_label":"phishing"}
```

The presence of `==> PASS` plus a JSON verdict line with the **same `email_id`** as the POST is the primary success signal. `verdict_label` will be `benign | suspicious | phishing | malware` depending on which random scores rolled (per spec §1 step 5 thresholds: ≤25 / ≤50 / ≤75 / >75). Across multiple runs you should see all four labels appear.

### 2. Topics + retention (one-time check)

```bash
docker exec cybersiren-redpanda rpk topic list -X brokers=localhost:9092
```

Should print 12 topics. Partition counts: `analysis.attachments` and `scores.attachment` = 3, every other topic = 6. Retention (sample): `emails.raw` 172800000 ms (48 h), `analysis.urls` 86400000 ms (24 h), `emails.verdict` 604800000 ms (7 d). All zstd-compressed, delete cleanup.

### 3. Metrics counters (run while stubs are alive)

```bash
curl -s http://localhost:9102/metrics | grep cybersiren_kafka
```

After 4 emails through a fresh run, the counters form an exact conservation law:

| Service | consumed | produced | Notes |
|---|---:|---:|---|
| svc-01-ingestion | 0 | 4 | HTTP only |
| svc-02-parser | 4 | 20 | fan-out × 5 |
| svc-03-url-pipeline | 4 | 4 | |
| svc-04-header-analysis | 4 | 4 | |
| svc-05-attachment-analysis | 4 | 4 | |
| svc-06-nlp-pipeline | 4 | 4 | |
| svc-07-aggregator | 20 | 4 | fan-in × 5 |
| svc-08-decision | 4 | 4 | |
| svc-09-notification | 4 | 0 | sink |
| svc-10-api-dashboard | 4 | 0 | sink |

Every edge of the DAG fires exactly N times for N emails. No dups, no losses.

### 4. Distributed tracing

```bash
curl -s "http://localhost:16686/api/traces?service=svc-01-ingestion&limit=1" \
  | jq '.data[0] | {traceID, span_count: (.spans | length)}'
```

A single traceID should contain ~57 spans across all 10 services:

```
svc-01-ingestion             1 span
svc-02-parser                7 spans
svc-03-url-analysis          3 spans
svc-04-header-analysis       3 spans
svc-05-attachment-analysis   3 spans
svc-06-nlp                   3 spans
svc-07-aggregator           30 spans   (5 inputs × consume + valkey ops + final produce)
svc-08-decision              3 spans
svc-09-notification          2 spans
svc-10-api-dashboard         2 spans
```

That single trace ID spanning 10 services is the proof that the W3C `traceparent` header is being injected on produce and re-extracted on consume across every Kafka hop — the spec §12 tracing requirement is satisfied. Browse it visually at <http://localhost:16686> → "svc-01-ingestion" → "Find Traces".

### 5. Failure modes you'd see if it were broken

- **Hang at "Waiting for healthz"**: a stub crashed at boot — `tail .smoke-logs/<svc>.log`. Most common cause is Postgres / Valkey / Redpanda not up.
- **`FAIL: no emails.verdict record`**: an intermediate service didn't process. The counter table above shows where the chain stops.
- **Verdict has the wrong `email_id`**: would mean partition keys aren't being preserved. Has not happened.

---

## Port map (smoke run)

| Endpoint | URL |
|---|---|
| Ingest endpoint (svc-01) | <http://localhost:8081/ingest> |
| Stubs `/metrics` and `/healthz` | <http://localhost:9101/healthz> .. <http://localhost:9110/healthz> |
| Redpanda Kafka API | `localhost:9092` |
| Redpanda Console | <http://localhost:8080> |
| Jaeger UI | <http://localhost:16686> |
| Postgres | `localhost:5432` |
| Valkey | `localhost:6379` |

---

## Definition-of-Done crosswalk (from `infra-plan-cc.md` §5)

| Criterion | Verified by |
|---|---|
| `make up` healthy infra | `docker ps` reports `(healthy)` on every cybersiren-* container |
| 12 topics + correct partitions + retention | `rpk topic describe <topic>` |
| Contracts JSON round-trip tests pass | `go test ./shared/contracts/kafka/` |
| Producer/consumer propagate `traceparent` and zerolog enrichment | one Jaeger trace spans all 10 services; logs include `email_id`/`offset`/`partition` |
| Stubs expose `/metrics` and `/healthz` and consume/produce on right topics | `run_pipeline.sh start` healthz polling + counter table above |
| Fake email reaches `emails.verdict` ≤30 s with same `email_id` | `==> PASS` output |
| Single Jaeger trace spans the whole pipeline | `curl /api/traces?service=svc-01-ingestion` |
| Counters non-zero across run | `cybersiren_kafka_messages_*_total` > 0 on every stub |
| Real svc-03 / svc-06 / svc-11 demos still work | unchanged binary entry points; see [DEMO.md](DEMO.md) |
| Existing tests pass | `go build ./... && go test -short ./shared/...` |

---

## Cleanup

```bash
make smoke-stop          # only kills the native stubs (infra stays up)
make down                # stops all compose containers (volumes preserved)
make down-v              # stops + drops volumes (fresh start next time)
```
