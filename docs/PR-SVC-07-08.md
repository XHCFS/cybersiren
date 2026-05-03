# PR: SVC-07 aggregator and SVC-08 decision (pipeline backbone)

This PR completes the aggregator → decision path: Valkey buffering, Kafka contracts, Postgres writes, verdict publish, observability, and migration support for stable Kafka republish.

## Operational / breaking changes

- **Valkey keys:** Aggregation buckets use `aggregator:{org_id}:{email_id}`. Publish locks use `aggregator:publock:{org_id}:{email_id}`. After deploy, **clear or ignore legacy** email-only aggregator keys (`aggregator:{email}`) so stale state does not mix with tenant-scoped keys.
- **Migration 029** (`029_verdict_kafka_wire_and_pipeline_unique.up.sql`): adds `verdicts.kafka_verdict_wire` (JSONB) and partial unique index `uq_verdicts_pipeline_email_partition` on `(entity_id, email_fetched_at)` for pipeline verdicts. It now includes a pre-flight duplicate guard and fails fast with a clear error if existing data violates the predicate (`entity_type = email`, `source IN (model, rule)`).
- **Migration runtime note:** index creation is non-concurrent in this migration; schedule during low write traffic if `verdicts` is large.
- **SVC-04 rules cache key migration:** header-analysis now uses `rules_cache:header:{org}` (previously `rules_cache:{org}`), so the first deploy causes per-org warm misses while entries repopulate from Postgres.

## Behaviour notes

- **Kafka producer retries:** The last argument to `Producer.Publish` is the count of **extra** attempts after the first `ProduceSync` (see `shared/kafka/producer/producer.go`).
- **Dedupe / republish:** SVC-08 stores the immutable `emails.verdict` JSON on the verdict row and prefers it when publishing after dedupe replay so Kafka bytes stay stable across redeliveries.
- **Replay semantics:** `emails.scored` remains at-least-once (duplicate publishes are possible on redelivery/rebalance), while `emails.verdict` is byte-stable on replay via `kafka_verdict_wire`.

## How to validate

```bash
make test-short
make integration-schema   # optional: DATABASE_URL + db-migrate; see Makefile
```

Race and repetition on critical paths:

```bash
go test -race -count=2 ./services/svc-07-aggregator/... ./services/svc-08-decision/... ./shared/...
```
