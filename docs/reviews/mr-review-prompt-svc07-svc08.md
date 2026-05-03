# MR review prompt: SVC-07 aggregator + SVC-08 decision engine

Paste the block below into a fresh chat (or Cursor agent) targeting this repository. Swap `BRANCH` / `PR` if needed.

```
You are reviewing a GitHub MR that implements the Score Aggregator (SVC-07) and Decision Engine (SVC-08) for CyberSiren. Read `docs/design/svc-07-08-design-brief.md` first, then critically review the diff against `origin/main`.

## Scope expectations
- SVC-07: consumes `analysis.plans` + four `scores.*` topics; Valkey barrier; 30s timeout (sweeper); at-least-once publish semantics; Prometheus metrics; **no Postgres**.
- SVC-08: consumes `emails.scored`; weighted blend; JSON-DSL rules (shared implementation); verdict + confidence; campaign fingerprint + SimHash + empirical-Bayes nudge; **all DB writes in a single transaction**; publish `emails.verdict`; metrics + tracing patterns consistent with svc-04.

## Critical checks (must answer with code references)
1. **Contract**: Does `EmailsScored` / `EmailsVerdict` JSON match downstream expectations? Any breaking change vs existing producers/consumers?
2. **`internal/` boundary**: Rules DSL must not be duplicated; confirm SVC-08 imports `shared/rules/dsl` (not svc-04 `internal/rules`).
3. **DB ordering**: Inside one tx: campaign UPSERT before `UPDATE emails` (needs `campaign_id`); verdict + rule_hits append-only.
4. **Kafka semantics**: Handler returns `nil` on poison pills (commit offset) vs error on transient DB/publish failures (do not commit). Verify SVC-08 matches svc-04 processor patterns where applicable.
5. **Integration debt**: Packager placeholders for `internal_id` / `fetched_at` — are they wired from real ingestion or still TODO? Flag any risk for partitioned `emails` writes.
6. **Rules targets**: Brief mentions `decision`; implementation may use `campaign` enum — justified and documented?
7. **`pgx` enums**: Verdict/source/entity types accepted by Postgres (string vs typed enum bindings).
8. **Metrics naming**: No Prometheus registration clashes with svc-04 (prefixes).
9. **Tests**: Blender, confidence, fingerprint, nudge; aggregator unit tests — gaps?

## Deliverable
Short verdict (approve / request changes / block) with numbered findings: severity (P0–P3), file:line when possible, and concrete fix suggestion. No stylistic bikeshedding unless it hides a bug.

Use: `git diff origin/main...HEAD` and targeted reads; run `go test ./...` and `go vet ./...` if you can execute commands.
```

## How to use

1. Open the MR on GitHub and attach this file or paste the fenced block into the reviewer chat.
2. Replace the first line’s context with the actual PR link or branch name.
3. For a second pass, run the same prompt after addressing review comments (regression-focused).
