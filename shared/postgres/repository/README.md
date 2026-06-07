# postgres/repository

Thin repository wrappers over the sqlc-generated query layer (`db/sqlc`). All
SQL is authored in `db/queries/*.sql` and generated with `make generate`
(sqlc-only, decision D8). These wrappers add tenant scoping, error context, and
small input/output models — they never hand-write SQL.

## Tenant isolation (G10 / spec §16 D12)

Migration `018_add_rls` puts **FORCE ROW LEVEL SECURITY** on 13 tenant tables
with a `tenant_isolation` policy of the form:

```sql
current_setting('app.current_org_id', TRUE) IS NOT NULL
AND org_id = current_setting('app.current_org_id', TRUE)::BIGINT
```

Until something sets that GUC, the policy denies every row. Two things make the
boundary real:

1. **`WithOrgTx` / `SetOrgGUC`** (`tenant_tx.go`) — every transaction that
   touches an RLS-forced table binds `app.current_org_id` with `SET LOCAL`
   semantics (`set_config(..., true)`), so the org id is checked on every read
   and write and is discarded when the tx ends (never leaks onto a pooled
   connection). Compose multi-statement writes through the `*db.Queries` handle
   the callback receives (`db.New(tx)`).

2. **A non-bypass app DB role.** Postgres superusers bypass RLS entirely and the
   table owner bypasses it unless `FORCE` is set. The application MUST connect as
   a role that is **neither superuser nor `BYPASSRLS`** and is **not the table
   owner**, otherwise the GUC is set but ignored. Provision a login role (e.g.
   `cybersiren_app`) granted only DML on the application tables and point the
   service DSN at it. The `migration_role` referenced by the `migration_bypass`
   policies is the *separate* role used to run migrations.

   > This role wiring lives in the migrations/compose layer (out of this
   > package's scope). The data layer is ready for it today: the moment the app
   > DSN uses a non-bypass role, isolation is enforced with zero code changes.

The cross-org isolation proof is `rls_integration_test.go` (build tag
`integration`); it requires `APP_DATABASE_URL` pointing at the non-bypass role
and is exercised at the batch integration gate, not in the light unit run.

## Control-plane reads

`api_keys`, `users`, and `organisations` are intentionally **not** RLS-forced:
the API-key lookup is what resolves which org a request belongs to, so it must
run before any org GUC can be set. `user_repo.go` reads them straight off the
pool. `audit_log` IS RLS-forced, so its read runs under `WithOrgTx`.
