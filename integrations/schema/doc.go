// Package schema holds optional Postgres schema assertions for migrations.
//
// Normal `go test ./...` compiles this package empty of tests (integration
// tests use the `integration` build tag). Run:
//
//	go test -tags=integration ./integrations/schema/...
//
// With DATABASE_URL set and migrations applied through 029 or later.
package schema
