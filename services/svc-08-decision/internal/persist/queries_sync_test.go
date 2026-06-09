package persist

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestDecisionQueriesAreSQLCGenerated verifies that every SQL statement the
// decision writer relies on has been migrated into the sqlc set: each canonical
// query body in db/queries/*.sql must appear verbatim (modulo whitespace) in
// the corresponding generated db/sqlc/*.sql.go file. This is the byte-shape
// guard that replaced the old raw-pgx query constants.
func TestDecisionQueriesAreSQLCGenerated(t *testing.T) {
	t.Parallel()
	cases := []struct {
		queryFile string
		queryName string
		genFile   string
	}{
		{"campaigns.sql", "UpsertCampaign", "campaigns.sql.go"},
		{"campaigns.sql", "GetCampaignByFingerprint", "campaigns.sql.go"},
		{"verdicts.sql", "InsertVerdict", "verdicts.sql.go"},
		{"verdicts.sql", "FindExistingVerdictForEmail", "verdicts.sql.go"},
		{"verdicts.sql", "UpdateVerdictKafkaWire", "verdicts.sql.go"},
		{"emails_scores.sql", "UpdateEmailScores", "emails_scores.sql.go"},
		{"email_campaign_snapshot.sql", "GetEmailCampaignSnapshot", "email_campaign_snapshot.sql.go"},
	}

	for _, c := range cases {
		canonical := extractQueryBody(t, readRepoFile(t, filepath.Join("db", "queries", c.queryFile)), c.queryName)
		generated := normalizeSQL(readRepoFile(t, filepath.Join("db", "sqlc", c.genFile)))
		if !strings.Contains(generated, canonical) {
			t.Fatalf("query %s not found verbatim in generated %s — run 'make generate'\ncanonical:\n%s", c.queryName, c.genFile, canonical)
		}
	}
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "../../../../"))
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// extractQueryBody returns the SQL body of the named query from a canonical
// .sql file, with comments and the trailing semicolon stripped and whitespace
// normalised, so it can be matched against the generated const string.
func extractQueryBody(t *testing.T, canonicalSQL, queryName string) string {
	t.Helper()
	marker := "-- name: " + queryName + " "
	idx := strings.Index(canonicalSQL, marker)
	if idx < 0 {
		t.Fatalf("missing marker %q in canonical SQL", queryName)
	}
	block := canonicalSQL[idx+len(marker):]
	if end := strings.Index(block, "\n-- name: "); end >= 0 {
		block = block[:end]
	}
	return normalizeSQL(block)
}

// normalizeSQL strips comment lines and collapses runs of whitespace so two
// formatting-equivalent SQL fragments compare equal.
func normalizeSQL(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		out = append(out, trimmed)
	}
	joined := strings.Join(out, " ")
	joined = strings.TrimSuffix(strings.TrimSpace(joined), ";")
	return strings.Join(strings.Fields(joined), " ")
}
