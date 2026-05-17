package persist

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestQueriesStaySyncedWithCanonicalSQLFiles(t *testing.T) {
	t.Parallel()
	canonicalCampaignsSQL := readCanonicalQueryFile(t, "campaigns.sql")
	canonicalVerdictsSQL := readCanonicalQueryFile(t, "verdicts.sql")
	canonicalEmailScoresSQL := readCanonicalQueryFile(t, "emails_scores.sql")
	canonicalEmailCampaignSnapshotSQL := readCanonicalQueryFile(t, "email_campaign_snapshot.sql")

	assertSQLContainsQuery(t, canonicalCampaignsSQL, "name: UpsertCampaign", queryUpsertCampaign)
	assertSQLContainsQuery(t, canonicalVerdictsSQL, "name: InsertVerdict", queryInsertVerdict)
	assertSQLContainsQuery(t, canonicalEmailScoresSQL, "name: UpdateEmailScores", queryUpdateEmailScores)
	assertSQLContainsQuery(t, canonicalEmailCampaignSnapshotSQL, "name: GetEmailCampaignSnapshot", queryEmailCampaignSnapshot)
}

func readCanonicalQueryFile(t *testing.T, file string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "../../../../"))
	path := filepath.Join(root, "db", "queries", file)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read canonical query %s: %v", file, err)
	}
	return string(b)
}

func assertSQLContainsQuery(t *testing.T, canonicalSQL, queryName, runtimeQuery string) {
	t.Helper()
	marker := "-- " + queryName
	idx := strings.Index(canonicalSQL, marker)
	if idx < 0 {
		t.Fatalf("missing marker %q in canonical SQL", queryName)
	}
	start := idx + len(marker)
	block := canonicalSQL[start:]
	if end := strings.Index(block, "\n-- name: "); end >= 0 {
		block = block[:end]
	}

	canonicalBody := normalizeSQL(block)
	actualBody := normalizeSQL(runtimeQuery)
	if canonicalBody != actualBody {
		t.Fatalf("query drift for %s\ncanonical:\n%s\n\nruntime:\n%s", queryName, canonicalBody, actualBody)
	}
}

func normalizeSQL(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ";")
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for i := range lines {
		line := strings.TrimRight(lines[i], " \t")
		trimmed := strings.TrimSpace(line)
		if len(out) == 0 && strings.HasPrefix(trimmed, ":") {
			continue
		}
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		if len(out) == 0 && trimmed == "" {
			continue
		}
		out = append(out, line)
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}
