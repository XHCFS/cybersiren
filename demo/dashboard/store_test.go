package main

import (
	"path/filepath"
	"testing"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// TestStorePersistence proves scans survive a restart: a store flushed to a file
// is fully reloaded (feed + verdict + detail) by a fresh store on the same file.
func TestStorePersistence(t *testing.T) {
	file := filepath.Join(t.TempDir(), "scans.json")

	s1 := newStore(10, file)
	s1.recordSubmit("019ebce8-1b12-713b-b351-fdca9d656760", "gmail", "hi", "Aser <a@b.com>")
	s1.applyVerdict(&contracts.EmailsVerdict{
		Meta:         contracts.MessageMeta{EmailID: "019ebce8-1b12-713b-b351-fdca9d656760"},
		VerdictLabel: "benign", RiskScore: 16,
	})
	s1.flush()

	// Fresh store on the same file == a restart.
	s2 := newStore(10, file)

	feed := s2.feedItems()
	if len(feed) != 1 {
		t.Fatalf("want 1 persisted scan, got %d", len(feed))
	}
	f := feed[0]
	if f.Source != "gmail" || f.Subject != "hi" {
		t.Errorf("feed item not restored: %+v", f)
	}
	if f.Status != "scored" || f.Label != "benign" || f.RiskScore == nil || *f.RiskScore != 16 {
		t.Errorf("verdict not restored: status=%s label=%s risk=%v", f.Status, f.Label, f.RiskScore)
	}

	sc := s2.get("019ebce8-1b12-713b-b351-fdca9d656760")
	if sc == nil || sc.Verdict == nil || sc.Verdict.VerdictLabel != "benign" {
		t.Fatalf("scan detail not restored: %+v", sc)
	}
}
