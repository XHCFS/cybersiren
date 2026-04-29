package ti

import (
	"context"
	"errors"
	"testing"

	"github.com/rs/zerolog"
)

type stubIndicatorLookup struct {
	calls      []string
	hit        bool
	score      int
	threatType string
	err        error
}

func (s *stubIndicatorLookup) LookupTIIndicator(
	_ context.Context,
	indicatorType string,
	value string,
) (bool, int, string, error) {
	s.calls = append(s.calls, indicatorType+":"+value)
	if s.err != nil {
		return false, 0, "", s.err
	}
	return s.hit, s.score, s.threatType, nil
}

func TestFallbackLookup_UsesPostgresWhenValkeyUnavailable(t *testing.T) {
	t.Parallel()

	db := &stubIndicatorLookup{hit: true, score: 91, threatType: "phishing"}
	lookup := NewFallbackLookup(nil, db, zerolog.Nop())

	hit, score, threat, err := lookup.IsBlocklisted(context.Background(), "Example.COM.")
	if err != nil {
		t.Fatalf("IsBlocklisted returned error: %v", err)
	}
	if !hit || score != 91 || threat != "phishing" {
		t.Fatalf("fallback result mismatch: hit=%v score=%d threat=%q", hit, score, threat)
	}
	if len(db.calls) != 1 || db.calls[0] != "domain:example.com" {
		t.Fatalf("db fallback call = %#v, want domain:example.com", db.calls)
	}
}

func TestFallbackLookup_DBErrorIsObservableToExtractor(t *testing.T) {
	t.Parallel()

	db := &stubIndicatorLookup{err: errors.New("db down")}
	lookup := NewFallbackLookup(nil, db, zerolog.Nop())

	_, _, _, err := lookup.IsBlocklisted(context.Background(), "[2001:db8::1]")
	if err == nil {
		t.Fatal("expected DB lookup error")
	}
	if len(db.calls) != 1 || db.calls[0] != "ip:2001:db8::1" {
		t.Fatalf("db fallback call = %#v, want ip:2001:db8::1", db.calls)
	}
}
