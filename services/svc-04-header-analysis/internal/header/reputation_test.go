package header

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	contractsk "github.com/saif/cybersiren/shared/contracts/kafka"
)

type stubTILookup struct {
	calls       []string
	domainHit   bool
	domainScore int
	domainType  string
	ipHit       bool
	ipScore     int
	ipType      string
	err         error
}

func (s *stubTILookup) IsBlocklisted(_ context.Context, value string) (bool, int, string, error) {
	s.calls = append(s.calls, value)
	if s.err != nil {
		return false, 0, "", s.err
	}
	if strings.Contains(value, ".") && !looksLikeIP(value) {
		return s.domainHit, s.domainScore, s.domainType, nil
	}
	return s.ipHit, s.ipScore, s.ipType, nil
}

func looksLikeIP(v string) bool {
	// Crude — good enough for tests.
	return strings.Count(v, ".") == 3 && !strings.ContainsAny(v, "abcdefghijklmnopqrstuvwxyz")
}

func TestReputationExtractor_FreeProviderAndTyposquat(t *testing.T) {
	t.Parallel()

	r := NewReputationExtractor(nil, 2, zerolog.Nop())

	got := r.Extract(context.Background(), &contractsk.AnalysisHeadersMessage{
		SenderDomain: "support@gmail.com",
	})
	// SenderDomain is normalised, so "support@gmail.com" is not a domain;
	// reputation only treats it as one if SenderDomain is a clean FQDN.
	if got.IsFreeProvider {
		t.Errorf("must not flag malformed SenderDomain as free provider, got %+v", got)
	}

	got = r.Extract(context.Background(), &contractsk.AnalysisHeadersMessage{
		SenderDomain: "gmail.com",
	})
	if !got.IsFreeProvider {
		t.Errorf("gmail.com must be flagged as free provider")
	}
	if got.TyposquatDistance != 0 {
		t.Errorf("free providers must not be flagged as typosquats: %+v", got)
	}

	got = r.Extract(context.Background(), &contractsk.AnalysisHeadersMessage{
		SenderDomain: "paypa1.com",
	})
	if got.TyposquatTarget != "paypal.com" || got.TyposquatDistance != 1 {
		t.Errorf("expected typosquat target paypal.com dist 1, got %+v", got)
	}
}

func TestReputationExtractor_TIDomainAndIP(t *testing.T) {
	t.Parallel()

	stub := &stubTILookup{
		domainHit:   true,
		domainScore: 90,
		domainType:  "phishing",
		ipHit:       true,
		ipScore:     85,
		ipType:      "spam",
	}
	r := NewReputationExtractor(stub, 2, zerolog.Nop())

	got := r.Extract(context.Background(), &contractsk.AnalysisHeadersMessage{
		SenderDomain:  "evil-corp.com",
		OriginatingIP: "203.0.113.7",
	})

	if !got.TIDomainMatch || got.TIDomainRiskScore != 90 || got.TIDomainThreatType != "phishing" {
		t.Errorf("domain TI propagation wrong: %+v", got)
	}
	if !got.TIIPMatch || got.TIIPRiskScore != 85 || got.TIIPThreatType != "spam" {
		t.Errorf("ip TI propagation wrong: %+v", got)
	}
}

func TestReputationExtractor_TILookupErrorIsTolerated(t *testing.T) {
	t.Parallel()

	stub := &stubTILookup{err: errors.New("valkey unavailable")}
	r := NewReputationExtractor(stub, 2, zerolog.Nop())

	got := r.Extract(context.Background(), &contractsk.AnalysisHeadersMessage{
		SenderDomain:  "example.com",
		OriginatingIP: "203.0.113.7",
	})

	// Errors must not propagate as TI hits.
	if got.TIDomainMatch || got.TIIPMatch {
		t.Errorf("errors must not surface as hits, got %+v", got)
	}
}

func TestReputationExtractor_NilMessage(t *testing.T) {
	t.Parallel()
	r := NewReputationExtractor(nil, 2, zerolog.Nop())
	got := r.Extract(context.Background(), nil)
	zero := ReputationSignals{}
	if got != zero {
		t.Errorf("nil msg should yield zero ReputationSignals, got %+v", got)
	}
}

func TestReputationExtractor_DomainAgeAlwaysNil(t *testing.T) {
	t.Parallel()
	r := NewReputationExtractor(nil, 2, zerolog.Nop())
	got := r.Extract(context.Background(), &contractsk.AnalysisHeadersMessage{
		SenderDomain: "newly-registered.com",
	})
	if got.DomainAgeDays != nil {
		t.Errorf("DomainAgeDays must be nil while WHOIS isn't piped to SVC-04, got %v", *got.DomainAgeDays)
	}
}
