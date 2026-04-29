package processor

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/header"
	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/rules"
	contractsk "github.com/saif/cybersiren/shared/contracts/kafka"
)

func TestDecodeMessage(t *testing.T) {
	t.Parallel()

	good := contractsk.AnalysisHeadersMessage{EmailID: 7, OrgID: 1, SenderEmail: "a@b.com"}
	body, _ := json.Marshal(good)

	parsed, err := decodeMessage(body)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if parsed.EmailID != 7 || parsed.OrgID != 1 || parsed.SenderEmail != "a@b.com" {
		t.Errorf("decoded mismatch: %+v", parsed)
	}

	if _, err := decodeMessage(nil); err == nil {
		t.Errorf("expected error on empty body")
	}
	if _, err := decodeMessage([]byte("not json")); err == nil {
		t.Errorf("expected error on garbage")
	}

	bad := contractsk.AnalysisHeadersMessage{EmailID: 0}
	body, _ = json.Marshal(bad)
	if _, err := decodeMessage(body); err == nil {
		t.Errorf("expected error on email_id=0")
	}
}

func TestEncodeKey(t *testing.T) {
	t.Parallel()

	for _, id := range []int64{1, 99, 1234567890} {
		got := string(encodeKey(id))
		if got != strconv.FormatInt(id, 10) {
			t.Errorf("encodeKey(%d) = %q", id, got)
		}
	}
}

func TestScoreBucket(t *testing.T) {
	t.Parallel()

	cases := map[int]string{
		0:   "low",
		29:  "low",
		30:  "medium",
		59:  "medium",
		60:  "high",
		79:  "high",
		80:  "critical",
		100: "critical",
	}
	for s, want := range cases {
		if got := ScoreBucket(s); got != want {
			t.Errorf("ScoreBucket(%d) = %q, want %q", s, got, want)
		}
	}
}

func TestBuildScoresHeader(t *testing.T) {
	t.Parallel()

	parsed := contractsk.AnalysisHeadersMessage{EmailID: 42, OrgID: 9}
	signals := header.HeaderSignals{
		Auth:       header.AuthSignals{SPF: header.AuthResultFail},
		Reputation: header.ReputationSignals{IsFreeProvider: true},
		Structural: header.StructuralSignals{HopCount: 5, TimeDriftHours: 1.5},
	}
	er := rules.EvaluationResult{
		Fired: []rules.FiredRule{{
			Rule:        rules.CachedRule{ID: 1, Name: "test", Version: "1.0.0", ScoreImpact: 50},
			MatchDetail: json.RawMessage([]byte(`{"signal":"auth.spf"}`)),
		}},
		AuthSubScore: 50,
	}

	out := buildScoresHeader(parsed, signals, er, 60, 12*time.Millisecond)
	if out.EmailID != 42 || out.OrgID != 9 || out.Component != "header" {
		t.Errorf("envelope wrong: %+v", out)
	}
	if out.Score != 60 || out.AuthSubScore != 50 {
		t.Errorf("score propagation wrong: %+v", out)
	}
	if len(out.FiredRules) != 1 || out.FiredRules[0].RuleName != "test" {
		t.Errorf("fired rules propagation wrong: %+v", out.FiredRules)
	}
	if out.Signals.SPFResult != "fail" || !out.Signals.IsFreeProvider {
		t.Errorf("signals wire view wrong: %+v", out.Signals)
	}
	if out.ProcessingTimeMs < 0 {
		t.Errorf("processing time must be non-negative")
	}
}
