package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/saif/cybersiren/services/svc-06-nlp/internal/nlp"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// fakePredictor injects a canned response or error into process() so the
// timeout/fallback path can be exercised without a live FastAPI service.
type fakePredictor struct {
	resp   *nlp.PredictResponse
	status int
	err    error

	gotReq nlp.PredictRequest
	calls  int
}

func (f *fakePredictor) Predict(ctx context.Context, req nlp.PredictRequest) (*nlp.PredictResponse, int, error) {
	f.calls++
	f.gotReq = req
	return f.resp, f.status, f.err
}

// capturingPublisher records the last published key/value instead of talking
// to a real Kafka producer. It can also be told to fail (infra error path).
type capturingPublisher struct {
	gotKey   []byte
	gotValue []byte
	calls    int
	failWith error
}

func (p *capturingPublisher) publish(ctx context.Context, key, value []byte) error {
	p.calls++
	p.gotKey = key
	p.gotValue = value
	return p.failWith
}

func sampleInput() contracts.AnalysisText {
	return contracts.AnalysisText{
		Meta:    contracts.NewMeta("email-abc", 7),
		Subject: "Verify your account now",
		Body:    "please click the link to verify",
	}
}

// TestProcess_PredictTimeoutEmitsFallback proves that when Predict returns a
// timeout (context.DeadlineExceeded), the handler does NOT return an error
// (so the offset commits and the partition does not stall) and instead emits
// a scores.nlp envelope with the neutral fallback score of 50.
func TestProcess_PredictTimeoutEmitsFallback(t *testing.T) {
	pred := &fakePredictor{err: context.DeadlineExceeded, status: 0}
	pub := &capturingPublisher{}
	in := sampleInput()

	if err := process(context.Background(), in, pred, pub.publish); err != nil {
		t.Fatalf("process returned error on predict timeout (must NOT stall partition): %v", err)
	}

	if pub.calls != 1 {
		t.Fatalf("expected exactly one publish, got %d", pub.calls)
	}
	if string(pub.gotKey) != in.Meta.EmailID {
		t.Fatalf("publish key = %q, want %q", pub.gotKey, in.Meta.EmailID)
	}

	var out contracts.ScoreEnvelope //nolint:staticcheck // G13: decoding the sanctioned legacy ScoreEnvelope emit.
	if err := json.Unmarshal(pub.gotValue, &out); err != nil {
		t.Fatalf("unmarshal published envelope: %v", err)
	}
	if out.Score != 50 {
		t.Fatalf("fallback score = %v, want 50", out.Score)
	}
	if out.Component != contracts.ComponentNLP {
		t.Fatalf("component = %q, want %q", out.Component, contracts.ComponentNLP)
	}
	if out.Meta.EmailID != in.Meta.EmailID {
		t.Fatalf("meta email_id = %q, want %q", out.Meta.EmailID, in.Meta.EmailID)
	}
	if got := out.Details["classification"]; got != "unknown" {
		t.Fatalf("classification = %v, want \"unknown\"", got)
	}
	if got, ok := out.Details["fallback"].(bool); !ok || !got {
		t.Fatalf("details.fallback = %v, want true", out.Details["fallback"])
	}
	if got := out.Details["fallback_reason"]; got != "nlp_predict_timeout" {
		t.Fatalf("details.fallback_reason = %v, want \"nlp_predict_timeout\"", got)
	}
	// subject + plain_text must still be carried for SVC-08 fingerprint/SimHash.
	if got := out.Details["subject"]; got != in.Subject {
		t.Fatalf("details.subject = %v, want %q", got, in.Subject)
	}
	if got := out.Details["plain_text"]; got != in.Body {
		t.Fatalf("details.plain_text = %v, want %q", got, in.Body)
	}
}

// TestProcess_GenericPredictErrorEmitsFallback proves the fallback also covers
// non-timeout failures (unreachable service, non-2xx) — any non-nil error.
func TestProcess_GenericPredictErrorEmitsFallback(t *testing.T) {
	pred := &fakePredictor{err: errors.New("connection refused"), status: 502}
	pub := &capturingPublisher{}
	in := sampleInput()

	if err := process(context.Background(), in, pred, pub.publish); err != nil {
		t.Fatalf("process returned error on predict failure (must NOT stall partition): %v", err)
	}
	var out contracts.ScoreEnvelope //nolint:staticcheck // G13: decoding the sanctioned legacy ScoreEnvelope emit.
	if err := json.Unmarshal(pub.gotValue, &out); err != nil {
		t.Fatalf("unmarshal published envelope: %v", err)
	}
	if out.Score != 50 {
		t.Fatalf("fallback score = %v, want 50", out.Score)
	}
}

// TestProcess_SuccessEmitsRealScore is the happy-path sanity check that the
// refactor did not break the success branch: the real ContentRiskScore and
// classification flow through unchanged.
func TestProcess_SuccessEmitsRealScore(t *testing.T) {
	pred := &fakePredictor{
		resp: &nlp.PredictResponse{
			Classification:      "phishing",
			Confidence:          0.91,
			PhishingProbability: 0.88,
			ContentRiskScore:    88,
			IntentLabels:        []string{"credential_theft"},
			UrgencyScore:        0.7,
			ObfuscationDetected: true,
		},
		status: 200,
	}
	pub := &capturingPublisher{}
	in := sampleInput()

	if err := process(context.Background(), in, pred, pub.publish); err != nil {
		t.Fatalf("process returned error on success path: %v", err)
	}
	if pub.calls != 1 {
		t.Fatalf("expected exactly one publish, got %d", pub.calls)
	}

	var out contracts.ScoreEnvelope //nolint:staticcheck // G13: decoding the sanctioned legacy ScoreEnvelope emit.
	if err := json.Unmarshal(pub.gotValue, &out); err != nil {
		t.Fatalf("unmarshal published envelope: %v", err)
	}
	if out.Score != 88 {
		t.Fatalf("success score = %v, want 88 (real ContentRiskScore)", out.Score)
	}
	if got := out.Details["classification"]; got != "phishing" {
		t.Fatalf("classification = %v, want \"phishing\"", got)
	}
	if _, isFallback := out.Details["fallback"]; isFallback {
		t.Fatalf("success path must not set details.fallback")
	}
	// success path must still carry subject + plain_text for SVC-08.
	if got := out.Details["plain_text"]; got != in.Body {
		t.Fatalf("details.plain_text = %v, want %q", got, in.Body)
	}
}

// TestProcess_PublishErrorStillReturnsError proves infra failures (publish)
// are NOT swallowed by the fallback — only model timeouts become a score=50.
func TestProcess_PublishErrorStillReturnsError(t *testing.T) {
	pred := &fakePredictor{err: context.DeadlineExceeded}
	pub := &capturingPublisher{failWith: errors.New("kafka down")}
	in := sampleInput()

	if err := process(context.Background(), in, pred, pub.publish); err == nil {
		t.Fatalf("expected publish error to propagate (infra failure, not a model timeout)")
	}
}
