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

// TestMapIntentTo5Label exercises every 5-label output, multi-intent priority
// resolution, the empty/legitimate short-circuits and the unknown-label fall
// back. mapIntentTo5Label must be pure and deterministic.
func TestMapIntentTo5Label(t *testing.T) {
	tests := []struct {
		name           string
		intents        []string
		classification string
		wantLabel      string
		wantConf       float64
	}{
		{
			name:      "credential_harvest -> credential_harvesting",
			intents:   []string{"credential_harvest"},
			wantLabel: intentCredentialHarvesting,
			wantConf:  1.0,
		},
		{
			name:      "account_verification -> credential_harvesting",
			intents:   []string{"account_verification"},
			wantLabel: intentCredentialHarvesting,
			wantConf:  1.0,
		},
		{
			name:      "data_exfiltration -> credential_harvesting",
			intents:   []string{"data_exfiltration"},
			wantLabel: intentCredentialHarvesting,
			wantConf:  1.0,
		},
		{
			name:      "malware_delivery -> malware_delivery",
			intents:   []string{"malware_delivery"},
			wantLabel: intentMalwareDelivery,
			wantConf:  1.0,
		},
		{
			name:      "social_engineering -> bec",
			intents:   []string{"social_engineering"},
			wantLabel: intentBEC,
			wantConf:  1.0,
		},
		{
			name:      "urgency_threat -> bec",
			intents:   []string{"urgency_threat"},
			wantLabel: intentBEC,
			wantConf:  1.0,
		},
		{
			name:      "impersonation -> bec",
			intents:   []string{"impersonation"},
			wantLabel: intentBEC,
			wantConf:  1.0,
		},
		{
			name:      "payment_fraud -> scam",
			intents:   []string{"payment_fraud"},
			wantLabel: intentScam,
			wantConf:  1.0,
		},
		{
			name:      "prize_scam -> scam",
			intents:   []string{"prize_scam"},
			wantLabel: intentScam,
			wantConf:  1.0,
		},
		{
			name:      "marketing_spam -> legitimate",
			intents:   []string{"marketing_spam"},
			wantLabel: intentLegitimate,
			wantConf:  1.0,
		},
		{
			name:      "benign_notification -> legitimate",
			intents:   []string{"benign_notification"},
			wantLabel: intentLegitimate,
			wantConf:  1.0,
		},
		{
			name:           "classification legitimate short-circuits",
			intents:        []string{"credential_harvest"},
			classification: "legitimate",
			wantLabel:      intentLegitimate,
			wantConf:       1.0,
		},
		{
			name:      "no intents -> legitimate high confidence",
			intents:   nil,
			wantLabel: intentLegitimate,
			wantConf:  1.0,
		},
		{
			name:      "only unknown labels -> legitimate low confidence",
			intents:   []string{"totally_unknown", "made_up"},
			wantLabel: intentLegitimate,
			wantConf:  0.5,
		},
		{
			// credential_harvesting outranks bec & scam: priority order wins.
			name:      "multi-intent priority picks credential_harvesting",
			intents:   []string{"payment_fraud", "urgency_threat", "credential_harvest"},
			wantLabel: intentCredentialHarvesting,
			wantConf:  1.0 / 3.0,
		},
		{
			// malware_delivery outranks scam.
			name:      "multi-intent priority picks malware_delivery over scam",
			intents:   []string{"prize_scam", "malware_delivery"},
			wantLabel: intentMalwareDelivery,
			wantConf:  0.5,
		},
		{
			// two intents collapse to the same bucket -> full agreement.
			name:      "two intents same bucket -> confidence 1.0",
			intents:   []string{"credential_harvest", "account_verification"},
			wantLabel: intentCredentialHarvesting,
			wantConf:  1.0,
		},
		{
			// unknown labels are ignored and do not dilute confidence.
			name:      "unknown labels ignored in confidence",
			intents:   []string{"credential_harvest", "junk_label"},
			wantLabel: intentCredentialHarvesting,
			wantConf:  1.0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotLabel, gotConf := mapIntentTo5Label(tc.intents, tc.classification)
			if gotLabel != tc.wantLabel {
				t.Fatalf("label = %q, want %q", gotLabel, tc.wantLabel)
			}
			if diff := gotConf - tc.wantConf; diff > 1e-9 || diff < -1e-9 {
				t.Fatalf("confidence = %v, want %v", gotConf, tc.wantConf)
			}
		})
	}
}

// TestProcess_SuccessEmitsFacets proves the success path now emits the
// structured facets{} + model_versions{} envelope (with impersonation/
// deception/urgency/intent) INTO the Details map while STILL carrying the
// legacy svc-07/svc-08 dependency keys (subject, plain_text, intent_labels).
func TestProcess_SuccessEmitsFacets(t *testing.T) {
	brand := "paypal"
	pred := &fakePredictor{
		resp: &nlp.PredictResponse{
			Classification:      "phishing",
			Confidence:          0.93,
			PhishingProbability: 0.9,
			ContentRiskScore:    90,
			IntentLabels:        []string{"credential_harvest", "urgency_threat"},
			UrgencyScore:        0.8,
			ObfuscationDetected: true,
			ImpersonationScore:  0.75,
			ImpersonatedBrand:   &brand,
			DeceptionScore:      0.6,
		},
		status: 200,
	}
	pub := &capturingPublisher{}
	in := sampleInput()
	in.SenderName = "PayPal Support"
	in.SenderDomain = "paypa1-secure.example"

	if err := process(context.Background(), in, pred, pub.publish); err != nil {
		t.Fatalf("process returned error on success path: %v", err)
	}

	// Sender fields must have been forwarded to the predictor.
	if pred.gotReq.SenderName != in.SenderName {
		t.Fatalf("predict sender_name = %q, want %q", pred.gotReq.SenderName, in.SenderName)
	}
	if pred.gotReq.SenderDomain != in.SenderDomain {
		t.Fatalf("predict sender_domain = %q, want %q", pred.gotReq.SenderDomain, in.SenderDomain)
	}

	// Decode the published Details into a typed view of the facet envelope.
	var out struct {
		Score   float64 `json:"score"`
		Details struct {
			IntentLabels  []string                   `json:"intent_labels"`
			Subject       string                     `json:"subject"`
			PlainText     string                     `json:"plain_text"`
			Facets        contracts.NLPFacets        `json:"facets"`
			ModelVersions contracts.NLPModelVersions `json:"model_versions"`
		} `json:"details"`
	}
	if err := json.Unmarshal(pub.gotValue, &out); err != nil {
		t.Fatalf("unmarshal published envelope: %v", err)
	}

	// Regression guard: svc-08 dependency keys must survive.
	if out.Details.Subject != in.Subject {
		t.Fatalf("details.subject = %q, want %q", out.Details.Subject, in.Subject)
	}
	if out.Details.PlainText != in.Body {
		t.Fatalf("details.plain_text = %q, want %q", out.Details.PlainText, in.Body)
	}
	if len(out.Details.IntentLabels) != 2 {
		t.Fatalf("details.intent_labels = %v, want the 2 raw Python labels", out.Details.IntentLabels)
	}

	// Facets must carry the injected impersonation/deception/urgency values.
	f := out.Details.Facets
	if f.ImpersonationScore != 0.75 {
		t.Fatalf("facets.impersonation_score = %v, want 0.75", f.ImpersonationScore)
	}
	if f.ImpersonatedBrand == nil || *f.ImpersonatedBrand != brand {
		t.Fatalf("facets.impersonated_brand = %v, want %q", f.ImpersonatedBrand, brand)
	}
	if f.DeceptionScore != 0.6 {
		t.Fatalf("facets.deception_score = %v, want 0.6", f.DeceptionScore)
	}
	if f.UrgencyScore != 0.8 {
		t.Fatalf("facets.urgency_score = %v, want 0.8", f.UrgencyScore)
	}
	// credential_harvest + urgency_threat -> credential_harvesting wins (priority).
	if f.IntentLabel != intentCredentialHarvesting {
		t.Fatalf("facets.intent_label = %q, want %q", f.IntentLabel, intentCredentialHarvesting)
	}
	if f.IntentConfidence <= 0 || f.IntentConfidence > 1 {
		t.Fatalf("facets.intent_confidence = %v, want (0,1]", f.IntentConfidence)
	}

	// model_versions populated.
	if out.Details.ModelVersions.Impersonation == "" || out.Details.ModelVersions.Intent == "" {
		t.Fatalf("model_versions not populated: %+v", out.Details.ModelVersions)
	}
}

// TestProcess_FallbackEmitsNeutralFacets proves the timeout/fallback path emits
// the same envelope shape: neutral facets + model_versions so consumers can
// always read them.
func TestProcess_FallbackEmitsNeutralFacets(t *testing.T) {
	pred := &fakePredictor{err: context.DeadlineExceeded, status: 0}
	pub := &capturingPublisher{}
	in := sampleInput()

	if err := process(context.Background(), in, pred, pub.publish); err != nil {
		t.Fatalf("process returned error on fallback path: %v", err)
	}

	var out struct {
		Details struct {
			Facets        contracts.NLPFacets        `json:"facets"`
			ModelVersions contracts.NLPModelVersions `json:"model_versions"`
		} `json:"details"`
	}
	if err := json.Unmarshal(pub.gotValue, &out); err != nil {
		t.Fatalf("unmarshal published envelope: %v", err)
	}
	if out.Details.Facets.IntentLabel != intentLegitimate {
		t.Fatalf("fallback facets.intent_label = %q, want %q", out.Details.Facets.IntentLabel, intentLegitimate)
	}
	if out.Details.Facets.ImpersonationScore != 0 || out.Details.Facets.DeceptionScore != 0 {
		t.Fatalf("fallback facets must be zero-scored: %+v", out.Details.Facets)
	}
	if out.Details.Facets.ImpersonatedBrand != nil {
		t.Fatalf("fallback impersonated_brand = %v, want nil", out.Details.Facets.ImpersonatedBrand)
	}
	if out.Details.ModelVersions.Intent == "" {
		t.Fatalf("fallback model_versions not populated: %+v", out.Details.ModelVersions)
	}

	// Shape-identical invariant: the fallback envelope must carry the same
	// legacy keys the success path emits, so consumers (svc-08 fingerprint
	// reads intent_labels; the console reads confidence/obfuscation) see a
	// stable shape on either path. Decode the raw Details map and assert the
	// keys are present (not silently dropped on a timeout).
	var rawOut struct {
		Details map[string]json.RawMessage `json:"details"`
	}
	if err := json.Unmarshal(pub.gotValue, &rawOut); err != nil {
		t.Fatalf("unmarshal raw envelope: %v", err)
	}
	for _, key := range []string{
		"classification", "phishing_probability", "confidence",
		"intent_labels", "urgency_score", "obfuscation_detected",
		"intent_label", "intent_confidence", "subject", "plain_text",
	} {
		if _, ok := rawOut.Details[key]; !ok {
			t.Fatalf("fallback envelope missing legacy key %q (shape must match success path)", key)
		}
	}
	// intent_labels must be an empty array, not null, for downstream stability.
	if got := string(rawOut.Details["intent_labels"]); got != "[]" {
		t.Fatalf("fallback intent_labels = %s, want []", got)
	}
}
