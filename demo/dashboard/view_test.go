package main

import (
	"encoding/json"
	"testing"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

func ptrInt(i int) *int { return &i }

// TestViewOf_LegacyEnvelopeDetail proves the dashboard surfaces the rich per-URL
// L1/L2 signals and NLP detail that svc-03/svc-06 emit inside the legacy
// ScoreEnvelope.details (not the typed url_details/facets), plus the typed
// header detail from svc-04.
func TestViewOf_LegacyEnvelopeDetail(t *testing.T) {
	const id = "019ebc59-3c63-7100-8814-98a2fbd698f8"

	// svc-03 legacy ScoreEnvelope on component_details.url
	urlRaw := json.RawMessage(`{
		"component":"url","score":100,
		"details":{"urls_total":1,"per_url":[
			{"url":"http://paypa1-secure.com/verify","score":100,"ti_match":true,
			 "ti_threat_type":"phishing","guard_hit":"typosquat:paypal",
			 "ml_deploy_p":0.93,"ml_verdict":"phishing","label":"phishing"}
		]}}`)
	// svc-06 legacy ScoreEnvelope on component_details.nlp
	nlpRaw := json.RawMessage(`{
		"component":"nlp","score":100,
		"details":{"classification":"phishing","confidence":0.9,
			"intent_labels":["credential_harvesting"],"urgency_score":0.8,
			"obfuscation_detected":true}}`)
	// svc-04 typed ScoresHeaderMessage
	headerRaw, _ := json.Marshal(contracts.ScoresHeaderMessage{
		EmailID: id, Component: "header", Score: 35,
		AuthSubScore: 0, ReputationSubScore: 35, StructuralSubScore: 20,
		Signals: contracts.HeaderSignals{SenderDomain: "paypa1-secure.com"},
	})

	es := &contracts.EmailsScored{
		Meta:        contracts.MessageMeta{EmailID: id, OrgID: 1},
		InternalID:  5,
		URLScore:    ptrInt(100),
		HeaderScore: ptrInt(35),
		NLPScore:    ptrInt(100),
		ComponentDetails: contracts.ComponentDetails{
			URL: urlRaw, NLP: nlpRaw, Header: headerRaw,
		},
	}

	st := newStore(10)
	st.recordSubmit(id, "upload", "Urgent: your account has been limited", "PayPal Security")
	st.applyScored(es)
	v := viewOf(st.get(id))

	// URL: composite + per-link L1 (TI) and L2 (ML) from the legacy envelope.
	if v.Modules.URL == nil {
		t.Fatal("url module nil")
	}
	u := v.Modules.URL
	if u.URLCount != 1 || u.TIBlocked != 1 || u.MLScored != 1 {
		t.Fatalf("url counts: count=%d ti=%d ml=%d (want 1/1/1)", u.URLCount, u.TIBlocked, u.MLScored)
	}
	if len(u.Links) != 1 {
		t.Fatalf("want 1 link, got %d", len(u.Links))
	}
	l := u.Links[0]
	if l.Score == nil || *l.Score != 100 {
		t.Errorf("per-URL overall score = %v, want 100", l.Score)
	}
	if l.MLScore != nil {
		t.Errorf("ml_score must stay nil for the legacy envelope (100 is the overall score, not an L2 score), got %v", l.MLScore)
	}
	if l.Label != "phishing" {
		t.Errorf("per-URL label = %q, want phishing", l.Label)
	}
	if !l.TIMatched {
		t.Error("L1: ti_matched should be true")
	}
	if l.MLVerdict == nil || *l.MLVerdict != "phishing" {
		t.Errorf("L2: ml_verdict = %v, want phishing", l.MLVerdict)
	}
	if l.MLDeployP == nil || *l.MLDeployP < 0.92 {
		t.Errorf("L2: ml_deploy_p = %v, want ~0.93", l.MLDeployP)
	}
	if l.GuardHit == nil || *l.GuardHit != "typosquat:paypal" {
		t.Errorf("guard_hit = %v", l.GuardHit)
	}

	// NLP: legacy classification/urgency/obfuscation, no typed facets.
	if v.Modules.NLP == nil {
		t.Fatal("nlp module nil")
	}
	n := v.Modules.NLP
	if n.Classification != "phishing" {
		t.Errorf("nlp classification = %q", n.Classification)
	}
	if n.Urgency != 0.8 {
		t.Errorf("nlp urgency = %v, want 0.8", n.Urgency)
	}
	if !n.Obfuscation {
		t.Error("nlp obfuscation should be true")
	}
	if n.HasFacets {
		t.Error("legacy NLP should not claim typed facets")
	}

	// Header: typed sub-scores from svc-04.
	if v.Modules.Header == nil || v.Modules.Header.Reputation != 35 {
		t.Fatalf("header reputation sub-score wrong: %+v", v.Modules.Header)
	}

	// Final status reflects scored once the verdict arrives; here only scores.
	if v.Status != "scoring" {
		t.Errorf("status = %q, want scoring (no verdict yet)", v.Status)
	}
}
