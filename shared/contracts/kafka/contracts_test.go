package kafka_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

func TestRoundTrip_AllPayloads(t *testing.T) {
	now := time.Date(2026, 5, 2, 12, 0, 0, 0, time.UTC)
	meta := contracts.MessageMeta{
		EmailID:       "01890000-0000-7000-8000-000000001001",
		OrgID:         42,
		Timestamp:     now,
		TraceID:       "00000000000000000000000000000001",
		SpanID:        "0000000000000001",
		SchemaVersion: contracts.SchemaVersion,
	}

	cases := []struct {
		name    string
		payload any
		fresh   func() any
	}{
		{
			name: "EmailsRaw",
			payload: contracts.EmailsRaw{
				Meta:          meta,
				SourceAdapter: "api",
				MessageID:     "<test@example.com>",
				RawMessageB64: "Zm9v",
				APIKeyID:      99,
				Headers:       map[string]string{"From": "x@y"},
			},
			fresh: func() any { return &contracts.EmailsRaw{} },
		},
		{
			name: "AnalysisURLs",
			payload: contracts.AnalysisURLs{Meta: meta, InternalID: 5005, URLs: []contracts.ExtractedURL{
				{URL: "https://x", VisibleText: "click", Position: "body", HTMLContext: "href"},
				{URL: "https://y"},
			}},
			fresh: func() any { return &contracts.AnalysisURLs{} },
		},
		{
			name: "AnalysisHeadersMessage",
			payload: contracts.AnalysisHeadersMessage{
				EmailID:      "01890000-0000-7000-8000-000000001001",
				InternalID:   5005,
				FetchedAt:    now,
				OrgID:        42,
				SenderDomain: "acme.example",
				AuthSPF:      "pass",
				BodyHTML:     "<html><body>hi</body></html>",
				BodyPlain:    "hi",
			},
			fresh: func() any { return &contracts.AnalysisHeadersMessage{} },
		},
		{
			name: "AnalysisAttachments",
			payload: contracts.AnalysisAttachments{
				Meta: meta,
				Attachments: []contracts.Attachment{{
					Filename: "a.pdf", SHA256: "ff", MD5: "aa", SHA1: "bb",
					ContentID: "cid-1", ContentType: "application/pdf",
					Disposition: "attachment", SizeBytes: 1024,
					Entropy: 7.6, DetectedType: "application/x-msdownload",
				}},
			},
			fresh: func() any { return &contracts.AnalysisAttachments{} },
		},
		{
			name: "AnalysisText",
			payload: contracts.AnalysisText{
				Meta: meta, Subject: "hi", Body: "body",
				SenderName: "Acme", SenderDomain: "acme.example",
				BodyLanguage: "en", WordCount: 1,
			},
			fresh: func() any { return &contracts.AnalysisText{} },
		},
		{
			name: "AnalysisPlan",
			payload: contracts.AnalysisPlan{
				Meta:            meta,
				ExpectedScores:  []string{contracts.TopicScoresURL, contracts.TopicScoresHeader},
				URLCount:        2,
				AttachmentCount: 1,
				HasBody:         true,
				CreatedAt:       now.UnixMilli(),
			},
			fresh: func() any { return &contracts.AnalysisPlan{} },
		},
		{
			name: "ScoresURL",
			payload: func() any {
				src, age, ml := "phishtank", 30, 80
				return contracts.ScoresURL{
					Meta: meta, Component: contracts.ComponentURL, Score: 72,
					URLCount: 1, TIBlockedCount: 1, MLScoredCount: 0,
					CacheHitCount: 0, RiskiestURL: "https://x",
					URLDetails: []contracts.URLDetail{{
						URL: "https://x", Domain: "x", TIMatched: true,
						TISource: &src, DomainAgeDays: &age, HasSSL: true,
						RedirectCount: 0, MLScore: &ml, IsShortened: false,
						EnrichmentAvailable: true,
					}},
					ProcessingTimeMs: 12,
				}
			}(),
			fresh: func() any { return &contracts.ScoresURL{} },
		},
		{
			name: "ScoresAttachment",
			payload: contracts.ScoresAttachment{
				Meta: meta, Component: contracts.ComponentAttachment, Score: 90,
				AttachmentCount: 1, MaliciousCount: 1,
				AttachmentDetails: []contracts.AttachmentDetail{{
					SHA256: "ff", Filename: "a.exe", ContentType: "application/x-msdownload",
					SizeBytes: 2048, Entropy: 7.8, IsMalicious: true,
					ExtensionMismatch: true, HasMacros: false,
					IsDangerousExtension: true, IndividualScore: 90,
				}},
				ProcessingTimeMs: 8,
			},
			fresh: func() any { return &contracts.ScoresAttachment{} },
		},
		{
			name: "ScoresNLP",
			payload: func() any {
				brand := "PayPal"
				return contracts.ScoresNLP{
					Meta: meta, Component: contracts.ComponentNLP, Score: 60,
					Facets: contracts.NLPFacets{
						UrgencyScore: 0.7, IntentLabel: "credential_harvesting",
						IntentConfidence: 0.82, ImpersonationScore: 0.4,
						ImpersonatedBrand: &brand, DeceptionScore: 0.55,
					},
					ModelVersions: contracts.NLPModelVersions{
						Urgency: "heur-v1", Intent: "distilbert-v1.0",
						Impersonation: "heur-v1", Deception: "heur-v1",
					},
					ProcessingTimeMs: 30,
				}
			}(),
			fresh: func() any { return &contracts.ScoresNLP{} },
		},
		{
			name: "EmailsScored",
			payload: func() any {
				url, hdr, nlp := 72, 85, 60
				return contracts.EmailsScored{
					Meta:                 meta,
					InternalID:           1001,
					FetchedAt:            now,
					URLScore:             &url,
					HeaderScore:          &hdr,
					NLPScore:             &nlp,
					PartialAnalysis:      false,
					AggregationLatencyMS: 312,
					ComponentDetails: contracts.ComponentDetails{
						URL:    json.RawMessage(`{"meta":{},"score":72}`),
						Header: json.RawMessage(`{"email_id":"01890000-0000-7000-8000-000000001001","score":85}`),
						NLP:    json.RawMessage(`{"meta":{},"score":60}`),
					},
				}
			}(),
			fresh: func() any { return &contracts.EmailsScored{} },
		},
		{
			name: "EmailsScored_Partial",
			payload: contracts.EmailsScored{
				Meta:              meta,
				InternalID:        1001,
				FetchedAt:         now,
				PartialAnalysis:   true,
				MissingComponents: []string{contracts.TopicScoresAttachment, contracts.TopicScoresNLP},
				TimeoutTriggered:  true,
				ComponentDetails:  contracts.ComponentDetails{},
			},
			fresh: func() any { return &contracts.EmailsScored{} },
		},
		{
			name: "EmailsVerdict",
			payload: func() any {
				camp := int64(17)
				hdr, content, urlR := 85, 60, 72
				return contracts.EmailsVerdict{
					Meta: meta, InternalID: 1001, FetchedAt: now,
					RiskScore:           78,
					VerdictLabel:        "phishing",
					Confidence:          0.82,
					HeaderRiskScore:     &hdr,
					ContentRiskScore:    &content,
					URLRiskScore:        &urlR,
					CampaignID:          &camp,
					CampaignFingerprint: "a3f8",
					IsNewCampaign:       false,
					FiredRules: []contracts.VerdictFiredRule{
						{RuleID: 42, RuleName: "spf-fail-high-entropy-subject", ScoreImpact: 15},
					},
					VerdictSource:         "model",
					ModelVersion:          "xgb-v1.2+distilbert-v1.0",
					ProcessingTimeTotalMS: 45,
				}
			}(),
			fresh: func() any { return &contracts.EmailsVerdict{} },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.payload)
			require.NoError(t, err)

			out := tc.fresh()
			require.NoError(t, json.Unmarshal(b, out))

			b2, err := json.Marshal(out)
			require.NoError(t, err)
			assert.JSONEq(t, string(b), string(b2))
		})
	}
}

func TestAllTopicsCount(t *testing.T) {
	assert.Len(t, contracts.AllTopics, 12)
}

// TestSpecWireTags pins the spec field names so a rename doesn't silently
// break the wire contract with the non-Go consumers / persisted columns.
func TestSpecWireTags(t *testing.T) {
	meta := contracts.NewMeta("e1", 2)

	raw, err := json.Marshal(contracts.EmailsRaw{Meta: meta, RawMessageB64: "Zg==", APIKeyID: 7})
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"raw_rfc822"`)
	assert.Contains(t, string(raw), `"api_key_id"`)
	assert.NotContains(t, string(raw), `"raw_message_b64"`)

	urls, err := json.Marshal(contracts.AnalysisURLs{Meta: meta, InternalID: 5005, URLs: []contracts.ExtractedURL{
		{URL: "https://x", VisibleText: "t", Position: "body", HTMLContext: "href"},
	}})
	require.NoError(t, err)
	for _, k := range []string{`"visible_text"`, `"position"`, `"html_context"`} {
		assert.Contains(t, string(urls), k)
	}
	// svc-02 forwards internal_id so svc-03 can look up email_urls without a
	// message_id round-trip; it is omitted (zero) until svc-02 populates it.
	assert.Contains(t, string(urls), `"internal_id":5005`)
	zeroURLs, err := json.Marshal(contracts.AnalysisURLs{Meta: meta})
	require.NoError(t, err)
	assert.NotContains(t, string(zeroURLs), `"internal_id"`)

	att, err := json.Marshal(contracts.Attachment{
		Filename: "a", SHA256: "ff", MD5: "aa", SHA1: "bb", ContentID: "c",
		Disposition: "inline", Entropy: 1.5, DetectedType: "text/plain",
	})
	require.NoError(t, err)
	for _, k := range []string{`"md5"`, `"sha1"`, `"content_id"`, `"disposition"`, `"entropy"`, `"detected_type"`} {
		assert.Contains(t, string(att), k)
	}

	txt, err := json.Marshal(contracts.AnalysisText{Meta: meta, SenderDomain: "d", BodyLanguage: "en", WordCount: 3})
	require.NoError(t, err)
	for _, k := range []string{`"sender_domain"`, `"body_language"`, `"word_count"`} {
		assert.Contains(t, string(txt), k)
	}

	hdr, err := json.Marshal(contracts.AnalysisHeadersMessage{EmailID: "e1", InternalID: 9, OrgID: 2, BodyHTML: "<p>x</p>", BodyPlain: "x"})
	require.NoError(t, err)
	assert.Contains(t, string(hdr), `"body_html"`)
	assert.Contains(t, string(hdr), `"body_plain"`)
	assert.Contains(t, string(hdr), `"internal_id"`)

	plan, err := json.Marshal(contracts.AnalysisPlan{Meta: meta, URLCount: 1, AttachmentCount: 1, HasBody: true, CreatedAt: 5})
	require.NoError(t, err)
	for _, k := range []string{`"url_count"`, `"attachment_count"`, `"has_body"`, `"created_at"`} {
		assert.Contains(t, string(plan), k)
	}

	nlp, err := json.Marshal(contracts.ScoresNLP{Meta: meta, Component: contracts.ComponentNLP, Score: 50})
	require.NoError(t, err)
	assert.Contains(t, string(nlp), `"facets"`)
	assert.Contains(t, string(nlp), `"model_versions"`)

	// scores.header forwards internal_id so the aggregator (no DB access) can
	// place the surrogate PK on emails.scored without a lookup.
	shdr, err := json.Marshal(contracts.ScoresHeaderMessage{
		EmailID: "e1", InternalID: 9, OrgID: 2, Component: contracts.ComponentHeader, Score: 50,
	})
	require.NoError(t, err)
	assert.Contains(t, string(shdr), `"internal_id":9`)
	var shdrOut contracts.ScoresHeaderMessage
	require.NoError(t, json.Unmarshal(shdr, &shdrOut))
	assert.Equal(t, int64(9), shdrOut.InternalID)

	// score is an int, never a float on the wire.
	assert.Contains(t, string(nlp), `"score":50`)
}

// TestTypedScoresScoreIsInt guards G13's float→int score change on the typed
// payloads.
func TestTypedScoresScoreIsInt(t *testing.T) {
	meta := contracts.NewMeta("e1", 2)
	for _, b := range [][]byte{
		mustJSON(t, contracts.ScoresURL{Meta: meta, Component: contracts.ComponentURL, Score: 100}),
		mustJSON(t, contracts.ScoresAttachment{Meta: meta, Component: contracts.ComponentAttachment, Score: 100}),
		mustJSON(t, contracts.ScoresNLP{Meta: meta, Component: contracts.ComponentNLP, Score: 100}),
	} {
		assert.Contains(t, string(b), `"score":100`)
		assert.NotContains(t, string(b), `"score":100.0`)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// validator is implemented by every typed payload that carries score data.
type validator interface{ Validate() error }

func ptr(i int) *int { return &i }

// TestValidate_ScorePayloads checks the additive Validate() methods: in-range
// + ids-present pass, out-of-range scores (negative and >100) fail, the two-id
// header pair rejects both-zero, and nil pointer scores do not trip.
func TestValidate_ScorePayloads(t *testing.T) {
	meta := contracts.NewMeta("e1001", 42)

	cases := []struct {
		name    string
		payload validator
		wantErr bool
	}{
		// ── ScoresURL ───────────────────────────────────────────────────
		{"ScoresURL/ok", contracts.ScoresURL{Meta: meta, Component: contracts.ComponentURL, Score: 72, URLCount: 5}, false},
		{"ScoresURL/zero", contracts.ScoresURL{Meta: meta, Component: contracts.ComponentURL, Score: 0}, false},
		{"ScoresURL/max", contracts.ScoresURL{Meta: meta, Component: contracts.ComponentURL, Score: 100}, false},
		{"ScoresURL/negative", contracts.ScoresURL{Meta: meta, Component: contracts.ComponentURL, Score: -1}, true},
		{"ScoresURL/over", contracts.ScoresURL{Meta: meta, Component: contracts.ComponentURL, Score: 101}, true},

		// ── ScoresAttachment ────────────────────────────────────────────
		{"ScoresAttachment/ok", contracts.ScoresAttachment{Meta: meta, Component: contracts.ComponentAttachment, Score: 90, AttachmentCount: 3}, false},
		{"ScoresAttachment/negative", contracts.ScoresAttachment{Meta: meta, Component: contracts.ComponentAttachment, Score: -5}, true},
		{"ScoresAttachment/over", contracts.ScoresAttachment{Meta: meta, Component: contracts.ComponentAttachment, Score: 200}, true},

		// ── ScoresNLP ───────────────────────────────────────────────────
		{"ScoresNLP/ok", contracts.ScoresNLP{Meta: meta, Component: contracts.ComponentNLP, Score: 60}, false},
		{"ScoresNLP/negative", contracts.ScoresNLP{Meta: meta, Component: contracts.ComponentNLP, Score: -1}, true},
		{"ScoresNLP/over", contracts.ScoresNLP{Meta: meta, Component: contracts.ComponentNLP, Score: 101}, true},

		// ── ScoresHeaderMessage (score range + logical-id presence) ─────
		// email_id is the always-present logical id (UUIDv7 string); it can no
		// longer stand in for the int64 internal_id, so Validate keys only off
		// email_id's presence (LANDMINE B). internal_id may legitimately be zero.
		{"ScoresHeaderMessage/ok", contracts.ScoresHeaderMessage{EmailID: "e1001", InternalID: 5005, OrgID: 42, Component: contracts.ComponentHeader, Score: 50, AuthSubScore: 200}, false},
		{"ScoresHeaderMessage/emailID-only", contracts.ScoresHeaderMessage{EmailID: "e1001", OrgID: 42, Component: contracts.ComponentHeader, Score: 50}, false},
		{"ScoresHeaderMessage/internalID-only", contracts.ScoresHeaderMessage{InternalID: 5005, OrgID: 42, Component: contracts.ComponentHeader, Score: 50}, true},
		{"ScoresHeaderMessage/no-email-id", contracts.ScoresHeaderMessage{OrgID: 42, Component: contracts.ComponentHeader, Score: 50}, true},
		{"ScoresHeaderMessage/negative", contracts.ScoresHeaderMessage{EmailID: "e1001", Component: contracts.ComponentHeader, Score: -1}, true},
		{"ScoresHeaderMessage/over", contracts.ScoresHeaderMessage{EmailID: "e1001", Component: contracts.ComponentHeader, Score: 101}, true},

		// ── EmailsScored (nullable component scores + addressing key) ───
		// internal_id is the verdict-row PK; email_id (UUIDv7 string) can NOT
		// substitute for it (LANDMINE B), so internal_id<=0 is unaddressable
		// poison svc-08 would silently drop — Validate rejects it here.
		{"EmailsScored/all-nil", contracts.EmailsScored{Meta: meta, InternalID: 1001}, false},
		{"EmailsScored/in-range", contracts.EmailsScored{Meta: meta, InternalID: 1001, URLScore: ptr(72), HeaderScore: ptr(0), AttachmentScore: ptr(100), NLPScore: ptr(60)}, false},
		{"EmailsScored/internalID-zero", contracts.EmailsScored{Meta: meta, InternalID: 0, URLScore: ptr(50)}, true},
		{"EmailsScored/internalID-negative", contracts.EmailsScored{Meta: meta, InternalID: -1}, true},
		{"EmailsScored/url-negative", contracts.EmailsScored{Meta: meta, InternalID: 1001, URLScore: ptr(-1)}, true},
		{"EmailsScored/header-over", contracts.EmailsScored{Meta: meta, InternalID: 1001, HeaderScore: ptr(101)}, true},
		{"EmailsScored/attachment-over", contracts.EmailsScored{Meta: meta, InternalID: 1001, AttachmentScore: ptr(150)}, true},
		{"EmailsScored/nlp-negative", contracts.EmailsScored{Meta: meta, InternalID: 1001, NLPScore: ptr(-3)}, true},

		// ── EmailsVerdict (RiskScore + nullable component risk scores) ──
		{"EmailsVerdict/ok", contracts.EmailsVerdict{Meta: meta, InternalID: 1001, RiskScore: 78, HeaderRiskScore: ptr(85), Confidence: 0.82}, false},
		{"EmailsVerdict/nil-components", contracts.EmailsVerdict{Meta: meta, InternalID: 1001, RiskScore: 0}, false},
		{"EmailsVerdict/risk-negative", contracts.EmailsVerdict{Meta: meta, InternalID: 1001, RiskScore: -1}, true},
		{"EmailsVerdict/risk-over", contracts.EmailsVerdict{Meta: meta, InternalID: 1001, RiskScore: 101}, true},
		{"EmailsVerdict/header-risk-over", contracts.EmailsVerdict{Meta: meta, InternalID: 1001, RiskScore: 50, HeaderRiskScore: ptr(200)}, true},
		{"EmailsVerdict/url-risk-negative", contracts.EmailsVerdict{Meta: meta, InternalID: 1001, RiskScore: 50, URLRiskScore: ptr(-2)}, true},
		{"EmailsVerdict/content-risk-over", contracts.EmailsVerdict{Meta: meta, InternalID: 1001, RiskScore: 50, ContentRiskScore: ptr(101)}, true},
		{"EmailsVerdict/attachment-risk-negative", contracts.EmailsVerdict{Meta: meta, InternalID: 1001, RiskScore: 50, AttachmentRiskScore: ptr(-1)}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.payload.Validate()
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestValidate_DoesNotMutateWire confirms Validate() is read-only: a payload
// that passes validation round-trips byte-for-byte identically to one that was
// never validated.
func TestValidate_DoesNotMutateWire(t *testing.T) {
	meta := contracts.NewMeta("e1001", 42)
	s := contracts.ScoresURL{Meta: meta, Component: contracts.ComponentURL, Score: 72, URLCount: 5}

	before, err := json.Marshal(s)
	require.NoError(t, err)
	require.NoError(t, s.Validate())
	after, err := json.Marshal(s)
	require.NoError(t, err)
	assert.JSONEq(t, string(before), string(after))
}

func TestNewMetaSchemaVersion(t *testing.T) {
	m := contracts.NewMeta("e7", 8)
	assert.Equal(t, contracts.SchemaVersion, m.SchemaVersion)
	assert.Equal(t, "e7", m.EmailID)
	assert.Equal(t, int64(8), m.OrgID)
	assert.False(t, m.Timestamp.IsZero())
}

func TestNewMetaWithFetched(t *testing.T) {
	clock := time.Date(2026, 4, 10, 15, 30, 0, 0, time.UTC)
	m := contracts.NewMetaWithFetched("e10", 20, clock)
	assert.Equal(t, "e10", m.EmailID)
	assert.Equal(t, int64(20), m.OrgID)
	assert.True(t, m.FetchedAt.Equal(clock))
	assert.Equal(t, contracts.SchemaVersion, m.SchemaVersion)
}

func TestMessageMetaFetchedAtJSONRoundTrip(t *testing.T) {
	// Omitting fetched_at on the wire must decode to zero FetchedAt so consumers treat it as absent.
	payload := []byte(`{"email_id":"e1","org_id":2,"timestamp":"2026-01-02T03:04:05Z","schema_version":1}`)
	var m contracts.MessageMeta
	require.NoError(t, json.Unmarshal(payload, &m))
	assert.True(t, m.FetchedAt.IsZero())

	with := contracts.NewMetaWithFetched("e1", 2, time.Date(2026, 3, 3, 1, 0, 0, 0, time.FixedZone("east", 3600)))
	b2, err := json.Marshal(with)
	require.NoError(t, err)
	assert.Contains(t, string(b2), `"fetched_at":"2026-03-03T00:00:00Z"`)

	var back contracts.MessageMeta
	require.NoError(t, json.Unmarshal(b2, &back))
	assert.True(t, back.FetchedAt.Equal(time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC)))
}

func TestEmailsScored_nilScorePointersOmitJSONKeys(t *testing.T) {
	now := time.Date(2026, 5, 2, 12, 0, 0, 0, time.UTC)
	meta := contracts.NewMetaWithFetched("e42", 7, now)
	es := contracts.EmailsScored{
		Meta:             meta,
		InternalID:       1001,
		FetchedAt:        now,
		PartialAnalysis:  false,
		ComponentDetails: contracts.ComponentDetails{},
	}
	b, err := json.Marshal(es)
	require.NoError(t, err)
	s := string(b)
	assert.NotContains(t, s, `"url_score"`)
	assert.NotContains(t, s, `"header_score"`)
	assert.NotContains(t, s, `"attachment_score"`)
	assert.NotContains(t, s, `"nlp_score"`)

	var out contracts.EmailsScored
	require.NoError(t, json.Unmarshal(b, &out))
	assert.Nil(t, out.URLScore)
	assert.Nil(t, out.HeaderScore)
	assert.Nil(t, out.AttachmentScore)
	assert.Nil(t, out.NLPScore)
	assert.Equal(t, int64(1001), out.InternalID)
	assert.True(t, out.FetchedAt.Equal(now))
}
