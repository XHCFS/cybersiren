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
		EmailID:       1001,
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
			payload: contracts.AnalysisURLs{Meta: meta, URLs: []contracts.ExtractedURL{
				{URL: "https://x", VisibleText: "click", Position: "body", HTMLContext: "href"},
				{URL: "https://y"},
			}},
			fresh: func() any { return &contracts.AnalysisURLs{} },
		},
		{
			name: "AnalysisHeaders",
			payload: contracts.AnalysisHeaders{
				Meta:      meta,
				Headers:   map[string]string{"x": "y"},
				BodyHTML:  "<html><body>hi</body></html>",
				BodyPlain: "hi",
			},
			fresh: func() any { return &contracts.AnalysisHeaders{} },
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
						Header: json.RawMessage(`{"email_id":1001,"score":85}`),
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
	meta := contracts.NewMeta(1, 2)

	raw, err := json.Marshal(contracts.EmailsRaw{Meta: meta, RawMessageB64: "Zg==", APIKeyID: 7})
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"raw_rfc822"`)
	assert.Contains(t, string(raw), `"api_key_id"`)
	assert.NotContains(t, string(raw), `"raw_message_b64"`)

	urls, err := json.Marshal(contracts.AnalysisURLs{Meta: meta, URLs: []contracts.ExtractedURL{
		{URL: "https://x", VisibleText: "t", Position: "body", HTMLContext: "href"},
	}})
	require.NoError(t, err)
	for _, k := range []string{`"visible_text"`, `"position"`, `"html_context"`} {
		assert.Contains(t, string(urls), k)
	}

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

	hdr, err := json.Marshal(contracts.AnalysisHeaders{Meta: meta, BodyHTML: "<p>x</p>", BodyPlain: "x"})
	require.NoError(t, err)
	assert.Contains(t, string(hdr), `"body_html"`)
	assert.Contains(t, string(hdr), `"body_plain"`)

	plan, err := json.Marshal(contracts.AnalysisPlan{Meta: meta, URLCount: 1, AttachmentCount: 1, HasBody: true, CreatedAt: 5})
	require.NoError(t, err)
	for _, k := range []string{`"url_count"`, `"attachment_count"`, `"has_body"`, `"created_at"`} {
		assert.Contains(t, string(plan), k)
	}

	nlp, err := json.Marshal(contracts.ScoresNLP{Meta: meta, Component: contracts.ComponentNLP, Score: 50})
	require.NoError(t, err)
	assert.Contains(t, string(nlp), `"facets"`)
	assert.Contains(t, string(nlp), `"model_versions"`)
	// score is an int, never a float on the wire.
	assert.Contains(t, string(nlp), `"score":50`)
}

// TestTypedScoresScoreIsInt guards G13's float→int score change on the typed
// payloads.
func TestTypedScoresScoreIsInt(t *testing.T) {
	meta := contracts.NewMeta(1, 2)
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

func TestNewMetaSchemaVersion(t *testing.T) {
	m := contracts.NewMeta(7, 8)
	assert.Equal(t, contracts.SchemaVersion, m.SchemaVersion)
	assert.Equal(t, int64(7), m.EmailID)
	assert.Equal(t, int64(8), m.OrgID)
	assert.False(t, m.Timestamp.IsZero())
}

func TestNewMetaWithFetched(t *testing.T) {
	clock := time.Date(2026, 4, 10, 15, 30, 0, 0, time.UTC)
	m := contracts.NewMetaWithFetched(10, 20, clock)
	assert.Equal(t, int64(10), m.EmailID)
	assert.Equal(t, int64(20), m.OrgID)
	assert.True(t, m.FetchedAt.Equal(clock))
	assert.Equal(t, contracts.SchemaVersion, m.SchemaVersion)
}

func TestMessageMetaFetchedAtJSONRoundTrip(t *testing.T) {
	// Omitting fetched_at on the wire must decode to zero FetchedAt so consumers treat it as absent.
	payload := []byte(`{"email_id":1,"org_id":2,"timestamp":"2026-01-02T03:04:05Z","schema_version":1}`)
	var m contracts.MessageMeta
	require.NoError(t, json.Unmarshal(payload, &m))
	assert.True(t, m.FetchedAt.IsZero())

	with := contracts.NewMetaWithFetched(1, 2, time.Date(2026, 3, 3, 1, 0, 0, 0, time.FixedZone("east", 3600)))
	b2, err := json.Marshal(with)
	require.NoError(t, err)
	assert.Contains(t, string(b2), `"fetched_at":"2026-03-03T00:00:00Z"`)

	var back contracts.MessageMeta
	require.NoError(t, json.Unmarshal(b2, &back))
	assert.True(t, back.FetchedAt.Equal(time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC)))
}

func TestEmailsScored_nilScorePointersOmitJSONKeys(t *testing.T) {
	now := time.Date(2026, 5, 2, 12, 0, 0, 0, time.UTC)
	meta := contracts.NewMetaWithFetched(42, 7, now)
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
