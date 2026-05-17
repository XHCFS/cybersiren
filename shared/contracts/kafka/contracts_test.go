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
				SourceAdapter: "http",
				MessageID:     "<test@example.com>",
				RawMessageB64: "Zm9v",
				Headers:       map[string]string{"From": "x@y"},
			},
			fresh: func() any { return &contracts.EmailsRaw{} },
		},
		{
			name:    "AnalysisURLs",
			payload: contracts.AnalysisURLs{Meta: meta, URLs: []string{"https://x"}},
			fresh:   func() any { return &contracts.AnalysisURLs{} },
		},
		{
			name:    "AnalysisHeaders",
			payload: contracts.AnalysisHeaders{Meta: meta, Headers: map[string]string{"x": "y"}},
			fresh:   func() any { return &contracts.AnalysisHeaders{} },
		},
		{
			name: "AnalysisAttachments",
			payload: contracts.AnalysisAttachments{
				Meta:        meta,
				Attachments: []contracts.Attachment{{Filename: "a.pdf", SHA256: "ff"}},
			},
			fresh: func() any { return &contracts.AnalysisAttachments{} },
		},
		{
			name:    "AnalysisText",
			payload: contracts.AnalysisText{Meta: meta, Subject: "hi", Body: "body"},
			fresh:   func() any { return &contracts.AnalysisText{} },
		},
		{
			name: "AnalysisPlan",
			payload: contracts.AnalysisPlan{
				Meta:           meta,
				ExpectedScores: []string{contracts.TopicScoresURL, contracts.TopicScoresHeader},
			},
			fresh: func() any { return &contracts.AnalysisPlan{} },
		},
		{
			name: "ScoresURL",
			payload: contracts.ScoresURL{ScoreEnvelope: contracts.ScoreEnvelope{
				Meta: meta, Component: contracts.ComponentURL, Score: 42.0,
			}},
			fresh: func() any { return &contracts.ScoresURL{} },
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
