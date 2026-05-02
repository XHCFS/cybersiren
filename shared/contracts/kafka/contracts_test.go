package kafkacontracts_test

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
		EmailID:       "email-001",
		OrgID:         "org-001",
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
			payload: contracts.EmailsScored{
				Meta:            meta,
				InternalID:      "fake-internal-id",
				FetchedAt:       now,
				ComponentScores: map[string]float64{"url": 50, "nlp": 60},
			},
			fresh: func() any { return &contracts.EmailsScored{} },
		},
		{
			name: "EmailsVerdict",
			payload: contracts.EmailsVerdict{
				Meta: meta, InternalID: "fake", FetchedAt: now,
				RiskScore: 55, VerdictLabel: "suspicious",
			},
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
	m := contracts.NewMeta("e", "o")
	assert.Equal(t, contracts.SchemaVersion, m.SchemaVersion)
	assert.Equal(t, "e", m.EmailID)
	assert.Equal(t, "o", m.OrgID)
	assert.False(t, m.Timestamp.IsZero())
}
