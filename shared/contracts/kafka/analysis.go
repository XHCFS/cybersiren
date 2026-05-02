package kafkacontracts

// AnalysisURLs is published by svc-02-parser to analysis.urls — the list of
// URLs extracted from the email body for downstream URL scoring.
type AnalysisURLs struct {
	Meta MessageMeta `json:"meta"`
	URLs []string    `json:"urls"`
}

// AnalysisHeaders is published by svc-02-parser to analysis.headers.
type AnalysisHeaders struct {
	Meta    MessageMeta       `json:"meta"`
	Headers map[string]string `json:"headers"`
}

// Attachment represents one attachment slot in analysis.attachments.
type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type,omitempty"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
}

// AnalysisAttachments is published by svc-02-parser to analysis.attachments.
type AnalysisAttachments struct {
	Meta        MessageMeta  `json:"meta"`
	Attachments []Attachment `json:"attachments"`
}

// AnalysisText is published by svc-02-parser to analysis.text — the cleaned
// subject + body sent to the NLP classifier.
type AnalysisText struct {
	Meta    MessageMeta `json:"meta"`
	Subject string      `json:"subject"`
	Body    string      `json:"body"`
}

// AnalysisPlan is published by svc-02-parser to analysis.plans — the list of
// score topics that the aggregator should expect for this email_id.
type AnalysisPlan struct {
	Meta           MessageMeta `json:"meta"`
	ExpectedScores []string    `json:"expected_scores"` // topic names: scores.url, scores.header, ...
}
