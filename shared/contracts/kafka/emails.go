package kafka

import "time"

// EmailsRaw is the wire payload published by svc-01-ingestion to emails.raw
// (architecture-spec §1, Step 1). The raw_message field holds the base64
// RFC-822 source so this struct stays JSON-friendly.
type EmailsRaw struct {
	Meta          MessageMeta       `json:"meta"`
	SourceAdapter string            `json:"source_adapter"`
	MessageID     string            `json:"message_id,omitempty"`
	RawMessageB64 string            `json:"raw_message_b64"`
	Headers       map[string]string `json:"headers,omitempty"`
}

// EmailsScored is published by svc-07-aggregator to emails.scored once all
// component scores have arrived (architecture-spec §1, Step 4).
//
// InternalID and FetchedAt are placeholders in v0; the spec requires them to
// align with the DB row in emails(internal_id, fetched_at). Until svc-01
// inserts the row, stubs forward fake values copied from MessageMeta.
type EmailsScored struct {
	Meta            MessageMeta        `json:"meta"`
	InternalID      string             `json:"internal_id"` // placeholder in v0
	FetchedAt       time.Time          `json:"fetched_at"`  // placeholder in v0
	ComponentScores map[string]float64 `json:"component_scores"`
}

// EmailsVerdict is published by svc-08-decision to emails.verdict
// (architecture-spec §1, Step 5).
type EmailsVerdict struct {
	Meta         MessageMeta `json:"meta"`
	InternalID   string      `json:"internal_id"`
	FetchedAt    time.Time   `json:"fetched_at"`
	RiskScore    float64     `json:"risk_score"`
	VerdictLabel string      `json:"verdict_label"` // benign | suspicious | phishing | malware
	FiredRules   []string    `json:"fired_rules,omitempty"`
}
