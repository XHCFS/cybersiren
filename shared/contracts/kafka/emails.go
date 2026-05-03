package kafka

import "time"

// EmailsRaw is the wire payload published by svc-01-ingestion to emails.raw
// (architecture-spec §1, Step 1). The raw_message field holds the base64
// RFC-822 source so this struct stays JSON-friendly.
type EmailsRaw struct {
	Meta          MessageMeta       `json:"meta"`
	FetchedAt     time.Time         `json:"fetched_at"`
	SourceAdapter string            `json:"source_adapter"`
	MessageID     string            `json:"message_id,omitempty"`
	RawMessageB64 string            `json:"raw_message_b64"`
	Headers       map[string]string `json:"headers,omitempty"`
}

// EmailsScored is published by svc-07-aggregator to emails.scored once all
// component scores have arrived (architecture-spec §1, Step 4).
//
// InternalID and FetchedAt mirror the partitioned emails (internal_id,
// fetched_at) PK so SVC-08 can write to Postgres without an extra lookup.
// In v0 svc-01 generates them; once the real ingestion path lands they
// will come from the INSERT into emails.
type EmailsScored struct {
	Meta            MessageMeta        `json:"meta"`
	InternalID      int64              `json:"internal_id"`
	FetchedAt       time.Time          `json:"fetched_at"`
	ComponentScores map[string]float64 `json:"component_scores"`
}

// EmailsVerdict is published by svc-08-decision to emails.verdict
// (architecture-spec §1, Step 5).
type EmailsVerdict struct {
	Meta         MessageMeta `json:"meta"`
	InternalID   int64       `json:"internal_id"`
	FetchedAt    time.Time   `json:"fetched_at"`
	RiskScore    float64     `json:"risk_score"`
	VerdictLabel string      `json:"verdict_label"` // benign | suspicious | phishing | malware
	FiredRules   []string    `json:"fired_rules,omitempty"`
}
