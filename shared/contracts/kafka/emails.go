package kafka

import (
	"encoding/json"
	"time"
)

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

// ComponentDetails carries the full upstream score messages forward to the
// Decision Engine (SVC-08). Each field is the raw JSON of the corresponding
// scores.* message, so the engine can extract analyser-specific signals
// (sender_domain, intent, primary URL domain, ...) without re-coupling
// SVC-08 to every analyser's typed schema.
//
// Empty / missing fields encode as JSON null (omitempty produces "null" via
// json.RawMessage when the message was not received). The Decision Engine
// treats a zero-length RawMessage as "component absent" — same semantics as
// the matching *Score top-level pointer being nil.
type ComponentDetails struct {
	URL        json.RawMessage `json:"url,omitempty"`
	Header     json.RawMessage `json:"header,omitempty"`
	Attachment json.RawMessage `json:"attachment,omitempty"`
	NLP        json.RawMessage `json:"nlp,omitempty"`
}

// EmailsScored is published by svc-07-aggregator to emails.scored once all
// expected component scores have arrived (architecture-spec §1, Step 4).
//
// InternalID and FetchedAt mirror the partitioned emails (internal_id,
// fetched_at) PK so SVC-08 can write to Postgres without an extra lookup.
//
// Top-level *Score fields are nullable — they are nil when the component
// did not appear in analysis.plans (e.g. attachment for an email without
// attachments) or when aggregation timed out before that score arrived.
// SVC-08 must not assume a non-nil score; partial analysis is signalled
// via PartialAnalysis + MissingComponents.
//
// ComponentDetails carries the original score messages verbatim for
// downstream analysis (campaign fingerprinting reads sender_domain from
// component_details.header, primary URL domain from component_details.url,
// intent from component_details.nlp.details, etc.).
type EmailsScored struct {
	Meta       MessageMeta `json:"meta"`
	InternalID int64       `json:"internal_id"`
	FetchedAt  time.Time   `json:"fetched_at"`

	URLScore        *int `json:"url_score,omitempty"`
	HeaderScore     *int `json:"header_score,omitempty"`
	AttachmentScore *int `json:"attachment_score,omitempty"`
	NLPScore        *int `json:"nlp_score,omitempty"`

	PartialAnalysis      bool     `json:"partial_analysis"`
	MissingComponents    []string `json:"missing_components,omitempty"`
	TimeoutTriggered     bool     `json:"timeout_triggered,omitempty"`
	AggregationLatencyMS int64    `json:"aggregation_latency_ms,omitempty"`

	ComponentDetails ComponentDetails `json:"component_details"`
}

// EmailsVerdict is published by svc-08-decision to emails.verdict
// (architecture-spec §1, Step 5).
//
// All component risk scores are mirrored as nullable pointers so the wire
// shape can faithfully represent partial analyses (a missing attachment
// score is null rather than 0). The blended/final RiskScore is always
// present and clamped to [0, 100].
type EmailsVerdict struct {
	Meta       MessageMeta `json:"meta"`
	InternalID int64       `json:"internal_id"`
	FetchedAt  time.Time   `json:"fetched_at"`

	VerdictLabel string  `json:"verdict_label"` // benign | suspicious | phishing | malware | spam | unknown
	Confidence   float64 `json:"confidence"`    // [0.0, 1.0]
	RiskScore    int     `json:"risk_score"`    // [0, 100]

	HeaderRiskScore     *int `json:"header_risk_score,omitempty"`
	ContentRiskScore    *int `json:"content_risk_score,omitempty"`
	URLRiskScore        *int `json:"url_risk_score,omitempty"`
	AttachmentRiskScore *int `json:"attachment_risk_score,omitempty"`

	CampaignID          *int64 `json:"campaign_id,omitempty"`
	CampaignFingerprint string `json:"campaign_fingerprint,omitempty"`
	IsNewCampaign       bool   `json:"is_new_campaign"`

	FiredRules            []VerdictFiredRule `json:"fired_rules,omitempty"`
	VerdictSource         string             `json:"verdict_source"` // "model" | "rule"
	ModelVersion          string             `json:"model_version,omitempty"`
	PartialAnalysis       bool               `json:"partial_analysis"`
	ProcessingTimeTotalMS int64              `json:"processing_time_total_ms"`
}

// VerdictFiredRule is the trimmed rule-fire summary attached to
// emails.verdict. The full match_detail blob lives in rule_hits in
// Postgres; this is the explainability surface for downstream consumers
// (notification, dashboard) that should not have to query the DB.
type VerdictFiredRule struct {
	RuleID      int64  `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	ScoreImpact int    `json:"score_impact"`
}
