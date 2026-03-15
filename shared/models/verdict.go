package models

import (
	"encoding/json"
)

// EntityType identifies which table an entity lives in.
type EntityType string

const (
	EntityTypeEmail      EntityType = "email"
	EntityTypeThreat     EntityType = "threat"
	EntityTypeAttachment EntityType = "attachment"
	EntityTypeCampaign   EntityType = "campaign"
)

// VerdictLabel mirrors the verdict_label Postgres ENUM.
type VerdictLabel string

const (
	VerdictBenign     VerdictLabel = "benign"
	VerdictSuspicious VerdictLabel = "suspicious"
	VerdictPhishing   VerdictLabel = "phishing"
	VerdictMalware    VerdictLabel = "malware"
	VerdictSpam       VerdictLabel = "spam"
	VerdictUnknown    VerdictLabel = "unknown"
)

// VerdictSource mirrors the verdict_source Postgres ENUM.
type VerdictSource string

const (
	VerdictSourceModel   VerdictSource = "model"
	VerdictSourceAnalyst VerdictSource = "analyst"
	VerdictSourceFeed    VerdictSource = "feed"
	VerdictSourceRule    VerdictSource = "rule"
)

// FinalVerdict is the in-memory result produced at the end of the detection
// pipeline, before it is persisted as a Verdict row.
type FinalVerdict struct {
	OrgID      int64         `json:"org_id"      validate:"required"`
	EntityType EntityType    `json:"entity_type" validate:"required"`
	EntityID   int64         `json:"entity_id"   validate:"required"`
	Label      VerdictLabel  `json:"label"       validate:"required"`
	Confidence float64       `json:"confidence"  validate:"min=0,max=1"`
	Source     VerdictSource `json:"source"      validate:"required"`

	HeaderRiskScore     int `json:"header_risk_score"`
	ContentRiskScore    int `json:"content_risk_score"`
	AttachmentRiskScore int `json:"attachment_risk_score"`
	URLRiskScore        int `json:"url_risk_score"`
	TotalRiskScore      int `json:"total_risk_score" validate:"min=0,max=100"`

	FiredRules   []FiredRule `json:"fired_rules,omitempty"`
	ModelVersion string      `json:"model_version,omitempty"`
	Notes        string      `json:"notes,omitempty"`
}

// FiredRule is a summary of a rule that fired during evaluation.
type FiredRule struct {
	RuleID      int64           `json:"rule_id"`
	RuleName    string          `json:"rule_name"`
	RuleVersion string          `json:"rule_version"`
	ScoreImpact int             `json:"score_impact"`
	MatchDetail json.RawMessage `json:"match_detail,omitempty"`
}

// RuleStatus mirrors the rule_status Postgres ENUM.
type RuleStatus string

const (
	RuleStatusDraft    RuleStatus = "draft"
	RuleStatusActive   RuleStatus = "active"
	RuleStatusDisabled RuleStatus = "disabled"
	RuleStatusArchived RuleStatus = "archived"
)

// EnrichmentEntityType is the subset of EntityType values that enrichment_jobs and
// enrichment_results accept. campaign is not a valid enrichment target.
type EnrichmentEntityType = EntityType

const (
	EnrichmentEntityTypeEmail      EnrichmentEntityType = EntityTypeEmail
	EnrichmentEntityTypeAttachment EnrichmentEntityType = EntityTypeAttachment
	EnrichmentEntityTypeThreat     EnrichmentEntityType = EntityTypeThreat
)
