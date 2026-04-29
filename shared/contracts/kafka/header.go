// Package kafka holds the Go message types that flow on CyberSiren's Kafka
// pipeline. Each type maps 1:1 to the schema documented in
// docs/architecture/architecture-spec-detail.html (ARCH-SPEC §1 / §3).
//
// The shapes here intentionally use plain JSON tags only — no validation
// dependencies — so they can be imported by any service (producer or
// consumer) without dragging in extra runtime deps.
//
// CONTRACT NOTE for SVC-04:
//
//	`email_id` on every analysis.* / scores.* topic is the BIGINT value
//	of `emails.internal_id`. SVC-04 uses it directly as
//	`rule_hits.entity_id` and as the partitioning key. ARCH-SPEC §14
//	step 3b confirms this mapping. SVC-02 (Parser) is the source of
//	truth and is responsible for emitting the correct `internal_id`.
package kafka

import (
	"encoding/json"
	"time"
)

// AnalysisHeadersMessage matches the `analysis.headers` topic payload.
//
// All fields are optional from the consumer side — SVC-02 may legitimately
// omit fields it could not parse from the raw RFC822 headers. SVC-04 must
// treat zero-values as "missing", not as failed authentication.
type AnalysisHeadersMessage struct {
	// EmailID == emails.internal_id (BIGINT).
	EmailID int64 `json:"email_id"`
	// InternalID is emails.internal_id (BIGINT). Required for rule_hits.entity_id.
	// Populated by SVC-02 immediately after the emails INSERT.
	InternalID int64 `json:"internal_id"`
	// FetchedAt is emails.fetched_at (partition key / FK companion for rule_hits).
	// Populated by SVC-02 alongside InternalID.
	FetchedAt time.Time `json:"fetched_at"`
	// OrgID is the owning tenant; required for rules cache scoping.
	OrgID int64 `json:"org_id"`

	// ── Sender identity ─────────────────────────────────────────────────
	SenderEmail  string `json:"sender_email,omitempty"`
	SenderDomain string `json:"sender_domain,omitempty"`
	SenderName   string `json:"sender_name,omitempty"`
	ReplyToEmail string `json:"reply_to_email,omitempty"`
	ReturnPath   string `json:"return_path,omitempty"`

	// ── IP / agent ──────────────────────────────────────────────────────
	OriginatingIP  string `json:"originating_ip,omitempty"`
	XOriginatingIP string `json:"x_originating_ip,omitempty"`
	MailerAgent    string `json:"mailer_agent,omitempty"`

	// ── Auth results ────────────────────────────────────────────────────
	// Possible values: "pass" | "fail" | "softfail" | "none" | "" (missing).
	AuthSPF   string `json:"auth_spf,omitempty"`
	AuthDKIM  string `json:"auth_dkim,omitempty"`
	AuthDMARC string `json:"auth_dmarc,omitempty"`
	AuthARC   string `json:"auth_arc,omitempty"`

	// ── Threading / metadata ────────────────────────────────────────────
	InReplyTo      string   `json:"in_reply_to,omitempty"`
	ReferencesList []string `json:"references_list,omitempty"`
	SentTimestamp  int64    `json:"sent_timestamp,omitempty"` // raw Unix epoch
	ContentCharset string   `json:"content_charset,omitempty"`
	Precedence     string   `json:"precedence,omitempty"`
	ListID         string   `json:"list_id,omitempty"`

	// ── Received chain ──────────────────────────────────────────────────
	HopCount      int           `json:"hop_count,omitempty"`
	ReceivedChain []ReceivedHop `json:"received_chain,omitempty"`

	// ── Vendor security tags / raw header dump ──────────────────────────
	VendorSecurityTags json.RawMessage `json:"vendor_security_tags,omitempty"`
	HeadersJSON        json.RawMessage `json:"headers_json,omitempty"`
}

// ReceivedHop is a single entry in the Received-chain.
type ReceivedHop struct {
	From      string `json:"from,omitempty"`
	By        string `json:"by,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"` // Unix epoch seconds
}

// ScoresHeaderMessage matches the `scores.header` topic payload.
type ScoresHeaderMessage struct {
	EmailID int64 `json:"email_id"`
	OrgID   int64 `json:"org_id"`

	Component string `json:"component"` // always "header"
	Score     int    `json:"score"`     // [0, 100]

	AuthSubScore       int `json:"auth_sub_score"`
	ReputationSubScore int `json:"reputation_sub_score"`
	StructuralSubScore int `json:"structural_sub_score"`

	FiredRules []FiredRule   `json:"fired_rules"`
	Signals    HeaderSignals `json:"signals"`

	ProcessingTimeMs int `json:"processing_time_ms"`
}

// FiredRule is one rule that contributed to a sub-score.
type FiredRule struct {
	RuleID      int64           `json:"rule_id"`
	RuleName    string          `json:"rule_name"`
	RuleVersion string          `json:"rule_version"`
	ScoreImpact int             `json:"score_impact"`
	MatchDetail json.RawMessage `json:"match_detail,omitempty"`
}

// HeaderSignals is the structured snapshot of every dimension SVC-04
// inspects, attached to scores.header for downstream explainability.
type HeaderSignals struct {
	SPFResult           string  `json:"spf_result"`
	DKIMResult          string  `json:"dkim_result"`
	DMARCResult         string  `json:"dmarc_result"`
	FromReplyToMatch    bool    `json:"from_reply_to_match"`
	FromReturnPathMatch bool    `json:"from_return_path_match"`
	DomainAgeDays       *int    `json:"domain_age_days"`
	TyposquatTarget     *string `json:"typosquat_target"`
	TyposquatDistance   *int    `json:"typosquat_distance"`
	IsFreeProvider      bool    `json:"is_free_provider"`
	HopCount            int     `json:"hop_count"`
	TimeDriftHours      float64 `json:"time_drift_hours"`
}
