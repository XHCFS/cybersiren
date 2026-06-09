// Package kafka holds the Go message types that flow on CyberSiren's Kafka
// pipeline. Each type maps 1:1 to the schema documented in
// docs/architecture/architecture-spec-detail.html (ARCH-SPEC §1 / §3).
//
// The shapes here intentionally use plain JSON tags only — no validation
// dependencies — so they can be imported by any service (producer or
// consumer) without dragging in extra runtime deps.
//
// CONTRACT NOTE for SVC-04 — two-id model (ARCH-SPEC §1 / §16 D11, G17):
//
//	`email_id` and `internal_id` are TWO DISTINCT identifiers:
//	  - `email_id`  — the logical id assigned by SVC-01, the Kafka partition
//	    key, opaque. Its contract type is a UUIDv7 string; it is carried as
//	    an int64 only on an interim basis (SVC-01 emits
//	    time.Now().UnixNano()/1000). The uuid.NewV7() swap + widening to a
//	    string is tracked by issue #142.
//	  - `internal_id` — the DB BIGSERIAL surrogate (emails.internal_id),
//	    assigned by Postgres on the SVC-02 INSERT. With `fetched_at` it is
//	    the partitioned `emails` composite PK, and it is what SVC-04 writes
//	    to `rule_hits.entity_id` (ARCH-SPEC §14 step 3b).
//
//	Both ids are carried on analysis.headers, scores.header, and
//	emails.scored so consumers reconstruct the `(internal_id, fetched_at)`
//	PK without a DB lookup. scores.header forwards `internal_id` because the
//	aggregator (SVC-07) that builds emails.scored has no DB access (§4) and
//	header is the always-present component.
//	SVC-02 (P1.1) populates `internal_id` from the INSERT RETURNING;
//	until then it is zero and consumers fall back to `email_id` (the interim
//	int64 email_id == internal_id equivalence). There is NO permanent
//	`email_id == internal_id` invariant.
package kafka

import (
	"encoding/json"
	"fmt"
	"time"
)

// AnalysisHeadersMessage matches the `analysis.headers` topic payload.
//
// All fields are optional from the consumer side — SVC-02 may legitimately
// omit fields it could not parse from the raw RFC822 headers. SVC-04 must
// treat zero-values as "missing", not as failed authentication.
type AnalysisHeadersMessage struct {
	// EmailID is the logical email identifier (ARCH-SPEC §1 / §16 D11):
	// assigned by SVC-01, the Kafka partition key, opaque. UUIDv7 string by
	// contract, carried as an int64 on an interim basis (swap tracked by
	// #142). Distinct from InternalID — do not depend on its numeric shape.
	EmailID int64 `json:"email_id"`
	// InternalID is the DB BIGSERIAL surrogate (emails.internal_id). With
	// FetchedAt it forms the partitioned emails composite PK; SVC-04 writes it
	// to rule_hits.entity_id (ARCH-SPEC §14 step 3b). Populated by SVC-02
	// (P1.1) from the INSERT RETURNING; zero until then, when consumers fall
	// back to EmailID (interim int64 email_id == internal_id equivalence).
	InternalID int64 `json:"internal_id,omitempty"`
	// FetchedAt is emails.fetched_at, the partition key on the partitioned
	// emails table and the companion for rule_hits.email_fetched_at.
	// Populated by SVC-02 alongside the ids per ARCH-SPEC §1 step 4.
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

	// ── Body content (D9 structural-anomaly signals) ────────────────────
	// BodyHTML is the raw HTML body part (empty when the message had no HTML
	// part); BodyPlain is the HTML-stripped / sanitized plain text. SVC-04
	// derives the structural signals it owns (html_only / has_hidden_text /
	// has_form / encoding anomalies) from these — per D9 the parser ships the
	// body and SVC-04 computes the structural dimension. (Moved here from the
	// retired map-based AnalysisHeaders so the body reaches the type SVC-04
	// actually consumes.)
	BodyHTML  string `json:"body_html,omitempty"`
	BodyPlain string `json:"body_plain,omitempty"`
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
	// InternalID is the DB BIGSERIAL surrogate (emails.internal_id), forwarded
	// by SVC-04 from analysis.headers so SVC-07 — which has no DB access (§4) —
	// can place it on emails.scored without a lookup. Header is the always-
	// present component (emails.scored.header_score is non-nullable), so this is
	// the reliable carrier for the surrogate id. With FetchedAt it forms the
	// partitioned emails composite PK that SVC-08 writes against. Zero until
	// SVC-02 populates internal_id from the INSERT RETURNING (P1.1); consumers
	// fall back to EmailID (interim int64 email_id == internal_id equivalence).
	InternalID int64 `json:"internal_id,omitempty"`
	OrgID      int64 `json:"org_id"`
	// FetchedAt is emails.fetched_at; with InternalID it is the composite PK
	// SVC-08 needs for partitioned emails updates, propagated SVC-04 → SVC-07 →
	// emails.scored. No omitempty: it is a no-op on time.Time (a zero time still
	// marshals), so the tag would only mislead — the field is always emitted.
	FetchedAt time.Time `json:"fetched_at"`

	Component string `json:"component"` // always "header"
	Score     int    `json:"score"`     // [0, 100]

	AuthSubScore       int `json:"auth_sub_score"`
	ReputationSubScore int `json:"reputation_sub_score"`
	StructuralSubScore int `json:"structural_sub_score"`

	FiredRules []FiredRule   `json:"fired_rules"`
	Signals    HeaderSignals `json:"signals"`

	ProcessingTimeMs int `json:"processing_time_ms"`
}

// Validate enforces the documented [0, 100] range on the composite Score and
// rejects a message carrying neither id. The auth/reputation/structural sub-
// scores are dimension contributions, not the spec's [0, 100] score, so they
// are left unbounded. EmailID and InternalID are the two-id pair (ARCH-SPEC §1
// / §16 D11): consumers fall back to EmailID until SVC-02 populates InternalID,
// so a message with both zero addresses nothing and is rejected.
func (m ScoresHeaderMessage) Validate() error {
	if m.EmailID == 0 && m.InternalID == 0 {
		return fmt.Errorf("scores: message has neither email_id nor internal_id")
	}
	return validateScore("header", m.Score)
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
