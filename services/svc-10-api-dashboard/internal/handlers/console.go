// Package handlers implements the svc-10 read-mostly analyst-console HTTP API
// (MVP-7): JWT login, a persisted read API over the email/verdict/rule tables,
// the 5 materialized-view stats dashboards, a read-only rules list, and a
// scan-submission proxy to svc-01. Every read against an RLS-forced table runs
// inside a tenant-scoped transaction (WithOrgTx) keyed by the authenticated JWT
// claim OrgID (G10). The control-plane login read is NOT RLS-forced and uses an
// explicit org filter.
package handlers

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by the reader when an entity does not exist or is
// hidden by the tenant boundary. Handlers map it to a 404.
var ErrNotFound = errors.New("not found")

// ErrInvalidCredentials is the single opaque login failure. The login handler
// returns the same 401 for an unknown user, a wrong password, and a NULL stored
// hash so a caller cannot probe which field was wrong.
var ErrInvalidCredentials = errors.New("invalid credentials")

// AuthUser is the authenticated identity returned by Login and /me.
type AuthUser struct {
	ID          int64  `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	OrgID       int64  `json:"org_id"`
}

// EmailListItem is one row of the paginated email list.
type EmailListItem struct {
	EmailID      string     `json:"email_id"` // logical UUIDv7 ("" when unresolvable)
	InternalID   int64      `json:"internal_id"`
	MessageID    string     `json:"message_id,omitempty"`
	SenderEmail  string     `json:"sender_email,omitempty"`
	SenderName   string     `json:"sender_name,omitempty"`
	SenderDomain string     `json:"sender_domain,omitempty"`
	Subject      string     `json:"subject,omitempty"`
	RiskScore    *int32     `json:"risk_score,omitempty"`
	VerdictLabel string     `json:"verdict_label,omitempty"`
	SentAt       *time.Time `json:"sent_at,omitempty"`
	FetchedAt    *time.Time `json:"fetched_at,omitempty"`
}

// Verdict is one verdict-history row.
type Verdict struct {
	ID           int64      `json:"id"`
	Label        string     `json:"label"`
	Confidence   *float64   `json:"confidence,omitempty"`
	Source       string     `json:"source"`
	ModelVersion string     `json:"model_version,omitempty"`
	Notes        string     `json:"notes,omitempty"`
	CreatedBy    *int64     `json:"created_by,omitempty"`
	CreatedAt    *time.Time `json:"created_at,omitempty"`
}

// RuleHit is one rule-firing row with the joined (possibly archived) rule
// metadata for score explainability.
type RuleHit struct {
	ID              int64      `json:"id"`
	RuleID          *int64     `json:"rule_id,omitempty"`
	RuleName        string     `json:"rule_name,omitempty"`
	RuleDescription string     `json:"rule_description,omitempty"`
	RuleTarget      string     `json:"rule_target,omitempty"`
	RuleVersion     string     `json:"rule_version"`
	ScoreImpact     int32      `json:"score_impact"`
	MatchDetail     any        `json:"match_detail,omitempty"`
	FiredAt         *time.Time `json:"fired_at,omitempty"`
}

// EnrichedThreat is the TI / enrichment record an email URL points to. Only the
// fields the console renders are surfaced.
type EnrichedThreat struct {
	ID         int64  `json:"id"`
	URL        string `json:"url"`
	Domain     string `json:"domain,omitempty"`
	Online     *bool  `json:"online,omitempty"`
	IPAddress  string `json:"ip_address,omitempty"`
	ASN        *int32 `json:"asn,omitempty"`
	ASNName    string `json:"asn_name,omitempty"`
	Country    string `json:"country,omitempty"`
	ThreatType string `json:"threat_type,omitempty"`
	Registrar  string `json:"registrar,omitempty"`
	RiskScore  *int32 `json:"risk_score,omitempty"`
	IsGlobal   bool   `json:"is_global"`
}

// EmailURL is one extracted URL with its TI matches and resolved threat.
type EmailURL struct {
	ID          int64           `json:"id"`
	VisibleText string          `json:"visible_text,omitempty"`
	ThreatID    *int64          `json:"threat_id,omitempty"`
	TIMatches   []TIMatch       `json:"ti_matches"`
	Threat      *EnrichedThreat `json:"threat,omitempty"`
}

// TIMatch is one TI-indicator match against an email URL.
type TIMatch struct {
	ID            int64      `json:"id"`
	TIIndicatorID int64      `json:"ti_indicator_id"`
	MatchType     string     `json:"match_type"`
	MatchedAt     *time.Time `json:"matched_at,omitempty"`
}

// Attachment is one email attachment link.
type Attachment struct {
	AttachmentID int64  `json:"attachment_id"`
	Filename     string `json:"filename,omitempty"`
	ContentType  string `json:"content_type,omitempty"`
	Disposition  string `json:"disposition,omitempty"`
	RiskScore    *int32 `json:"risk_score,omitempty"`
}

// Recipient is one to/cc/bcc recipient.
type Recipient struct {
	ID            int64  `json:"id"`
	Address       string `json:"address"`
	DisplayName   string `json:"display_name,omitempty"`
	RecipientType string `json:"recipient_type"`
}

// EmailDetail is the composite per-email detail view.
type EmailDetail struct {
	EmailID        string       `json:"email_id"`
	InternalID     int64        `json:"internal_id"`
	MessageID      string       `json:"message_id,omitempty"`
	SenderName     string       `json:"sender_name,omitempty"`
	SenderEmail    string       `json:"sender_email,omitempty"`
	SenderDomain   string       `json:"sender_domain,omitempty"`
	ReplyToEmail   string       `json:"reply_to_email,omitempty"`
	ReturnPath     string       `json:"return_path,omitempty"`
	Subject        string       `json:"subject,omitempty"`
	AuthSPF        string       `json:"auth_spf,omitempty"`
	AuthDKIM       string       `json:"auth_dkim,omitempty"`
	AuthDMARC      string       `json:"auth_dmarc,omitempty"`
	BodyPlain      string       `json:"body_plain,omitempty"`
	BodyHTML       string       `json:"body_html,omitempty"`
	RiskScore      *int32       `json:"risk_score,omitempty"`
	HeaderRisk     *int32       `json:"header_risk_score,omitempty"`
	ContentRisk    *int32       `json:"content_risk_score,omitempty"`
	URLRisk        *int32       `json:"url_risk_score,omitempty"`
	AttachmentRisk *int32       `json:"attachment_risk_score,omitempty"`
	SentAt         *time.Time   `json:"sent_at,omitempty"`
	FetchedAt      *time.Time   `json:"fetched_at,omitempty"`
	CurrentVerdict *Verdict     `json:"current_verdict,omitempty"`
	VerdictHistory []Verdict    `json:"verdict_history"`
	RuleHits       []RuleHit    `json:"rule_hits"`
	URLs           []EmailURL   `json:"urls"`
	Attachments    []Attachment `json:"attachments"`
	Recipients     []Recipient  `json:"recipients"`
}

// Page wraps a list result with its pagination echo.
type Page[T any] struct {
	Items  []T `json:"items"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
	Count  int `json:"count"`
}

// ConsoleReader is the narrow read-port the handlers depend on. The DB-backed
// implementation lives in store.go; tests inject a fake. Every org-scoped method
// takes orgID (the authenticated JWT claim) and runs under WithOrgTx internally.
type ConsoleReader interface {
	// Login resolves (org, email), bcrypt-compares password, and returns the
	// authenticated user. Returns ErrInvalidCredentials on any failure.
	Login(ctx context.Context, orgID int64, email, password string) (AuthUser, error)
	// ListEmails returns a page of the org's emails, newest first.
	ListEmails(ctx context.Context, orgID int64, limit, offset int) ([]EmailListItem, error)
	// GetEmailDetail returns the composite detail for one email by its logical
	// UUIDv7 email_id. Returns ErrNotFound when unresolvable / hidden by RLS.
	GetEmailDetail(ctx context.Context, orgID int64, emailID string) (EmailDetail, error)
	// ListRules returns the org's read-only rules (+ globals).
	ListRules(ctx context.Context, orgID int64) ([]RuleSummary, error)
	// Stats reads (the 5 MVs).
	ThreatSummary(ctx context.Context, orgID int64) ([]ThreatStat, error)
	CampaignSummary(ctx context.Context, orgID int64) ([]CampaignStat, error)
	FeedHealth(ctx context.Context, orgID int64) ([]FeedStat, error)
	RulePerformance(ctx context.Context, orgID int64) ([]RuleStat, error)
	OrgIngestionSummary(ctx context.Context, orgID int64) (IngestionStat, error)
}

// RuleSummary is one read-only rule.
type RuleSummary struct {
	ID          int64      `json:"id"`
	OrgID       *int64     `json:"org_id,omitempty"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Version     string     `json:"version"`
	Status      string     `json:"status"`
	Target      string     `json:"target"`
	ScoreImpact int32      `json:"score_impact"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
}

// ThreatStat is one mv_threat_summary row.
type ThreatStat struct {
	ThreatType   string     `json:"threat_type"`
	Country      string     `json:"country"`
	ASN          int32      `json:"asn"`
	ASNName      string     `json:"asn_name"`
	IsGlobal     bool       `json:"is_global"`
	OrgID        int64      `json:"org_id"`
	Total        int64      `json:"total"`
	OnlineCount  int64      `json:"online_count"`
	OfflineCount int64      `json:"offline_count"`
	AvgRiskScore float64    `json:"avg_risk_score"`
	MaxRiskScore *float64   `json:"max_risk_score,omitempty"`
	EarliestSeen *time.Time `json:"earliest_seen,omitempty"`
	LatestSeen   *time.Time `json:"latest_seen,omitempty"`
}

// CampaignStat is one mv_campaign_summary row.
type CampaignStat struct {
	CampaignID        int64      `json:"campaign_id"`
	OrgID             *int64     `json:"org_id,omitempty"`
	Name              string     `json:"name"`
	Fingerprint       string     `json:"fingerprint"`
	ThreatType        string     `json:"threat_type,omitempty"`
	TargetBrand       string     `json:"target_brand,omitempty"`
	RiskScore         *int32     `json:"risk_score,omitempty"`
	FirstSeen         *time.Time `json:"first_seen,omitempty"`
	LastSeen          *time.Time `json:"last_seen,omitempty"`
	EmailCount        int64      `json:"email_count"`
	AvgEmailRiskScore float64    `json:"avg_email_risk_score"`
	VerdictPhishing   int64      `json:"verdict_phishing"`
	VerdictMalware    int64      `json:"verdict_malware"`
	VerdictSuspicious int64      `json:"verdict_suspicious"`
	VerdictBenign     int64      `json:"verdict_benign"`
	VerdictSpam       int64      `json:"verdict_spam"`
	VerdictUnknown    int64      `json:"verdict_unknown"`
}

// FeedStat is one mv_feed_health row.
type FeedStat struct {
	FeedID                  int64      `json:"feed_id"`
	Name                    string     `json:"name"`
	DisplayName             string     `json:"display_name,omitempty"`
	FeedType                string     `json:"feed_type"`
	ReliabilityWeight       float64    `json:"reliability_weight"`
	Enabled                 *bool      `json:"enabled,omitempty"`
	LastFetchedAt           *time.Time `json:"last_fetched_at,omitempty"`
	SecondsSinceFetch       *float64   `json:"seconds_since_fetch,omitempty"`
	TotalThreatsContributed int64      `json:"total_threats_contributed"`
	ActiveThreats           int64      `json:"active_threats"`
	AvgThreatRiskScore      float64    `json:"avg_threat_risk_score"`
}

// RuleStat is one mv_rule_performance row.
type RuleStat struct {
	RuleID                int64      `json:"rule_id"`
	OrgID                 *int64     `json:"org_id,omitempty"`
	Name                  string     `json:"name"`
	Version               string     `json:"version"`
	Status                string     `json:"status"`
	Target                string     `json:"target"`
	ScoreImpact           int32      `json:"score_impact"`
	TotalHits             int64      `json:"total_hits"`
	HitsLast24h           int64      `json:"hits_last_24h"`
	HitsLast7d            int64      `json:"hits_last_7d"`
	TotalScoreContributed int64      `json:"total_score_contributed"`
	LastFiredAt           *time.Time `json:"last_fired_at,omitempty"`
}

// IngestionStat is the single mv_org_ingestion_summary row.
type IngestionStat struct {
	OrgID             *int64  `json:"org_id,omitempty"`
	TotalEmails       int64   `json:"total_emails"`
	EmailsLast24h     int64   `json:"emails_last_24h"`
	EmailsLast7d      int64   `json:"emails_last_7d"`
	EmailsLast30d     int64   `json:"emails_last_30d"`
	AvgRiskScore      float64 `json:"avg_risk_score"`
	MaxRiskScore      *int32  `json:"max_risk_score,omitempty"`
	HighRiskCount     int64   `json:"high_risk_count"`
	MediumRiskCount   int64   `json:"medium_risk_count"`
	LowRiskCount      int64   `json:"low_risk_count"`
	ConfirmedPhishing int64   `json:"confirmed_phishing"`
	ConfirmedMalware  int64   `json:"confirmed_malware"`
	ConfirmedSpam     int64   `json:"confirmed_spam"`
	ConfirmedBenign   int64   `json:"confirmed_benign"`
	Unclassified      int64   `json:"unclassified"`
}
