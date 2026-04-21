package models

import (
	"encoding/json"
	"time"
)

// URLAnalysisRequest is the payload consumed by the URL analysis service.
type URLAnalysisRequest struct {
	EmailID string      `json:"email_id"`
	OrgID   int64       `json:"org_id"`
	URLs    []URLTarget `json:"urls"`
}

// URLTarget is a single URL candidate extracted from an email.
type URLTarget struct {
	URL         string `json:"url"`
	VisibleText string `json:"visible_text,omitempty"`
	Position    string `json:"position,omitempty"` // body | header
	HTMLContext string `json:"html_context,omitempty"`
}

// URLAnalysisResponse is the service-level output published as scores.url.
type URLAnalysisResponse struct {
	EmailID          string            `json:"email_id"`
	OrgID            int64             `json:"org_id"`
	Component        string            `json:"component"` // "url"
	Score            int               `json:"score"`     // 0..100
	URLCount         int               `json:"url_count"`
	TIBlockedCount   int               `json:"ti_blocked_count"`
	MLScoredCount    int               `json:"ml_scored_count"`
	CacheHitCount    int               `json:"cache_hit_count"`
	RiskiestURL      string            `json:"riskiest_url,omitempty"`
	URLDetails       []URLScoreDetail  `json:"url_details,omitempty"`
	ProcessingTimeMS int64             `json:"processing_time_ms"`
	Metadata         json.RawMessage   `json:"metadata,omitempty"`
	GeneratedAt      time.Time         `json:"generated_at"`
	PartialAnalysis  bool              `json:"partial_analysis,omitempty"`
	MissingSignals   []string          `json:"missing_signals,omitempty"`
}

// URLScoreDetail is the per-URL scoring and explainability record.
type URLScoreDetail struct {
	URL                 string `json:"url"`
	Domain              string `json:"domain,omitempty"`
	TIMatched           bool   `json:"ti_matched"`
	TISource            string `json:"ti_source,omitempty"`
	DomainAgeDays       *int   `json:"domain_age_days,omitempty"`
	HasSSL              bool   `json:"has_ssl"`
	SSLIssuer           string `json:"ssl_issuer,omitempty"`
	RedirectCount       int    `json:"redirect_count,omitempty"`
	MLScore             *int   `json:"ml_score,omitempty"` // 0..100
	FinalScore          int    `json:"final_score"`        // 0..100
	IsShortened         bool   `json:"is_shortened,omitempty"`
	EnrichmentAvailable bool   `json:"enrichment_available"`
	CacheHit            bool   `json:"cache_hit,omitempty"`
	Reason              string `json:"reason,omitempty"` // cache | ti_blocklist | ml | fallback
}

// URLInferenceRequest is the minimal request passed to the local ML inference pipeline.
type URLInferenceRequest struct {
	URL string `json:"url"`
}

// URLInferenceResult is the raw ML model output before service-level thresholding.
type URLInferenceResult struct {
	URL                string    `json:"url"`
	Prediction         string    `json:"prediction"` // PHISHING | LEGITIMATE
	PhishProbability   float64   `json:"phish_probability"`
	RiskLevel          string    `json:"risk_level"` // SAFE | UNCERTAIN | SUSPICIOUS | DANGEROUS
	Score              int       `json:"score"`      // probability * 100
	ModelName          string    `json:"model_name,omitempty"`
	ModelVersion       string    `json:"model_version,omitempty"`
	InferenceLatencyUS int64     `json:"inference_latency_us,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
}

// EnrichmentData is the in-memory aggregate of all enrichment signals
// collected for a URL during the pipeline run. Assembled by the enrichment
// service, then written into enriched_threats + enrichment_results.
type EnrichmentData struct {
	URL string `json:"url" validate:"required,url"`

	// Network / geo
	IPAddress   string  `json:"ip_address,omitempty"`
	ASN         int     `json:"asn,omitempty"`
	ASNName     string  `json:"asn_name,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	Country     string  `json:"country,omitempty"`
	CountryName string  `json:"country_name,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`

	// TLS
	SSLEnabled    bool      `json:"ssl_enabled"`
	CertIssuer    string    `json:"cert_issuer,omitempty"`
	CertSubject   string    `json:"cert_subject,omitempty"`
	CertValidFrom time.Time `json:"cert_valid_from,omitempty"`
	CertValidTo   time.Time `json:"cert_valid_to,omitempty"`
	CertSerial    string    `json:"cert_serial,omitempty"`

	// WHOIS
	// CreationDate is a date-only value (no time component). The DB column is DATE.
	// When mapping to db.EnrichedThreat, truncate to date: pgtype.Date{Time: t.Truncate(24*time.Hour), Valid: true}
	CreationDate time.Time `json:"creation_date,omitempty"`
	// ExpiryDate is a date-only value. See CreationDate.
	ExpiryDate time.Time `json:"expiry_date,omitempty"`
	// UpdatedDate is a date-only value. See CreationDate.
	UpdatedDate time.Time `json:"updated_date,omitempty"`
	Registrar   string    `json:"registrar,omitempty"`
	NameServers []string  `json:"name_servers,omitempty"`

	// Availability
	Online         bool `json:"online"`
	HTTPStatusCode int  `json:"http_status_code,omitempty"`

	// Page content
	PageTitle    string `json:"page_title,omitempty"`
	PageLanguage string `json:"page_language,omitempty"`

	// Raw provider responses keyed by provider name, e.g. "virustotal", "ipinfo"
	ProviderResults map[string]json.RawMessage `json:"provider_results,omitempty"`
}
