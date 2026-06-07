package kafka

// Component discriminator values shared by every scores.* payload.
const (
	ComponentURL        = "url"
	ComponentHeader     = "header"
	ComponentAttachment = "attachment"
	ComponentNLP        = "nlp"
)

// ScoreEnvelope is the legacy generic scores.* shape: a float score plus an
// untyped Details map.
//
// Deprecated: G13 replaces this with the typed ScoresURL / ScoresAttachment /
// ScoresNLP payloads below (and the already-spec-faithful ScoresHeaderMessage
// in header.go). It is retained only so the not-yet-migrated stub producers
// (svckit, svc-03, svc-06) and the aggregator decoder keep compiling; those
// consumers move to the typed payloads in their own batches. New code MUST
// use the typed structs.
type ScoreEnvelope struct {
	Meta      MessageMeta            `json:"meta"`
	Component string                 `json:"component"` // "url" | "header" | "attachment" | "nlp"
	Score     float64                `json:"score"`     // 0..100
	Details   map[string]interface{} `json:"details,omitempty"`
}

// ── scores.url (svc-03) ──────────────────────────────────────────────────

// URLDetail is one per-URL scoring record on scores.url (ARCH-SPEC §1 step 3a).
type URLDetail struct {
	URL                 string  `json:"url"`
	Domain              string  `json:"domain,omitempty"`
	TIMatched           bool    `json:"ti_matched"`
	TISource            *string `json:"ti_source"`
	DomainAgeDays       *int    `json:"domain_age_days"`
	HasSSL              bool    `json:"has_ssl"`
	SSLIssuer           *string `json:"ssl_issuer"`
	RedirectCount       int     `json:"redirect_count"`
	MLScore             *int    `json:"ml_score"`
	IsShortened         bool    `json:"is_shortened"`
	EnrichmentAvailable bool    `json:"enrichment_available"`
	// GuardHit is set when the domain guard short-circuits: "allowlisted",
	// "typosquat:<brand>", or "brand-in-subdomain:<brand>" (PR #140).
	GuardHit *string `json:"guard_hit"`
	// MLDeployP / MLVerdict / MLCacheHit populated only when the L2 fusion
	// sidecar runs (PR #140).
	MLDeployP  *float64 `json:"ml_deploy_p"`
	MLVerdict  *string  `json:"ml_verdict"` // "phishing" | "benign" | null
	MLCacheHit bool     `json:"ml_cache_hit"`
}

// ScoresURL matches the scores.url topic payload (ARCH-SPEC §1 step 3a).
type ScoresURL struct {
	Meta      MessageMeta `json:"meta"`
	Component string      `json:"component"` // always "url"
	Score     int         `json:"score"`     // [0, 100]

	URLCount       int    `json:"url_count"`
	TIBlockedCount int    `json:"ti_blocked_count"`
	MLScoredCount  int    `json:"ml_scored_count"`
	CacheHitCount  int    `json:"cache_hit_count"`
	RiskiestURL    string `json:"riskiest_url,omitempty"`

	URLDetails       []URLDetail `json:"url_details,omitempty"`
	ProcessingTimeMs int         `json:"processing_time_ms"`
}

// ── scores.attachment (svc-05) ───────────────────────────────────────────

// AttachmentDetail is one per-attachment scoring record on scores.attachment
// (ARCH-SPEC §1 step 3c).
type AttachmentDetail struct {
	SHA256               string  `json:"sha256"`
	Filename             string  `json:"filename,omitempty"`
	ContentType          string  `json:"content_type,omitempty"`
	SizeBytes            int64   `json:"size_bytes,omitempty"`
	Entropy              float64 `json:"entropy"`
	IsMalicious          bool    `json:"is_malicious"`
	TISource             *string `json:"ti_source"`
	ExtensionMismatch    bool    `json:"extension_mismatch"`
	HasMacros            bool    `json:"has_macros"`
	IsDangerousExtension bool    `json:"is_dangerous_extension"`
	IndividualScore      int     `json:"individual_score"`
}

// ScoresAttachment matches the scores.attachment topic payload
// (ARCH-SPEC §1 step 3c).
type ScoresAttachment struct {
	Meta      MessageMeta `json:"meta"`
	Component string      `json:"component"` // always "attachment"
	Score     int         `json:"score"`     // [0, 100]

	AttachmentCount int `json:"attachment_count"`
	MaliciousCount  int `json:"malicious_count"`

	AttachmentDetails []AttachmentDetail `json:"attachment_details,omitempty"`
	ProcessingTimeMs  int                `json:"processing_time_ms"`
}

// ── scores.nlp (svc-06) ──────────────────────────────────────────────────

// NLPFacets is the structured facet output on scores.nlp (ARCH-SPEC §1 step
// 3d). Every facet score is preserved alongside the composite score for
// explainability. The facets are heuristic (G4 overrides D7 — no NER, no
// zero-shot, no retraining of the base DistilBERT model).
type NLPFacets struct {
	UrgencyScore float64 `json:"urgency_score"`
	// IntentLabel is one of credential_harvesting | malware_delivery | bec |
	// scam | legitimate.
	IntentLabel        string  `json:"intent_label"`
	IntentConfidence   float64 `json:"intent_confidence"`
	ImpersonationScore float64 `json:"impersonation_score"`
	ImpersonatedBrand  *string `json:"impersonated_brand"`
	DeceptionScore     float64 `json:"deception_score"`
}

// NLPModelVersions records the version string of each facet model/heuristic
// so downstream consumers can reason about score provenance.
type NLPModelVersions struct {
	Urgency       string `json:"urgency"`
	Intent        string `json:"intent"`
	Impersonation string `json:"impersonation"`
	Deception     string `json:"deception"`
}

// ScoresNLP matches the scores.nlp topic payload (ARCH-SPEC §1 step 3d).
type ScoresNLP struct {
	Meta      MessageMeta `json:"meta"`
	Component string      `json:"component"` // always "nlp"
	Score     int         `json:"score"`     // [0, 100]

	Facets        NLPFacets        `json:"facets"`
	ModelVersions NLPModelVersions `json:"model_versions"`

	ProcessingTimeMs int `json:"processing_time_ms"`
}
