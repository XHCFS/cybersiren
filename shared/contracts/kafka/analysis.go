package kafka

// ExtractedURL is one URL pulled out of an email body or header by svc-02,
// carrying the surrounding context svc-03 uses for scoring and explainability
// (ARCH-SPEC §1 step 2, analysis.urls schema).
type ExtractedURL struct {
	URL string `json:"url"`
	// VisibleText is the anchor/visible text the URL was rendered as (empty
	// for plain-text or non-anchored occurrences).
	VisibleText string `json:"visible_text,omitempty"`
	// Position is where the URL was found: "body" | "header".
	Position string `json:"position,omitempty"`
	// HTMLContext is the markup attribute the URL came from:
	// "href" | "src" | "action" | "plain_text".
	HTMLContext string `json:"html_context,omitempty"`
}

// AnalysisURLs is published by svc-02-parser to analysis.urls — the list of
// URLs extracted from the email body for downstream URL scoring. Each entry
// carries {visible_text, position, html_context} per ARCH-SPEC §1 step 2.
type AnalysisURLs struct {
	Meta MessageMeta    `json:"meta"`
	URLs []ExtractedURL `json:"urls"`
	// InternalID is the DB BIGSERIAL surrogate svc-02 assigns when it persists
	// the email; svc-03 uses it to look up email_urls. Zero until svc-02
	// populates it. Distinct from Meta.EmailID — the logical identifier — per
	// the two-id model (see MessageMeta.EmailID).
	InternalID int64 `json:"internal_id,omitempty"`
}

// NOTE: the analysis.headers payload is AnalysisHeadersMessage in header.go
// (svc-04's authoritative contract). The earlier map-based AnalysisHeaders
// type was retired — its D9 body-content fields (body_html / body_plain) now
// live on AnalysisHeadersMessage, the type svc-04 actually consumes.

// Attachment represents one attachment slot in analysis.attachments
// (ARCH-SPEC §1 step 2, analysis.attachments schema). svc-05 scores from
// these fields, so all ten spec fields are carried (G13 added the six that
// were previously dropped: md5, sha1, content_id, disposition, entropy,
// detected_type).
type Attachment struct {
	SHA256      string `json:"sha256,omitempty"`
	MD5         string `json:"md5,omitempty"`
	SHA1        string `json:"sha1,omitempty"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type,omitempty"`
	ContentID   string `json:"content_id,omitempty"`
	// Disposition is "inline" | "attachment".
	Disposition string `json:"disposition,omitempty"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
	// Entropy is the Shannon entropy of the attachment bytes (0..8).
	Entropy float64 `json:"entropy,omitempty"`
	// DetectedType is the magic-byte-derived content type (may differ from
	// ContentType, which is the MIME-declared type; svc-05 flags mismatches).
	DetectedType string `json:"detected_type,omitempty"`
}

// AnalysisAttachments is published by svc-02-parser to analysis.attachments.
type AnalysisAttachments struct {
	Meta        MessageMeta  `json:"meta"`
	Attachments []Attachment `json:"attachments"`
	// InternalID is the DB BIGSERIAL surrogate svc-02 assigns when it persists
	// the email; svc-05 uses it to key the email_attachments risk_score
	// write-back. Zero until svc-02 populates it. Distinct from Meta.EmailID —
	// the logical identifier — per the two-id model (see MessageMeta.EmailID and
	// AnalysisURLs.InternalID).
	InternalID int64 `json:"internal_id,omitempty"`
}

// AnalysisText is published by svc-02-parser to analysis.text — the cleaned
// subject + body sent to the NLP classifier (ARCH-SPEC §1 step 2,
// analysis.text schema).
type AnalysisText struct {
	Meta    MessageMeta `json:"meta"`
	Subject string      `json:"subject"`
	// SenderName / SenderDomain are carried so svc-06's heuristic brand
	// impersonation facet can compare claimed brand against sender identity
	// without re-parsing headers.
	SenderName   string `json:"sender_name,omitempty"`
	SenderDomain string `json:"sender_domain,omitempty"`
	// Body is the HTML-stripped clean plain text (spec field: plain_text).
	Body string `json:"body"`
	// BodyLanguage is the detected body language (e.g. "en"); empty when
	// undetected.
	BodyLanguage string `json:"body_language,omitempty"`
	// WordCount is the token/word count of the cleaned body.
	WordCount int `json:"word_count,omitempty"`
}

// AnalysisPlan is published by svc-02-parser to analysis.plans — the list of
// score topics that the aggregator (svc-07) should expect for this email,
// plus content counts the aggregator/decision engine use for completeness
// checks (ARCH-SPEC §1 step 2, analysis.plans schema).
type AnalysisPlan struct {
	Meta MessageMeta `json:"meta"`
	// ExpectedScores carries the fully-qualified scores.* TOPIC NAMES
	// (e.g. "scores.url"), matching what svc-07's packager compares against.
	// The ARCH-SPEC writes these as bare components (["url",...]); the repo
	// uses topic names on BOTH the svc-02 emit and the svc-07 match, so the
	// two ends agree. Do not switch to bare components without changing both
	// ends together (G13).
	ExpectedScores []string `json:"expected_scores"`

	// URLCount / AttachmentCount / HasBody mirror the email contents svc-02
	// derived the plan from; CreatedAt is the plan-emission time used for
	// aggregation-latency bookkeeping.
	URLCount        int   `json:"url_count,omitempty"`
	AttachmentCount int   `json:"attachment_count,omitempty"`
	HasBody         bool  `json:"has_body,omitempty"`
	CreatedAt       int64 `json:"created_at,omitempty"` // Unix epoch (ms) of plan emission
}
