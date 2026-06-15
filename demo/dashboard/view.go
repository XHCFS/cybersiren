package main

import (
	"encoding/json"
	"strings"
	"time"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// scanView is the full per-module breakdown the UI renders for one email. It is
// assembled from the cached emails.scored (rich component_details) + the final
// emails.verdict. Every section is nullable so the page can show progress as the
// pipeline fills it in.
type scanView struct {
	EmailID     string       `json:"email_id"`
	Status      string       `json:"status"` // pending | scoring | scored
	Source      string       `json:"source,omitempty"`
	Subject     string       `json:"subject,omitempty"`
	From        string       `json:"from,omitempty"`
	SubmittedAt *time.Time   `json:"submitted_at,omitempty"`
	Verdict     *verdictView `json:"verdict,omitempty"`
	Modules     modulesView  `json:"modules"`
	Aggregation *aggView     `json:"aggregation,omitempty"`
}

type verdictView struct {
	Label        string                       `json:"label"`
	RiskScore    int                          `json:"risk_score"`
	Confidence   float64                      `json:"confidence"`
	Source       string                       `json:"source,omitempty"`
	ModelVersion string                       `json:"model_version,omitempty"`
	Campaign     bool                         `json:"new_campaign,omitempty"`
	FiredRules   []contracts.VerdictFiredRule `json:"fired_rules,omitempty"`
}

type modulesView struct {
	URL        *urlView    `json:"url"`
	Header     *headerView `json:"header"`
	NLP        *nlpView    `json:"nlp"`
	Attachment *attachView `json:"attachment"`
}

type urlView struct {
	Score     *int       `json:"score"`
	URLCount  int        `json:"url_count"`
	TIBlocked int        `json:"ti_blocked"`
	MLScored  int        `json:"ml_scored"`
	Riskiest  string     `json:"riskiest_url,omitempty"`
	Links     []linkView `json:"links,omitempty"`
}

// linkView surfaces the per-URL risk plus the L1 (TI/heuristic) and L2 (ML fusion)
// signals. Score/Label are the URL's overall outcome; the ML* fields are L2-only
// and stay nil when the fusion sidecar did not score this URL.
type linkView struct {
	URL           string   `json:"url"`
	Domain        string   `json:"domain,omitempty"`
	Score         *int     `json:"score,omitempty"`     // per-URL overall risk [0,100]
	Label         string   `json:"label,omitempty"`     // phishing | legitimate | ...
	TIMatched     bool     `json:"ti_matched"`          // L1
	TISource      *string  `json:"ti_source,omitempty"` // L1 (threat type / feed)
	GuardHit      *string  `json:"guard_hit,omitempty"` // L1 (typosquat / brand guard)
	DomainAgeDays *int     `json:"domain_age_days,omitempty"`
	IsShortened   bool     `json:"is_shortened"`
	MLVerdict     *string  `json:"ml_verdict,omitempty"`  // L2 (only if fusion ran)
	MLDeployP     *float64 `json:"ml_deploy_p,omitempty"` // L2
	MLScore       *int     `json:"ml_score,omitempty"`    // L2 (typed contract only)
}

type headerView struct {
	Score        *int                  `json:"score"`
	Auth         int                   `json:"auth_sub_score"`
	Reputation   int                   `json:"reputation_sub_score"`
	Structural   int                   `json:"structural_sub_score"`
	SenderDomain string                `json:"sender_domain,omitempty"`
	SPF          string                `json:"spf,omitempty"`
	DKIM         string                `json:"dkim,omitempty"`
	DMARC        string                `json:"dmarc,omitempty"`
	DomainAge    *int                  `json:"domain_age_days,omitempty"`
	Typosquat    *string               `json:"typosquat_target,omitempty"`
	FreeProvider bool                  `json:"free_provider"`
	HopCount     int                   `json:"hop_count"`
	FiredRules   []contracts.FiredRule `json:"fired_rules,omitempty"`
}

type nlpView struct {
	Score             *int    `json:"score"`
	Classification    string  `json:"classification,omitempty"`
	Intent            string  `json:"intent,omitempty"`
	IntentConfidence  float64 `json:"intent_confidence"`
	Urgency           float64 `json:"urgency"`
	Obfuscation       bool    `json:"obfuscation"`
	HasFacets         bool    `json:"has_facets"` // typed impersonation/deception available
	Impersonation     float64 `json:"impersonation"`
	ImpersonatedBrand *string `json:"impersonated_brand,omitempty"`
	Deception         float64 `json:"deception"`
}

type attachView struct {
	Score     *int       `json:"score"`
	Count     int        `json:"count"`
	Malicious int        `json:"malicious"`
	Files     []fileView `json:"files,omitempty"`
}

type fileView struct {
	Filename        string `json:"filename,omitempty"`
	ContentType     string `json:"content_type,omitempty"`
	SizeBytes       int64  `json:"size_bytes,omitempty"`
	IsMalicious     bool   `json:"is_malicious"`
	HasMacros       bool   `json:"has_macros"`
	DangerousExt    bool   `json:"dangerous_extension"`
	ExtMismatch     bool   `json:"extension_mismatch"`
	IndividualScore int    `json:"individual_score"`
}

type aggView struct {
	Partial   bool     `json:"partial_analysis"`
	Missing   []string `json:"missing_components,omitempty"`
	Degraded  []string `json:"degraded_components,omitempty"`
	Timeout   bool     `json:"timeout_triggered"`
	LatencyMS int64    `json:"aggregation_latency_ms,omitempty"`
}

// viewOf builds the rich breakdown DTO from a cached scan.
func viewOf(sc *scan) scanView {
	v := scanView{
		EmailID: sc.EmailID,
		Status:  statusOf(sc),
		Source:  sc.Source,
		Subject: sc.Subject,
		From:    sc.From,
	}
	if !sc.SubmittedAt.IsZero() {
		t := sc.SubmittedAt
		v.SubmittedAt = &t
	}
	if ev := sc.Verdict; ev != nil {
		v.Verdict = &verdictView{
			Label:        ev.VerdictLabel,
			RiskScore:    ev.RiskScore,
			Confidence:   ev.Confidence,
			Source:       ev.VerdictSource,
			ModelVersion: ev.ModelVersion,
			Campaign:     ev.IsNewCampaign,
			FiredRules:   ev.FiredRules,
		}
	}
	if es := sc.Scored; es != nil {
		v.Aggregation = &aggView{
			Partial:   es.PartialAnalysis,
			Missing:   es.MissingComponents,
			Degraded:  es.DegradedComponents,
			Timeout:   es.TimeoutTriggered,
			LatencyMS: es.AggregationLatencyMS,
		}
		v.Modules.URL = urlViewOf(es.URLScore, es.ComponentDetails.URL)
		v.Modules.Header = headerViewOf(es.HeaderScore, sc.Header)
		v.Modules.NLP = nlpViewOf(es.NLPScore, es.ComponentDetails.NLP)
		v.Modules.Attachment = attachViewOf(es.AttachmentScore, sc.Attach)
	}
	return v
}

// legacyURL is one per_url record inside svc-03's legacy ScoreEnvelope.details
// (the L1 TI signals + L2 ML fields the typed ScoresURL has not adopted yet).
type legacyURL struct {
	URL          string  `json:"url"`
	Score        int     `json:"score"`
	Probability  float64 `json:"probability"`
	TIMatch      bool    `json:"ti_match"`
	TIThreatType string  `json:"ti_threat_type"`
	GuardHit     string  `json:"guard_hit"`
	MLDeployP    float64 `json:"ml_deploy_p"`
	MLVerdict    string  `json:"ml_verdict"`
	Label        string  `json:"label"`
}

// urlViewOf decodes the URL component, supporting BOTH the typed ScoresURL (when
// svc-03 migrates) and today's legacy ScoreEnvelope (per-URL detail under
// details.per_url). The composite score comes from emails.scored.url_score.
func urlViewOf(score *int, raw json.RawMessage) *urlView {
	if score == nil && len(raw) == 0 {
		return nil
	}
	uv := &urlView{Score: score}
	if len(raw) == 0 || string(raw) == "null" {
		return uv
	}
	var d struct {
		URLCount   int                   `json:"url_count"`
		TIBlocked  int                   `json:"ti_blocked_count"`
		MLScored   int                   `json:"ml_scored_count"`
		Riskiest   string                `json:"riskiest_url"`
		URLDetails []contracts.URLDetail `json:"url_details"`
		Details    struct {
			URLsTotal int         `json:"urls_total"`
			PerURL    []legacyURL `json:"per_url"`
		} `json:"details"`
	}
	_ = json.Unmarshal(raw, &d)

	if len(d.URLDetails) > 0 { // typed ScoresURL
		uv.URLCount, uv.TIBlocked, uv.MLScored, uv.Riskiest = d.URLCount, d.TIBlocked, d.MLScored, d.Riskiest
		for _, l := range d.URLDetails {
			uv.Links = append(uv.Links, linkView{
				URL: l.URL, Domain: l.Domain, TIMatched: l.TIMatched, TISource: l.TISource,
				GuardHit: l.GuardHit, DomainAgeDays: l.DomainAgeDays, IsShortened: l.IsShortened,
				MLVerdict: l.MLVerdict, MLDeployP: l.MLDeployP, MLScore: l.MLScore,
			})
		}
		return uv
	}

	// legacy ScoreEnvelope.details (svc-03 today)
	uv.URLCount = d.Details.URLsTotal
	for _, p := range d.Details.PerURL {
		if p.TIMatch {
			uv.TIBlocked++
		}
		if p.MLVerdict != "" {
			uv.MLScored++
		}
		s := p.Score
		uv.Links = append(uv.Links, linkView{
			URL:       p.URL,
			Score:     &s,
			Label:     p.Label,
			TIMatched: p.TIMatch,
			TISource:  optStr(p.TIThreatType),
			GuardHit:  optStr(p.GuardHit),
			MLVerdict: optStr(p.MLVerdict),
			MLDeployP: optF(p.MLDeployP),
		})
	}
	return uv
}

func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func optF(f float64) *float64 {
	if f == 0 {
		return nil
	}
	return &f
}

func headerViewOf(score *int, h *contracts.ScoresHeaderMessage) *headerView {
	if score == nil && h == nil {
		return nil
	}
	hv := &headerView{Score: score}
	if h != nil {
		hv.Auth = h.AuthSubScore
		hv.Reputation = h.ReputationSubScore
		hv.Structural = h.StructuralSubScore
		hv.FiredRules = h.FiredRules
		sg := h.Signals
		hv.SenderDomain = sg.SenderDomain
		hv.SPF = sg.SPFResult
		hv.DKIM = sg.DKIMResult
		hv.DMARC = sg.DMARCResult
		hv.DomainAge = sg.DomainAgeDays
		hv.Typosquat = sg.TyposquatTarget
		hv.FreeProvider = sg.IsFreeProvider
		hv.HopCount = sg.HopCount
	}
	return hv
}

// nlpViewOf decodes the NLP component. svc-06 today emits the structured facets
// (urgency/intent/impersonation/deception) under details.facets while keeping
// the legacy classification/intent_labels/obfuscation keys alongside; the typed
// ScoresNLP migration will move facets to the top level. This reads facets from
// EITHER location (top-level first, then details.facets) so impersonation and
// deception surface today, and falls back to the legacy details keys otherwise.
// Composite from emails.scored.nlp_score.
func nlpViewOf(score *int, raw json.RawMessage) *nlpView {
	if score == nil && len(raw) == 0 {
		return nil
	}
	nv := &nlpView{Score: score}
	if len(raw) == 0 || string(raw) == "null" {
		return nv
	}
	var d struct {
		Facets  contracts.NLPFacets `json:"facets"`
		Details struct {
			Classification string              `json:"classification"`
			Confidence     float64             `json:"confidence"`
			IntentLabels   json.RawMessage     `json:"intent_labels"`
			UrgencyScore   float64             `json:"urgency_score"`
			Obfuscation    bool                `json:"obfuscation_detected"`
			Facets         contracts.NLPFacets `json:"facets"`
		} `json:"details"`
	}
	_ = json.Unmarshal(raw, &d)

	// Prefer top-level facets (typed ScoresNLP); fall back to details.facets
	// (svc-06's current ScoreEnvelope emit).
	f := d.Facets
	if f.IntentLabel == "" && f.UrgencyScore == 0 && f.ImpersonationScore == 0 && f.DeceptionScore == 0 {
		f = d.Details.Facets
	}
	if f.IntentLabel != "" || f.UrgencyScore > 0 || f.ImpersonationScore > 0 || f.DeceptionScore > 0 {
		nv.HasFacets = true
		nv.Intent, nv.IntentConfidence = f.IntentLabel, f.IntentConfidence
		nv.Urgency, nv.Impersonation, nv.Deception = f.UrgencyScore, f.ImpersonationScore, f.DeceptionScore
		nv.ImpersonatedBrand = f.ImpersonatedBrand
		// classification / obfuscation live outside the facet struct.
		nv.Classification = d.Details.Classification
		nv.Obfuscation = d.Details.Obfuscation
		if nv.Intent == "" {
			nv.Intent = intentString(d.Details.IntentLabels, d.Details.Classification)
		}
		return nv
	}

	// legacy ScoreEnvelope.details (no facets at all)
	nv.Classification = d.Details.Classification
	nv.Intent = intentString(d.Details.IntentLabels, d.Details.Classification)
	nv.IntentConfidence = d.Details.Confidence
	nv.Urgency = d.Details.UrgencyScore
	nv.Obfuscation = d.Details.Obfuscation
	return nv
}

// intentString renders the legacy intent_labels (which may be a JSON array, a
// string, or an object) into a short label, falling back to the classification.
func intentString(raw json.RawMessage, fallback string) string {
	if len(raw) > 0 {
		var arr []string
		if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
			return strings.Join(arr, ", ")
		}
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return s
		}
	}
	return fallback
}

func attachViewOf(score *int, a *contracts.ScoresAttachment) *attachView {
	if score == nil && a == nil {
		return nil
	}
	av := &attachView{Score: score}
	if a != nil {
		av.Count = a.AttachmentCount
		av.Malicious = a.MaliciousCount
		for _, d := range a.AttachmentDetails {
			av.Files = append(av.Files, fileView{
				Filename: d.Filename, ContentType: d.ContentType, SizeBytes: d.SizeBytes,
				IsMalicious: d.IsMalicious, HasMacros: d.HasMacros, DangerousExt: d.IsDangerousExtension,
				ExtMismatch: d.ExtensionMismatch, IndividualScore: d.IndividualScore,
			})
		}
	}
	return av
}
