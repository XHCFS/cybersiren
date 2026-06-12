package main

import (
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

// linkView surfaces the L1 (TI/heuristic) vs L2 (ML fusion) signals per URL.
type linkView struct {
	URL           string   `json:"url"`
	Domain        string   `json:"domain,omitempty"`
	TIMatched     bool     `json:"ti_matched"`          // L1
	TISource      *string  `json:"ti_source,omitempty"` // L1
	GuardHit      *string  `json:"guard_hit,omitempty"` // L1
	DomainAgeDays *int     `json:"domain_age_days,omitempty"`
	IsShortened   bool     `json:"is_shortened"`
	MLVerdict     *string  `json:"ml_verdict,omitempty"`  // L2
	MLDeployP     *float64 `json:"ml_deploy_p,omitempty"` // L2
	MLScore       *int     `json:"ml_score,omitempty"`    // L2
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
	Intent            string  `json:"intent,omitempty"`
	IntentConfidence  float64 `json:"intent_confidence"`
	Urgency           float64 `json:"urgency"`
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
			Timeout:   es.TimeoutTriggered,
			LatencyMS: es.AggregationLatencyMS,
		}
		v.Modules.URL = urlViewOf(es.URLScore, sc.URL)
		v.Modules.Header = headerViewOf(es.HeaderScore, sc.Header)
		v.Modules.NLP = nlpViewOf(es.NLPScore, sc.NLP)
		v.Modules.Attachment = attachViewOf(es.AttachmentScore, sc.Attach)
	}
	return v
}

func urlViewOf(score *int, s *contracts.ScoresURL) *urlView {
	if score == nil && s == nil {
		return nil
	}
	uv := &urlView{Score: score}
	if s != nil {
		uv.URLCount = s.URLCount
		uv.TIBlocked = s.TIBlockedCount
		uv.MLScored = s.MLScoredCount
		uv.Riskiest = s.RiskiestURL
		for _, d := range s.URLDetails {
			uv.Links = append(uv.Links, linkView{
				URL: d.URL, Domain: d.Domain, TIMatched: d.TIMatched, TISource: d.TISource,
				GuardHit: d.GuardHit, DomainAgeDays: d.DomainAgeDays, IsShortened: d.IsShortened,
				MLVerdict: d.MLVerdict, MLDeployP: d.MLDeployP, MLScore: d.MLScore,
			})
		}
	}
	return uv
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

func nlpViewOf(score *int, n *contracts.ScoresNLP) *nlpView {
	if score == nil && n == nil {
		return nil
	}
	nv := &nlpView{Score: score}
	if n != nil {
		f := n.Facets
		nv.Intent = f.IntentLabel
		nv.IntentConfidence = f.IntentConfidence
		nv.Urgency = f.UrgencyScore
		nv.Impersonation = f.ImpersonationScore
		nv.ImpersonatedBrand = f.ImpersonatedBrand
		nv.Deception = f.DeceptionScore
	}
	return nv
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
