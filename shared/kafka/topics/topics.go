// Package topics is the canonical registry of all CyberSiren Kafka topics
// and consumer groups. The values match deploy/compose/kafka-init.sh and
// ARCH-SPEC §3 (Kafka Topic Registry).
//
// Centralising these strings here avoids subtle typos across services
// (e.g. "scores.headers" vs "scores.header" — only the latter is correct).
package topics

// Pipeline topics.
const (
	EmailsRaw           = "emails.raw"
	AnalysisURLs        = "analysis.urls"
	AnalysisHeaders     = "analysis.headers"
	AnalysisAttachments = "analysis.attachments"
	AnalysisText        = "analysis.text"
	AnalysisPlans       = "analysis.plans"
	ScoresURL           = "scores.url"
	ScoresHeader        = "scores.header"
	ScoresAttachment    = "scores.attachment"
	ScoresNLP           = "scores.nlp"
	EmailsScored        = "emails.scored"
	EmailsVerdict       = "emails.verdict"
)

// Consumer groups.
const (
	GroupParser             = "cg-parser"
	GroupURLAnalysis        = "cg-url-analysis"
	GroupHeaderAnalysis     = "cg-header-analysis"
	GroupAttachmentAnalysis = "cg-attachment-analysis"
	GroupNLPAnalysis        = "cg-nlp-analysis"
	GroupAggregator         = "cg-aggregator"
	GroupDecisionEngine     = "cg-decision-engine"
	GroupNotification       = "cg-notification"
	GroupDashboard          = "cg-dashboard"
)
