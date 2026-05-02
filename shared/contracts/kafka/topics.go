// Package kafka defines the on-the-wire Kafka message contracts
// that flow through the CyberSiren pipeline (per architecture-spec §1, §3).
// Wire format is JSON; every payload embeds a MessageMeta envelope.
package kafka

const (
	TopicEmailsRaw           = "emails.raw"
	TopicAnalysisURLs        = "analysis.urls"
	TopicAnalysisHeaders     = "analysis.headers"
	TopicAnalysisAttachments = "analysis.attachments"
	TopicAnalysisText        = "analysis.text"
	TopicAnalysisPlans       = "analysis.plans"
	TopicScoresURL           = "scores.url"
	TopicScoresHeader        = "scores.header"
	TopicScoresAttachment    = "scores.attachment"
	TopicScoresNLP           = "scores.nlp"
	TopicEmailsScored        = "emails.scored"
	TopicEmailsVerdict       = "emails.verdict"
)

// AllTopics is the canonical list of pipeline topics. Useful for admin/list
// operations and tests; do not iterate it for routing.
var AllTopics = []string{
	TopicEmailsRaw,
	TopicAnalysisURLs,
	TopicAnalysisHeaders,
	TopicAnalysisAttachments,
	TopicAnalysisText,
	TopicAnalysisPlans,
	TopicScoresURL,
	TopicScoresHeader,
	TopicScoresAttachment,
	TopicScoresNLP,
	TopicEmailsScored,
	TopicEmailsVerdict,
}

// Consumer-group names per architecture-spec §3 right column.
const (
	GroupParser              = "cg-parser"
	GroupURLAnalysis         = "cg-url-analysis"
	GroupHeaderAnalysis      = "cg-header-analysis"
	GroupAttachmentAnalysis  = "cg-attachment-analysis"
	GroupNLPAnalysis         = "cg-nlp-analysis"
	GroupAggregator          = "cg-aggregator"
	GroupDecisionEngine      = "cg-decision-engine"
	GroupNotification        = "cg-notification"
	GroupDashboard           = "cg-dashboard"
)
