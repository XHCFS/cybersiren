package kafka

// ScoreEnvelope is the shared shape for every scores.* topic: a 0..100 risk
// score plus optional analyser-specific details. Concrete topic types embed
// this so consumers can switch on Component without unmarshalling per type.
type ScoreEnvelope struct {
	Meta      MessageMeta            `json:"meta"`
	Component string                 `json:"component"` // "url" | "header" | "attachment" | "nlp"
	Score     float64                `json:"score"`     // 0..100
	Details   map[string]interface{} `json:"details,omitempty"`
}

type ScoresURL struct {
	ScoreEnvelope
}

type ScoresHeader struct {
	ScoreEnvelope
}

type ScoresAttachment struct {
	ScoreEnvelope
}

type ScoresNLP struct {
	ScoreEnvelope
}

const (
	ComponentURL        = "url"
	ComponentHeader     = "header"
	ComponentAttachment = "attachment"
	ComponentNLP        = "nlp"
)
