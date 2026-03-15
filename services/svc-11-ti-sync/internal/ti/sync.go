package ti

import "context"

type Feed interface {
	Fetch(ctx context.Context) ([]TIIndicator, error)
}

type TIIndicator struct {
	FeedID         int64
	IndicatorType  string
	IndicatorValue string
	ThreatType     string
	ThreatTags     []string
	RiskScore      int
	Confidence     float64
	SourceID       string
	RawMetadata    []byte
}
