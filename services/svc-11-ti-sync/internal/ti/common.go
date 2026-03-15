package ti

import (
	"errors"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/saif/cybersiren/shared/observability/tracing"
)

var (
	ErrPhishTankKeyMissing          = errors.New("phishtank api key missing")
	ErrThreatFoxAPIError            = errors.New("threatfox api returned non-ok query_status")
	ErrOpenPhishNonCommercialNotice = errors.New("OpenPhish free tier is non-commercial use only")
)

const (
	FeedFetchTimeout = 30 * time.Second
	URLIndicatorType = "url"
)

var feedTracer = tracing.Tracer("services/svc-11-ti-sync/internal/ti/feeds")

func Tracer() trace.Tracer {
	return feedTracer
}
