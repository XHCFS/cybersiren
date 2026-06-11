package metrics

import (
	"errors"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	zlog "github.com/rs/zerolog/log"
)

// Register registers collector c on reg and returns it, idempotently. If an
// identical collector is already registered (prometheus.AlreadyRegisteredError —
// e.g. a service re-inits its metrics in a test), the existing collector is
// returned so callers can register without panicking. A nil reg returns c
// unchanged (test convenience).
//
// Unlike the per-service copies it replaces, a NON-duplicate registration error
// (a name/label collision, a mismatched Desc) is LOGGED via the zerolog global
// rather than silently swallowed — those copies returned an unregistered
// collector whose .Inc()/.Observe() never reached /metrics with no signal at
// all. The collector is still returned so the caller's wiring stays non-nil.
func Register[T prometheus.Collector](reg *prometheus.Registry, c T) T {
	if reg == nil {
		return c
	}
	if err := reg.Register(c); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(T); ok {
				return existing
			}
			return c
		}
		zlog.Error().Err(err).Msg("metrics: collector registration failed; metric will not be exported")
	}
	return c
}

func Init(serviceName string) *prometheus.Registry {
	_ = serviceName

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	return registry
}

func HTTPHandler(registry *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}
