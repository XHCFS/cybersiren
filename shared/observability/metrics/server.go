package metrics

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
)

// StartServer starts a background HTTP server that exposes /metrics (Prometheus)
// and /healthz (liveness probe). It returns a shutdown function that gracefully
// stops the server within 5 seconds.
func StartServer(port int, registry *prometheus.Registry, log zerolog.Logger) func(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", HTTPHandler(registry))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Int("port", port).Msg("metrics server error")
		}
	}()

	log.Info().Int("port", port).Msg("metrics server started")

	return func(_ context.Context) error {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
