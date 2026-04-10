package metrics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
)

// StartServer binds a TCP listener on the given port and starts a background
// HTTP server that exposes /metrics (Prometheus) and /healthz (liveness probe).
// It returns a shutdown function and an error if the port cannot be bound.
func StartServer(port int, registry *prometheus.Registry, log zerolog.Logger) (func(ctx context.Context) error, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("metrics listen on port %d: %w", port, err)
	}

	return StartServerOnListener(ln, registry, log), nil
}

// StartServerOnListener starts a background HTTP server on the provided listener
// that exposes /metrics (Prometheus) and /healthz (liveness probe). It returns a
// shutdown function that gracefully stops the server within 5 seconds.
func StartServerOnListener(ln net.Listener, registry *prometheus.Registry, log zerolog.Logger) func(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", HTTPHandler(registry))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("metrics server error")
		}
	}()

	log.Info().Str("addr", ln.Addr().String()).Msg("metrics server started")

	return func(ctx context.Context) error {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
