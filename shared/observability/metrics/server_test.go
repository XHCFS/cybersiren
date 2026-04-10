package metrics_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/saif/cybersiren/shared/observability/metrics"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

func TestStartServer_MetricsEndpoint(t *testing.T) {
	port := freePort(t)
	reg := metrics.Init("test-service")
	log := zerolog.Nop()

	shutdown := metrics.StartServer(port, reg, log)
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", port))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "go_goroutines")
}

func TestStartServer_HealthzEndpoint(t *testing.T) {
	port := freePort(t)
	reg := prometheus.NewRegistry()
	log := zerolog.Nop()

	shutdown := metrics.StartServer(port, reg, log)
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "ok", string(body))
}

func TestStartServer_Shutdown(t *testing.T) {
	port := freePort(t)
	reg := prometheus.NewRegistry()
	log := zerolog.Nop()

	shutdown := metrics.StartServer(port, reg, log)

	time.Sleep(50 * time.Millisecond)

	err := shutdown(context.Background())
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	_, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
	assert.Error(t, err, "server should be stopped after shutdown")
}
