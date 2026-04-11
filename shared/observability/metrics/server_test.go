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

const testRequestTimeout = 200 * time.Millisecond

func getWithTimeout(url string, client *http.Client) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), testRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	return client.Do(req)
}

func TestStartServer_MetricsEndpoint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	port := ln.Addr().(*net.TCPAddr).Port
	reg := metrics.Init("test-service")
	log := zerolog.Nop()

	shutdown := metrics.StartServerOnListener(ln, reg, log)
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	metricsURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", port)
	healthzURL := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	client := &http.Client{Timeout: testRequestTimeout}

	require.Eventually(t, func() bool {
		resp, reqErr := getWithTimeout(healthzURL, client)
		if reqErr != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 2*time.Second, 10*time.Millisecond, "server did not become ready")

	resp, err := getWithTimeout(metricsURL, client)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "go_goroutines")
}

func TestStartServer_HealthzEndpoint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	port := ln.Addr().(*net.TCPAddr).Port
	reg := prometheus.NewRegistry()
	log := zerolog.Nop()

	shutdown := metrics.StartServerOnListener(ln, reg, log)
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	healthzURL := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	client := &http.Client{Timeout: testRequestTimeout}

	require.Eventually(t, func() bool {
		resp, reqErr := getWithTimeout(healthzURL, client)
		if reqErr != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 2*time.Second, 10*time.Millisecond, "server did not become ready")

	resp, err := getWithTimeout(healthzURL, client)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "ok", string(body))
}

func TestStartServer_Shutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	port := ln.Addr().(*net.TCPAddr).Port
	reg := prometheus.NewRegistry()
	log := zerolog.Nop()

	shutdown := metrics.StartServerOnListener(ln, reg, log)

	healthzURL := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	client := &http.Client{Timeout: testRequestTimeout}

	require.Eventually(t, func() bool {
		resp, reqErr := getWithTimeout(healthzURL, client)
		if reqErr != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 2*time.Second, 10*time.Millisecond, "server did not become ready")

	err = shutdown(context.Background())
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		resp, reqErr := getWithTimeout(healthzURL, client)
		if resp != nil {
			resp.Body.Close()
		}
		return reqErr != nil
	}, 2*time.Second, 10*time.Millisecond, "server did not shut down")
}
