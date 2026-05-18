//go:build integration

package phishing

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func startSidecar(t *testing.T, port string) func() {
	t.Helper()
	repoRoot := os.Getenv("REPO_ROOT")
	if repoRoot == "" {
		repoRoot = "../.."
	}
	servePath := repoRoot + "/fusion_export/scripts/serve.py"
	cmd := exec.Command("python", servePath, "--port", port, "--workers", "2")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())

	// Wait for sidecar to be ready.
	time.Sleep(4 * time.Second)

	return func() { _ = cmd.Process.Kill() }
}

func TestDetector_LiveBenignURL(t *testing.T) {
	dir := os.Getenv("GEOIP_DIR")
	if dir == "" {
		t.Skip("GEOIP_DIR not set")
	}

	stop := startSidecar(t, "8766")
	defer stop()

	d, err := NewDetector(Config{
		SidecarURL: "http://127.0.0.1:8766",
		GeoIPDir:   dir,
	})
	require.NoError(t, err)
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := d.Score(ctx, "https://google.com/")
	require.NoError(t, err)
	require.Equal(t, "benign", result.Verdict, "google.com should be benign")
}

func TestDetector_LivePhishingURL(t *testing.T) {
	dir := os.Getenv("GEOIP_DIR")
	if dir == "" {
		t.Skip("GEOIP_DIR not set")
	}

	stop := startSidecar(t, "8767")
	defer stop()

	d, err := NewDetector(Config{
		SidecarURL: "http://127.0.0.1:8767",
		GeoIPDir:   dir,
	})
	require.NoError(t, err)
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use a URL from fusion_export/live_phishing_urls.txt.
	repoRoot := os.Getenv("REPO_ROOT")
	if repoRoot == "" {
		repoRoot = "../.."
	}
	urlsFile := repoRoot + "/fusion_export/live_phishing_urls.txt"
	data, err := os.ReadFile(urlsFile)
	require.NoError(t, err)

	lines := splitLines(string(data))
	require.NotEmpty(t, lines)

	result, err := d.Score(ctx, lines[0])
	require.NoError(t, err)
	require.Equal(t, "phishing", result.Verdict, "live phishing URL should score as phishing")
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[0] != '#' {
				lines = append(lines, line)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		line := s[start:]
		if len(line) > 0 && line[0] != '#' {
			lines = append(lines, line)
		}
	}
	return lines
}
