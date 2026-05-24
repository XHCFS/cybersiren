package enricher

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTitleBrandMismatch_Mismatch(t *testing.T) {
	t.Parallel()
	require.Equal(t, 1.0, titleBrandMismatch("PayPal Login", "evil.com"))
}

func TestTitleBrandMismatch_Match(t *testing.T) {
	t.Parallel()
	require.Equal(t, 0.0, titleBrandMismatch("PayPal Login", "paypal.com"))
}

func TestTitleBrandMismatch_Subdomain(t *testing.T) {
	t.Parallel()
	require.Equal(t, 0.0, titleBrandMismatch("PayPal Login", "www.paypal.com"))
}

func TestTitleHasLoginKw(t *testing.T) {
	t.Parallel()
	require.Equal(t, 1.0, titleHasLoginKw("Secure Login Page"))
	require.Equal(t, 0.0, titleHasLoginKw("Welcome to our store"))
}

func TestIsEphemeralPlatform(t *testing.T) {
	t.Parallel()
	require.Equal(t, 1.0, isEphemeralPlatform("anything.vercel.app"))
	require.Equal(t, 0.0, isEphemeralPlatform("anything.example.com"))
}

func TestSubdomainDepth(t *testing.T) {
	t.Parallel()
	require.Equal(t, 2.0, subdomainDepth("a.b.example.com"))
	require.Equal(t, 0.0, subdomainDepth("example.com"))
}

func TestSubdomainBrandCount(t *testing.T) {
	t.Parallel()
	require.Equal(t, 1.0, subdomainBrandCount("paypal.evil.com"))
	require.Equal(t, 0.0, subdomainBrandCount("random.evil.com"))
}

func TestIPInURL(t *testing.T) {
	t.Parallel()
	require.Equal(t, 1.0, ipInURL("http://192.168.1.1/path"))
	require.Equal(t, 0.0, ipInURL("https://example.com/path"))
}

func TestNonStdPort(t *testing.T) {
	t.Parallel()
	require.Equal(t, 1.0, nonStdPort("https://example.com:8443/path"))
	require.Equal(t, 0.0, nonStdPort("https://example.com/path"))
	require.Equal(t, 0.0, nonStdPort("https://example.com:443/path"))
	require.Equal(t, 0.0, nonStdPort("http://example.com:80/path"))
}

func TestURLDomainCharRatio(t *testing.T) {
	t.Parallel()
	// "a1-b.example.com" = 16 chars; non-alpha-non-dot: '1', '-' = 2
	ratio := urlDomainCharRatio("a1-b.example.com")
	require.InDelta(t, 2.0/16.0, ratio, 0.001)
}

func TestDomainAgeDays_ApproxCorrect(t *testing.T) {
	t.Parallel()
	// A date exactly 365 days ago.
	d := time.Now().UTC().AddDate(-1, 0, 0).Format(time.RFC3339)
	days := daysSince(d)
	require.InDelta(t, 365.0, days, 2.0, "domain age should be ~365 days")
}

func TestDomainAgeDays_InvalidDate(t *testing.T) {
	t.Parallel()
	require.True(t, math.IsNaN(daysSince("not-a-date")))
}

func TestToJSON_NaNBecomesNull(t *testing.T) {
	t.Parallel()
	fv := FeatureVector{
		URL:           "https://example.com",
		ASN:           math.NaN(),
		DomainAgeDays: math.NaN(),
		Latitude:      math.NaN(),
	}
	m := fv.ToJSON()
	body, err := json.Marshal(m)
	require.NoError(t, err)

	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &decoded))

	require.Nil(t, decoded["asn"], "NaN ASN must serialize as null")
	require.Nil(t, decoded["domain_age_days"], "NaN domain_age_days must serialize as null")
	require.Nil(t, decoded["latitude"], "NaN latitude must serialize as null")
}
