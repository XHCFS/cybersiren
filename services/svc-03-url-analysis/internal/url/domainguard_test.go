package url

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckDomain_ExactMatch(t *testing.T) {
	t.Parallel()
	cases := []string{
		// Core brands — top positions in Cisco top-10K.
		"google.com", "paypal.com", "github.com",
		"microsoft.com", "amazon.com", "cloudflare.com",
		// Microsoft identity / O365 — in Cisco top-10K so their subdomains
		// (login.microsoftonline.com, outlook.office365.com) are never
		// handed to CheckSubdomainBrand.
		"microsoftonline.com", "office365.com", "sharepoint.com",
	}
	for _, apex := range cases {
		apex := apex
		t.Run(apex, func(t *testing.T) {
			t.Parallel()
			got := CheckDomain(apex)
			assert.Equal(t, "real", got.Verdict)
			assert.Equal(t, apex, got.MatchedBrand)
		})
	}
}

func TestCheckDomain_Typosquat(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input string
		brand string
	}{
		{"goog1e.com", "google.com"},
		{"paypa1.com", "paypal.com"},
		{"amaz0n.com", "amazon.com"},
		{"microsofft.com", "microsoft.com"},
		{"githib.com", "github.com"},
		{"linkedln.com", "linkedin.com"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := CheckDomain(tc.input)
			assert.Equal(t, "typosquat", got.Verdict)
			assert.Equal(t, tc.brand, got.MatchedBrand)
		})
	}
}

func TestCheckDomain_Unknown(t *testing.T) {
	t.Parallel()
	cases := []string{
		"verify-login.com",
		"evil-phishing-site.com",
		"random-domain.xyz",
		"secure-update-required.com",
		// netlify.app is intentionally NOT here: it is in the Cisco top-10K
		// (a legitimate hosting platform) and correctly resolves to "real".
		// Phishing subdomains on netlify.app get a different apex via PSL,
		// so they are not protected by netlify.app's allowlist entry.
	}
	for _, apex := range cases {
		apex := apex
		t.Run(apex, func(t *testing.T) {
			t.Parallel()
			got := CheckDomain(apex)
			assert.Equal(t, "unknown", got.Verdict)
		})
	}
}

func TestCheckDomain_ApexPassthrough(t *testing.T) {
	t.Parallel()
	// Callers must extract the apex first; CheckDomain receives only the apex.
	// "cloudflare.com" is in the list; "cdn.edge.static.cloudflare.com" is not.
	assert.Equal(t, "real", CheckDomain("cloudflare.com").Verdict)
	assert.Equal(t, "unknown", CheckDomain("cdn.edge.static.cloudflare.com").Verdict)
}

func TestCheckDomain_CaseInsensitive(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "real", CheckDomain("Google.COM").Verdict)
	assert.Equal(t, "real", CheckDomain("GITHUB.COM").Verdict)
}

func TestAllowlist_LoadedFromEmbed(t *testing.T) {
	t.Parallel()
	// Verify the embedded Cisco top-10K file was parsed correctly.
	assert.GreaterOrEqual(t, len(allowlistSlice), 9000, "allowlist should have ≥ 9000 entries")
	assert.GreaterOrEqual(t, len(allowlistSet), 9000, "allowlist set should have ≥ 9000 entries")
	// Spot-check a few entries that are in the Cisco top-10K.
	for _, d := range []string{"google.com", "microsoft.com", "microsoftonline.com", "office365.com"} {
		_, ok := allowlistSet[d]
		assert.True(t, ok, "%s must be present in the embedded allowlist", d)
	}
}

func TestApexFromURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		rawURL string
		want   string
	}{
		{"https://www.google.com/search?q=test", "google.com"},
		{"https://cdn.edge.static.cloudflare.com/assets/main.js", "cloudflare.com"},
		{"https://github.com/login", "github.com"},
		// vercel.app is a private PSL entry; publicsuffix treats each subdomain
		// as its own registered domain, so the full subdomain is returned.
		{"https://paypal-secure-login.vercel.app/verify", "paypal-secure-login.vercel.app"},
		{"http://192.168.1.1/admin", "192.168.1.1"},
		// Deep real-world URLs — apex extraction must strip subdomains and path.
		{"https://mail.google.com/mail/u/2/#inbox/FMfcgzQgLjSzssBCDsxTdncpMfxlqKlW", "google.com"},
		{"https://login.microsoftonline.com/common/oauth2/v2.0/authorize", "microsoftonline.com"},
		{"https://outlook.office365.com/mail/inbox", "office365.com"},
		{"https://appleid.apple.com/sign-in", "apple.com"},
		{"https://signin.aws.amazon.com/signin?redirect_uri=console", "amazon.com"},
		{"", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.rawURL, func(t *testing.T) {
			t.Parallel()
			got := ApexFromURL(tc.rawURL)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCheckSubdomainBrand(t *testing.T) {
	t.Parallel()
	cases := []struct {
		hostname string
		verdict  string
		brand    string
	}{
		// Brand in subdomain label, foreign apex.
		{"paypal-security.verify-login.com", "brand-in-subdomain", "paypal"},
		// Brand fills the entire private-PSL "registered" segment.
		{"microsoft-login-secure.netlify.app", "brand-in-subdomain", "microsoft"},
		// Brand-secure pattern on netlify.
		{"paypal-secure.netlify.app", "brand-in-subdomain", "paypal"},
		// Deep subdomain, brand in inner label.
		{"signin.apple-id.phish.ru", "brand-in-subdomain", "apple"},
		// No brand present — generic domain.
		{"verify-login.com", "unknown", ""},
		// Single label with no brand.
		{"evil.com", "unknown", ""},
		// Short labels (< 4 chars) are skipped; no false positives.
		{"cdn.io.net", "unknown", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.hostname, func(t *testing.T) {
			t.Parallel()
			got := CheckSubdomainBrand(tc.hostname)
			assert.Equal(t, tc.verdict, got.Verdict)
			if tc.brand != "" {
				assert.Equal(t, tc.brand, got.MatchedBrand)
			}
		})
	}
}

func TestCheckSubdomainBrand_CaseInsensitive(t *testing.T) {
	t.Parallel()
	got := CheckSubdomainBrand("PAYPAL-SECURITY.EVIL.COM")
	assert.Equal(t, "brand-in-subdomain", got.Verdict)
	assert.Equal(t, "paypal", got.MatchedBrand)
}

func TestCheckSubdomainBrand_AllowlistedApexNotReached(t *testing.T) {
	t.Parallel()
	// paypal.com IS in the allowlist — CheckDomain returns "real" and
	// CheckSubdomainBrand is never called by the handler.
	// This test documents that calling it directly on the hostname of
	// an allowlisted domain would match, so callers must gate on CheckDomain first.
	got := CheckSubdomainBrand("www.paypal.com")
	assert.Equal(t, "brand-in-subdomain", got.Verdict) // caller responsibility to skip
}

func TestHostnameFromURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		rawURL string
		want   string
	}{
		{"https://paypal-security.verify-login.com/path", "paypal-security.verify-login.com"},
		{"http://192.168.1.1/admin", "192.168.1.1"},
		{"https://GITHUB.COM/login", "github.com"},
		{"", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.rawURL, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, HostnameFromURL(tc.rawURL))
		})
	}
}

func TestLevenshtein(t *testing.T) {
	t.Parallel()
	cases := []struct {
		s, t string
		want int
	}{
		{"google.com", "google.com", 0},
		{"paypal.com", "paypa1.com", 1},
		{"google.com", "goog1e.com", 1},
		{"microsoft.com", "microsofft.com", 1},
		{"", "abc", 3},
		{"abc", "", 3},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.s+"_vs_"+tc.t, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, levenshtein(tc.s, tc.t))
		})
	}
}
