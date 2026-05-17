package url

import (
	_ "embed"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// top10kRaw is the Cisco Umbrella top-10 000 apex domains, embedded at build time.
// Regenerate with: scripts/update_allowlist.sh
//
//go:embed data/top10k_domains.txt
var top10kRaw string

// DomainGuardResult is the outcome of the apex-domain brand-similarity check.
type DomainGuardResult struct {
	Verdict      string // "real" | "typosquat" | "unknown"
	MatchedBrand string // non-empty for "real" and "typosquat"
}

// HostnameFromURL returns the lowercased hostname from rawURL (no port).
// Returns empty string when the URL cannot be parsed or has no host.
func HostnameFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// ApexFromURL extracts the registered apex domain from a fully-normalized URL
// (e.g. "cdn.edge.static.cloudflare.com" → "cloudflare.com").
// Returns empty string when the URL cannot be parsed or has no host.
func ApexFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	hostname := strings.ToLower(u.Hostname())
	if net.ParseIP(hostname) != nil {
		return hostname // IP address — no apex domain structure
	}
	apex, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err == nil && apex != "" {
		return apex
	}
	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return hostname
}

// CheckDomain checks apexDomain against the Cisco top-10K allowlist.
//
// Pass the registered apex domain (e.g. "cloudflare.com"), not a full
// hostname. Extract it with ApexFromURL or publicsuffix.EffectiveTLDPlusOne.
//
//   - "real"      — exact match in top-10K → fast-path benign
//   - "typosquat" — edit distance 1 from a top-10K entry → fast-path phishing
//   - "unknown"   — no match → proceed to enrichment + sidecar
func CheckDomain(apexDomain string) DomainGuardResult {
	apex := strings.ToLower(apexDomain)
	if _, ok := allowlistSet[apex]; ok {
		return DomainGuardResult{Verdict: "real", MatchedBrand: apex}
	}
	// Levenshtein distance 1 only against the full top-10K.
	// Distance 2 is intentionally excluded: with 10K reference domains, d=2
	// produces incidental collisions between unrelated legitimate domains.
	bestBrand := ""
	for _, entry := range allowlistSlice {
		if intAbs(len(apex)-len(entry)) >= 2 {
			continue // length gap alone exceeds budget
		}
		if levenshtein(apex, entry) == 1 {
			bestBrand = entry
			break
		}
	}
	if bestBrand != "" {
		return DomainGuardResult{Verdict: "typosquat", MatchedBrand: bestBrand}
	}
	return DomainGuardResult{Verdict: "unknown"}
}

// levenshtein returns the edit distance between s and t.
func levenshtein(s, t string) int {
	if s == t {
		return 0
	}
	m, n := len(s), len(t)
	if m < n {
		s, t, m, n = t, s, n, m
	}
	row := make([]int, n+1)
	for j := range row {
		row[j] = j
	}
	for i := 1; i <= m; i++ {
		prev := row[0]
		row[0] = i
		for j := 1; j <= n; j++ {
			temp := row[j]
			sub := 1
			if s[i-1] == t[j-1] {
				sub = 0
			}
			row[j] = min3(row[j]+1, row[j-1]+1, prev+sub)
			prev = temp
		}
	}
	return row[n]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func intAbs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// allowlistSlice and allowlistSet are loaded from the embedded Cisco top-10K
// file at program start. No manual list management — update via
// scripts/update_allowlist.sh and commit the regenerated data file.
var allowlistSlice []string
var allowlistSet map[string]struct{}

func init() {
	lines := strings.Split(strings.TrimSpace(top10kRaw), "\n")
	allowlistSlice = make([]string, 0, len(lines))
	allowlistSet = make(map[string]struct{}, len(lines))
	for _, line := range lines {
		d := strings.ToLower(strings.TrimSpace(line))
		if d == "" {
			continue
		}
		allowlistSlice = append(allowlistSlice, d)
		allowlistSet[d] = struct{}{}
	}
}

// CheckSubdomainBrand checks whether any label in the full hostname contains a
// known brand name as a substring. Invoke this only when CheckDomain returned
// "unknown" — the apex itself is not allowlisted. Labels shorter than 4 chars
// (e.g. "www", "com", "cdn") are skipped because no tracked brand fits inside them.
//
// This catches patterns like "paypal-security.verify-login.com" and
// "microsoft-login-secure.netlify.app" where the brand appears in a label but
// the registered domain is a third-party host.
func CheckSubdomainBrand(hostname string) DomainGuardResult {
	for _, label := range strings.Split(strings.ToLower(hostname), ".") {
		if len(label) < 4 {
			continue
		}
		for _, brand := range brandSubstrings {
			if strings.Contains(label, brand) {
				return DomainGuardResult{Verdict: "brand-in-subdomain", MatchedBrand: brand}
			}
		}
	}
	return DomainGuardResult{Verdict: "unknown"}
}

// brandSubstrings are the consumer brand keywords checked against individual
// hostname labels. This list is intentionally small and hand-selected:
// it must only contain strings long enough (≥ 5 chars) to avoid matching
// common tokens, and only brands that attackers actually impersonate in
// subdomain labels. The Cisco allowlist above handles all other legitimate
// domains via exact-match — this list is not a registry, it is a phishing
// pattern detector.
var brandSubstrings = []string{
	"paypal", "microsoft", "google", "amazon", "apple",
	"facebook", "instagram", "netflix", "github", "linkedin",
	"outlook", "icloud", "youtube", "whatsapp",
	"chase", "wellsfargo", "citibank",
	"dropbox", "discord", "spotify",
}
