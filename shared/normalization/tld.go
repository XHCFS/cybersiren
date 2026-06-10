package normalization

import "strings"

// TLDLabel returns the last dot-label of domain (its trailing TLD label),
// lowercased and trimmed with any trailing dot removed. It returns "" when the
// input has no dot-label (e.g. "localhost" or ""). For raw IPv4 input it returns
// the final octet (e.g. "1.2.3.4" -> "4"); that is acceptable because IPs are
// filtered upstream before this is called.
func TLDLabel(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return ""
	}
	if dot := strings.LastIndex(domain, "."); dot >= 0 {
		return domain[dot+1:]
	}
	return ""
}
