package header

import "strings"

// freeProviderDomains is an embedded, deliberately conservative list of
// consumer-grade free email providers commonly abused for phishing.
//
// This is NOT intended to be exhaustive. New entries can be added here
// or — preferably — moved into a configurable list once SVC-04 grows a
// proper "registry" surface. See "Follow-ups" in the MR.
//
// Entries are stored as registrable domains (lowercased, no leading dot).
var freeProviderDomains = map[string]struct{}{
	"gmail.com":      {},
	"googlemail.com": {},
	"outlook.com":    {},
	"hotmail.com":    {},
	"live.com":       {},
	"msn.com":        {},
	"yahoo.com":      {},
	"yahoo.co.uk":    {},
	"yahoo.co.jp":    {},
	"ymail.com":      {},
	"rocketmail.com": {},
	"icloud.com":     {},
	"me.com":         {},
	"mac.com":        {},
	"aol.com":        {},
	"protonmail.com": {},
	"proton.me":      {},
	"pm.me":          {},
	"tutanota.com":   {},
	"gmx.com":        {},
	"gmx.de":         {},
	"gmx.net":        {},
	"yandex.com":     {},
	"yandex.ru":      {},
	"mail.ru":        {},
	"inbox.ru":       {},
	"list.ru":        {},
	"bk.ru":          {},
	"zoho.com":       {},
	"fastmail.com":   {},
	"fastmail.fm":    {},
	"hushmail.com":   {},
	"naver.com":      {},
	"qq.com":         {},
	"163.com":        {},
	"126.com":        {},
	"sina.com":       {},
	"sina.cn":        {},
}

// IsFreeProvider returns true when the (already-normalised) domain is in
// the embedded free-provider list. It also matches subdomains of the
// listed domains so e.g. "alias.users.gmail.com" is still considered
// free-provider.
func IsFreeProvider(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return false
	}
	if _, ok := freeProviderDomains[d]; ok {
		return true
	}
	// Subdomain match: walk parent labels.
	for {
		idx := strings.Index(d, ".")
		if idx < 0 {
			return false
		}
		d = d[idx+1:]
		if _, ok := freeProviderDomains[d]; ok {
			return true
		}
	}
}
