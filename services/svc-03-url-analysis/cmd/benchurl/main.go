// Command benchurl runs the OFFLINE-runnable part of the REAL svc-03 URL stack
// over benchmark URLs: domain-guard allowlist + typosquat/brand-in-subdomain guard.
// (L2 operational fusion + TI need LIVE enrichment — SSL/WHOIS/page fetch of 44
// features — which is impossible for static/dead benchmark URLs; see notes.)
//
//	stdin : one raw URL per line
//	stdout: CSV  url,guard_verdict,guard_score
//	  guard_verdict: allowlisted | typosquat | brand-in-subdomain | unknown
//	  guard_score:   0 (allowlisted) | 100 (typosquat/brand) | -1 (unknown -> defer to L1)
package main

import (
	"bufio"
	"fmt"
	"os"

	urlpkg "github.com/saif/cybersiren/services/svc-03-url-analysis/internal/url"
)

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	fmt.Fprintln(out, "url,guard_verdict,guard_score")
	for in.Scan() {
		raw := in.Text()
		if raw == "" {
			continue
		}
		apex := urlpkg.ApexFromURL(raw)
		g := urlpkg.CheckDomain(apex)
		score := -1
		switch g.Verdict {
		case "real":
			g.Verdict = "allowlisted"
			score = 0
		case "typosquat":
			score = 100
		default:
			// not allowlisted, not a typosquat: check brand-in-subdomain
			sub := urlpkg.CheckSubdomainBrand(urlpkg.HostnameFromURL(raw))
			if sub.Verdict == "brand-in-subdomain" {
				g.Verdict = "brand-in-subdomain"
				score = 100
			}
		}
		fmt.Fprintf(out, "%q,%s,%d\n", raw, g.Verdict, score)
	}
}
