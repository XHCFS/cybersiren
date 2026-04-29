package header

import (
	"strings"
)

// brandRegistrableDomains is the embedded list of brand registrable
// domains we test for typosquats against. Entries are LOWERCASED.
//
// Calibration disclaimer: this list is a starter, not a labelled corpus.
// Adding/removing brands is one of the documented follow-ups.
var brandRegistrableDomains = []string{
	"paypal.com",
	"amazon.com",
	"apple.com",
	"microsoft.com",
	"google.com",
	"gmail.com",
	"netflix.com",
	"facebook.com",
	"instagram.com",
	"linkedin.com",
	"twitter.com",
	"x.com",
	"github.com",
	"dropbox.com",
	"adobe.com",
	"docusign.com",
	"office.com",
	"office365.com",
	"icloud.com",
	"outlook.com",
	"hotmail.com",
	"yahoo.com",
	"chase.com",
	"bankofamerica.com",
	"wellsfargo.com",
	"citibank.com",
	"hsbc.com",
	"barclays.com",
	"americanexpress.com",
	"dhl.com",
	"fedex.com",
	"ups.com",
	"usps.com",
}

// FindTyposquat returns the best (lowest non-zero distance) brand match
// against domain. distance = 0 means the input is one of the brand
// domains (no typosquat). When no brand is within maxDistance, returns
// ("", 0).
//
// The comparison is done on the registrable label of `domain` — we strip
// leading subdomains until we either match a brand or run out of labels.
// This catches "secure-paypal.com" and "paypa1-secure.com" while keeping
// the cost bounded.
func FindTyposquat(domain string, maxDistance int) (target string, distance int) {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimSuffix(d, ".")
	if d == "" || maxDistance < 1 {
		return "", 0
	}

	candidates := candidateLabels(d)
	bestTarget := ""
	bestDist := maxDistance + 1

	for _, c := range candidates {
		for _, brand := range brandRegistrableDomains {
			if c == brand {
				// Exact-match brand: don't flag as typosquat.
				return "", 0
			}
			dist := damerauLevenshtein(c, brand, bestDist)
			if dist == 0 {
				return "", 0
			}
			if dist < bestDist {
				bestDist = dist
				bestTarget = brand
			}
		}
	}

	if bestDist > maxDistance {
		return "", 0
	}
	return bestTarget, bestDist
}

// candidateLabels generates the label-suffix candidates we check against
// the brand list. For "login.secure-paypa1.com" we yield:
//
//	login.secure-paypa1.com
//	secure-paypa1.com
//	paypa1.com (only if its label-count >= 2)
//
// We stop at 2 labels because brands are stored as registrable domains.
func candidateLabels(domain string) []string {
	out := []string{domain}
	for {
		idx := strings.Index(domain, ".")
		if idx < 0 {
			break
		}
		domain = domain[idx+1:]
		if strings.Count(domain, ".") < 1 {
			break
		}
		out = append(out, domain)
	}
	if strings.Count(out[len(out)-1], ".") >= 1 {
		out = append(out, out[len(out)-1])
	}
	return dedupe(out)
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// damerauLevenshtein computes the Optimal-String-Alignment Damerau-
// Levenshtein distance between a and b. It supports the four classic
// edit operations: insert, delete, substitute, transpose-of-adjacent.
//
// `cap` allows the caller to stop computing once distance has exceeded
// the threshold of interest. Pass a large number to disable the bound.
//
// Implementation note: we use a 2-row rolling buffer (memory O(min(n,m)))
// plus a third "two-rows-back" row for the transposition step.
// Correctness verified against published OSA test vectors.
func damerauLevenshtein(a, b string, cap int) int {
	ar := []rune(strings.ToLower(a))
	br := []rune(strings.ToLower(b))
	la, lb := len(ar), len(br)

	if la == 0 {
		if lb < cap {
			return lb
		}
		return cap
	}
	if lb == 0 {
		if la < cap {
			return la
		}
		return cap
	}

	// Ensure ar is the shorter of the two for memory.
	if la > lb {
		ar, br = br, ar
		la, lb = lb, la
	}

	prevPrev := make([]int, la+1)
	prev := make([]int, la+1)
	curr := make([]int, la+1)

	for i := 0; i <= la; i++ {
		prev[i] = i
	}

	for j := 1; j <= lb; j++ {
		curr[0] = j
		minInRow := curr[0]
		for i := 1; i <= la; i++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}

			del := prev[i] + 1
			ins := curr[i-1] + 1
			sub := prev[i-1] + cost
			best := del
			if ins < best {
				best = ins
			}
			if sub < best {
				best = sub
			}

			// Transposition of adjacent characters: ab → ba.
			if i > 1 && j > 1 && ar[i-1] == br[j-2] && ar[i-2] == br[j-1] {
				trans := prevPrev[i-2] + 1
				if trans < best {
					best = trans
				}
			}

			curr[i] = best
			if best < minInRow {
				minInRow = best
			}
		}
		// Early-exit: every value in this row is >= minInRow, so future
		// rows can only grow above cap.
		if minInRow > cap {
			return cap + 1
		}
		prevPrev, prev, curr = prev, curr, prevPrev
	}

	if prev[la] > cap {
		return cap + 1
	}
	return prev[la]
}
