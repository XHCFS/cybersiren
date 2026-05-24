package url

import (
	"testing"
)

var _sink DomainGuardResult

func BenchmarkCheckDomain_AllowlistHit(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_sink = CheckDomain("google.com")
	}
}

func BenchmarkCheckDomain_TyposquatDetect(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_sink = CheckDomain("goog1e.com")
	}
}

func BenchmarkCheckDomain_Unknown(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_sink = CheckDomain("random-site-not-in-any-list.xyz")
	}
}

func BenchmarkCheckSubdomainBrand_Hit(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_sink = CheckSubdomainBrand("paypal-security.verify-login.com")
	}
}

func BenchmarkCheckSubdomainBrand_Miss(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_sink = CheckSubdomainBrand("completely-random-site.xyz")
	}
}

func BenchmarkApexFromURL(b *testing.B) {
	b.ReportAllocs()
	url := "https://cdn.edge.static.cloudflare.com/assets/bundle.min.js?v=1.2.3"
	for i := 0; i < b.N; i++ {
		_ = ApexFromURL(url)
	}
}
