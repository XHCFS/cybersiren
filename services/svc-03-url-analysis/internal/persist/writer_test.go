package persist

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/internal/phishing/enricher"
	"github.com/saif/cybersiren/shared/config"
)

func TestBuildEnrichmentParams(t *testing.T) {
	t.Parallel()

	eu := &enricher.EnrichedURL{
		IP:    "203.0.113.10",
		WHOIS: enricher.WHOISResult{Registrar: "Example Registrar", RegistrationDate: "2020-01-02T00:00:00Z", NameServers: "ns1.example.com, ns2.example.com"},
		Geo:   enricher.GeoIPResult{Country: "US", ASN: 64500, ISP: "Example ISP", Latitude: 37.7, Longitude: -122.4, CIDRBlock: "203.0.113.0/24"},
		TLS:   enricher.TLSResult{Enabled: true, Issuer: "Let's Encrypt", ValidFrom: "2024-01-01T00:00:00Z"},
		HTTP:  enricher.HTTPResult{StatusCode: 200, Title: "Login", Language: "en"},
	}
	p := buildEnrichmentParams(99, ScanRecord{RiskScore: 80, Enrichment: eu})

	if p.ID != 99 || !p.Online.Bool || p.HttpStatusCode.Int32 != 200 {
		t.Errorf("base fields wrong: %+v", p)
	}
	if p.IpAddress == nil || p.IpAddress.String() != "203.0.113.10" {
		t.Errorf("IpAddress = %v, want 203.0.113.10", p.IpAddress)
	}
	if !p.Asn.Valid || p.Asn.Int32 != 64500 || p.Country.String != "US" {
		t.Errorf("geo fields wrong: %+v", p)
	}
	if !p.Latitude.Valid || !p.Longitude.Valid {
		t.Errorf("coords should be valid: %+v", p.Latitude)
	}
	if !p.SslEnabled.Bool || p.CertIssuer.String != "Let's Encrypt" || !p.CertValidFrom.Valid {
		t.Errorf("tls fields wrong: %+v", p)
	}
	if !p.CreationDate.Valid || p.Registrar.String != "Example Registrar" {
		t.Errorf("whois fields wrong: %+v", p)
	}
	if len(p.NameServers) != 2 {
		t.Errorf("NameServers = %v, want 2 entries", p.NameServers)
	}
	if p.RiskScore.Int32 != 80 {
		t.Errorf("RiskScore = %d, want 80", p.RiskScore.Int32)
	}
}

func TestCoordOrNullDropsZeroPair(t *testing.T) {
	t.Parallel()
	if coordOrNull(0, 0).Valid {
		t.Error("0,0 must map to NULL (MaxMind miss sentinel)")
	}
	if !coordOrNull(0, -122.4).Valid {
		t.Error("0 latitude with non-zero longitude should be kept")
	}
}

func TestParseAnyLayouts(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"2020-01-02T03:04:05Z", "2020-01-02 03:04:05", "2020-01-02"} {
		if _, ok := parseAny(s); !ok {
			t.Errorf("parseAny(%q) failed", s)
		}
	}
	if _, ok := parseAny("not a date"); ok {
		t.Error("parseAny should reject garbage")
	}
}

func TestSplitNameServers(t *testing.T) {
	t.Parallel()
	got := splitNameServers("a.com,  b.com ,, c.com")
	if len(got) != 3 || got[1] != "b.com" {
		t.Errorf("splitNameServers = %v, want 3 trimmed entries", got)
	}
	if splitNameServers("  ") != nil {
		t.Error("blank input should be nil")
	}
}

// TestPersistEnrichmentEndToEnd seeds an email + bare enriched_threats + a TI
// indicator, then verifies Persist enriches the row, records a TTL'd
// enrichment_results, logs a job, and writes a TI-match audit row. Skipped in
// -short / no-DB; runs in the Integration CI job.
func TestPersistEnrichmentEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DB integration test in -short mode")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Skipf("config load failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, cfg.DB.DSN())
	if err != nil {
		t.Skipf("no DB pool: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("DB not reachable: %v", err)
	}

	uniq := time.Now().UnixNano()
	emailID := uniq
	fetchedAt := time.Now().UTC()
	url := fmt.Sprintf("https://enrich-test-%d.example.com/login", uniq)

	// Seed: email → bare enriched_threat → email_url, plus feed → ti_indicator.
	if _, err := pool.Exec(ctx, `INSERT INTO emails (internal_id, fetched_at) VALUES ($1,$2)`, emailID, fetchedAt); err != nil {
		t.Fatalf("seed email: %v", err)
	}
	defer pool.Exec(context.Background(), `DELETE FROM emails WHERE internal_id=$1`, emailID) //nolint:errcheck

	var threatID int64
	if err := pool.QueryRow(ctx, `INSERT INTO enriched_threats (url, source_feed, is_global) VALUES ($1,'email',TRUE) RETURNING id`, url).Scan(&threatID); err != nil {
		t.Fatalf("seed enriched_threat: %v", err)
	}
	defer pool.Exec(context.Background(), `DELETE FROM enriched_threats WHERE id=$1`, threatID) //nolint:errcheck

	var emailURLID int64
	if err := pool.QueryRow(ctx, `INSERT INTO email_urls (email_id, email_fetched_at, threat_id) VALUES ($1,$2,$3) RETURNING id`, emailID, fetchedAt, threatID).Scan(&emailURLID); err != nil {
		t.Fatalf("seed email_url: %v", err)
	}

	var feedID int64
	if err := pool.QueryRow(ctx, `INSERT INTO feeds (name, feed_type) VALUES ($1,'threat_intel') RETURNING id`, fmt.Sprintf("test-feed-%d", uniq)).Scan(&feedID); err != nil {
		t.Fatalf("seed feed: %v", err)
	}
	defer pool.Exec(context.Background(), `DELETE FROM feeds WHERE id=$1`, feedID) //nolint:errcheck
	var indicatorID int64
	if err := pool.QueryRow(ctx, `INSERT INTO ti_indicators (feed_id, indicator_type, indicator_value) VALUES ($1,'domain',$2) RETURNING id`, feedID, fmt.Sprintf("enrich-test-%d.example.com", uniq)).Scan(&indicatorID); err != nil {
		t.Fatalf("seed ti_indicator: %v", err)
	}

	w := NewWriter(pool, zerolog.Nop())
	scan := ScanRecord{
		URL: url, RiskScore: 88, URLP: 0.9, OpP: 0.3, DeployP: 0.77, Verdict: "phishing",
		TIMatched: true, TIIndicatorID: indicatorID,
		Enrichment: &enricher.EnrichedURL{
			IP:   "203.0.113.5",
			Geo:  enricher.GeoIPResult{Country: "US", ASN: 64500},
			TLS:  enricher.TLSResult{Enabled: true, Issuer: "Test CA", ValidFrom: "2024-01-01T00:00:00Z"},
			HTTP: enricher.HTTPResult{StatusCode: 200, Title: "Login"},
		},
	}
	if err := w.Persist(ctx, emailID, fetchedAt, []ScanRecord{scan}); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	// enriched_threats enriched.
	var country string
	var lastChecked *time.Time
	if err := pool.QueryRow(ctx, `SELECT country, last_checked FROM enriched_threats WHERE id=$1`, threatID).Scan(&country, &lastChecked); err != nil {
		t.Fatalf("read enriched_threat: %v", err)
	}
	if country != "US" || lastChecked == nil {
		t.Errorf("enrichment not applied: country=%q last_checked=%v", country, lastChecked)
	}

	// enrichment_results has a computed expires_at.
	var expiresAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT expires_at FROM enrichment_results WHERE entity_type='threat' AND entity_id=$1 AND provider=$2`, threatID, providerFusion).Scan(&expiresAt); err != nil {
		t.Fatalf("read enrichment_result: %v", err)
	}
	if expiresAt == nil {
		t.Error("expires_at not set by trigger")
	}

	// enrichment_jobs + email_url_ti_matches present.
	var jobs, matches int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM enrichment_jobs WHERE entity_type='threat' AND entity_id=$1`, threatID).Scan(&jobs)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM email_url_ti_matches WHERE email_url_id=$1 AND ti_indicator_id=$2`, emailURLID, indicatorID).Scan(&matches)
	if jobs != 1 || matches != 1 {
		t.Fatalf("jobs=%d matches=%d, want 1/1", jobs, matches)
	}

	// Re-persisting must not duplicate the TI-match audit row (ON CONFLICT).
	if err := w.Persist(ctx, emailID, fetchedAt, []ScanRecord{scan}); err != nil {
		t.Fatalf("Persist (redelivery): %v", err)
	}
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM email_url_ti_matches WHERE email_url_id=$1 AND ti_indicator_id=$2`, emailURLID, indicatorID).Scan(&matches)
	if matches != 1 {
		t.Errorf("after re-persist email_url_ti_matches = %d, want 1 (idempotent)", matches)
	}
}
