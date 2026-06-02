// Package persist writes SVC-03 URL enrichment results to Postgres. After the
// pipeline scores an email's URLs it hands the per-URL outcomes here, which
// enriches the bare enriched_threats rows SVC-02 created, records per-provider
// raw responses and a job row, and logs TI-feed matches. Writes are best-effort
// from the caller's perspective: scores.url is the SLA-bound output, so a
// persistence failure is surfaced for logging but must not block the publish.
package persist

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/internal/phishing/enricher"
)

// providerFusion is the enrichment_results provider label for the L2 fusion
// scorer + Go enricher path.
const providerFusion = "fusion-sidecar"

// defaultTTL is how long an enrichment_results row stays fresh; it matches the
// pipeline's prior-email reuse window.
const defaultTTL = 7 * 24 * time.Hour

// ScanRecord is the per-URL outcome the pipeline asks persist to store.
type ScanRecord struct {
	URL           string // raw URL; matches enriched_threats.url written by SVC-02
	RiskScore     int
	URLP          float64
	OpP           float64
	DeployP       float64
	Verdict       string
	TIMatched     bool
	TIIndicatorID int64
	Enrichment    *enricher.EnrichedURL // nil when the sidecar-fallback path ran
}

// Writer persists URL enrichment for an email in one transaction.
type Writer struct {
	pool *pgxpool.Pool
	ttl  time.Duration
	log  zerolog.Logger
}

// NewWriter constructs a Writer. A nil pool makes Persist a no-op error.
func NewWriter(pool *pgxpool.Pool, log zerolog.Logger) *Writer {
	return &Writer{pool: pool, ttl: defaultTTL, log: log}
}

// Persist writes enrichment, results, job, and TI-match rows for the scored
// URLs of one email. It maps each scan to the email_urls / enriched_threats row
// SVC-02 created; URLs without a matching row are skipped. All writes run in one
// transaction so an email's enrichment lands atomically.
func (w *Writer) Persist(ctx context.Context, emailID int64, fetchedAt time.Time, scans []ScanRecord) error {
	if w == nil || w.pool == nil {
		return fmt.Errorf("enrichment writer: not initialised")
	}
	if len(scans) == 0 {
		return nil
	}

	tx, err := w.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin enrichment tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	q := dbsqlc.New(tx)

	rows, err := q.ListEmailURLsForEmail(ctx, dbsqlc.ListEmailURLsForEmailParams{
		EmailID:        emailID,
		EmailFetchedAt: pgtype.Timestamptz{Time: fetchedAt, Valid: !fetchedAt.IsZero()},
	})
	if err != nil {
		return fmt.Errorf("list email_urls (email_id=%d): %w", emailID, err)
	}
	if len(rows) == 0 {
		return nil // SVC-02 rows not present (e.g. legacy message); nothing to enrich.
	}

	type ids struct {
		emailURLID int64
		threatID   int64
	}
	byURL := make(map[string]ids, len(rows))
	for _, r := range rows {
		if r.ThreatID.Valid {
			byURL[r.Url] = ids{emailURLID: r.EmailUrlID, threatID: r.ThreatID.Int64}
		}
	}

	for _, s := range scans {
		ref, ok := byURL[s.URL]
		if !ok {
			w.log.Debug().Str("url", s.URL).Int64("email_id", emailID).Msg("no email_urls row for scanned URL; skipping persist")
			continue
		}

		if s.Enrichment != nil {
			if err := q.UpdateEnrichedThreatEnrichment(ctx, buildEnrichmentParams(ref.threatID, s)); err != nil {
				return fmt.Errorf("update enriched_threat (id=%d): %w", ref.threatID, err)
			}
		}

		raw, err := json.Marshal(map[string]any{
			"url_p": s.URLP, "op_p": s.OpP, "deploy_p": s.DeployP, "verdict": s.Verdict,
		})
		if err != nil {
			return fmt.Errorf("marshal enrichment raw_response: %w", err)
		}
		if err := q.UpsertEnrichmentResult(ctx, dbsqlc.UpsertEnrichmentResultParams{
			EntityID:        ref.threatID,
			Provider:        providerFusion,
			RawResponse:     raw,
			TtlSeconds:      pgtype.Int4{Int32: int32(w.ttl.Seconds()), Valid: true},
			ReputationScore: pgtype.Float8{Float64: s.DeployP, Valid: true},
		}); err != nil {
			return fmt.Errorf("upsert enrichment_result (threat=%d): %w", ref.threatID, err)
		}

		if err := q.InsertEnrichmentJob(ctx, ref.threatID); err != nil {
			return fmt.Errorf("insert enrichment_job (threat=%d): %w", ref.threatID, err)
		}

		if s.TIMatched && s.TIIndicatorID != 0 {
			if err := q.InsertEmailURLTIMatch(ctx, dbsqlc.InsertEmailURLTIMatchParams{
				EmailUrlID:    ref.emailURLID,
				TiIndicatorID: s.TIIndicatorID,
			}); err != nil {
				return fmt.Errorf("insert email_url_ti_match (email_url=%d): %w", ref.emailURLID, err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit enrichment tx: %w", err)
	}
	return nil
}

// buildEnrichmentParams maps the enricher output to the enriched_threats UPDATE
// params. Date/time strings are parsed best-effort; unparseable values become
// SQL NULL rather than failing the row.
func buildEnrichmentParams(threatID int64, s ScanRecord) dbsqlc.UpdateEnrichedThreatEnrichmentParams {
	eu := s.Enrichment
	p := dbsqlc.UpdateEnrichedThreatEnrichmentParams{
		ID:             threatID,
		Online:         pgtype.Bool{Bool: eu.HTTP.StatusCode > 0, Valid: true},
		HttpStatusCode: int4OrNull(eu.HTTP.StatusCode),
		IpAddress:      ipOrNil(eu.IP),
		CidrBlock:      textOrNull(eu.Geo.CIDRBlock),
		Asn:            int4OrNull(eu.Geo.ASN),
		AsnName:        textOrNull(eu.Geo.ASNName),
		Isp:            textOrNull(eu.Geo.ISP),
		Country:        textOrNull(eu.Geo.Country),
		CountryName:    textOrNull(eu.Geo.CountryName),
		Region:         textOrNull(eu.Geo.Region),
		City:           textOrNull(eu.Geo.City),
		Latitude:       coordOrNull(eu.Geo.Latitude, eu.Geo.Longitude),
		Longitude:      coordOrNull(eu.Geo.Longitude, eu.Geo.Latitude),
		SslEnabled:     pgtype.Bool{Bool: eu.TLS.Enabled, Valid: true},
		CertIssuer:     textOrNull(eu.TLS.Issuer),
		CertSubject:    textOrNull(eu.TLS.Subject),
		CertValidFrom:  tsOrNull(eu.TLS.ValidFrom),
		CertValidTo:    tsOrNull(eu.TLS.ValidTo),
		Registrar:      textOrNull(eu.WHOIS.Registrar),
		CreationDate:   dateOrNull(eu.WHOIS.RegistrationDate),
		ExpiryDate:     dateOrNull(eu.WHOIS.ExpiryDate),
		UpdatedDate:    dateOrNull(eu.WHOIS.UpdatedDate),
		NameServers:    splitNameServers(eu.WHOIS.NameServers),
		PageLanguage:   textOrNull(eu.HTTP.Language),
		PageTitle:      textOrNull(eu.HTTP.Title),
		RiskScore:      int4OrNull(s.RiskScore),
	}
	return p
}

// ── helpers ──────────────────────────────────────────────────────────────────

func textOrNull(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

func int4OrNull(v int) pgtype.Int4 {
	return pgtype.Int4{Int32: int32(v), Valid: v != 0}
}

// coordOrNull keeps a latitude/longitude only when the pair isn't 0,0 (the
// MaxMind miss sentinel), so a real equator/prime-meridian point is the only
// edge case dropped.
func coordOrNull(v, other float64) pgtype.Float8 {
	if v == 0 && other == 0 {
		return pgtype.Float8{}
	}
	return pgtype.Float8{Float64: v, Valid: true}
}

func ipOrNil(s string) *netip.Addr {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return nil
	}
	return &addr
}

func splitNameServers(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// dateLayouts covers the common shapes whois parsers emit.
var dateLayouts = []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02 15:04:05", "2006-01-02"}

func dateOrNull(s string) pgtype.Date {
	if t, ok := parseAny(s); ok {
		return pgtype.Date{Time: t, Valid: true}
	}
	return pgtype.Date{}
}

func tsOrNull(s string) pgtype.Timestamptz {
	if t, ok := parseAny(s); ok {
		return pgtype.Timestamptz{Time: t, Valid: true}
	}
	return pgtype.Timestamptz{}
}

func parseAny(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
