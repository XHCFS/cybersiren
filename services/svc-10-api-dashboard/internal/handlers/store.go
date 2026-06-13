package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	db "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/shared/postgres/repository"
)

// dbReader is the DB-backed ConsoleReader. Org-scoped reads run inside
// repository.WithOrgTx so the RLS tenant boundary (app.current_org_id) is set;
// the control-plane login read runs directly on the pool (users is not
// RLS-forced).
type dbReader struct {
	pool *pgxpool.Pool
	q    *db.Queries
}

// NewDBReader builds a ConsoleReader over the connection pool.
func NewDBReader(pool *pgxpool.Pool) ConsoleReader {
	return &dbReader{pool: pool, q: db.New(pool)}
}

// Login resolves the user (control-plane read, explicit org filter), then
// bcrypt-compares the password. Every failure mode collapses to
// ErrInvalidCredentials so the wire response never reveals which field was wrong.
func (r *dbReader) Login(ctx context.Context, orgID int64, email, password string) (AuthUser, error) {
	row, err := r.q.GetUserByEmailWithPassword(ctx, db.GetUserByEmailWithPasswordParams{
		OrgID: orgID,
		Email: email,
	})
	if err != nil {
		// pgx.ErrNoRows (unknown user) and any other read error both fail closed.
		return AuthUser{}, ErrInvalidCredentials
	}
	if err := verifyPassword(row.PasswordHash, password); err != nil {
		return AuthUser{}, ErrInvalidCredentials
	}
	// Best-effort last-login bookkeeping; never blocks login on failure.
	_ = r.q.TouchUserLastLogin(ctx, row.ID)
	return AuthUser{
		ID:          row.ID,
		Email:       row.Email,
		DisplayName: row.DisplayName.String,
		Role:        string(row.Role),
		OrgID:       row.OrgID,
	}, nil
}

func (r *dbReader) ListEmails(ctx context.Context, orgID int64, limit, offset int) ([]EmailListItem, error) {
	var items []EmailListItem
	err := repository.WithOrgTx(ctx, r.pool, orgID, func(q *db.Queries) error {
		rows, err := q.ListEmailsByOrg(ctx, db.ListEmailsByOrgParams{
			OrgID:  orgID,
			Limit:  int32(limit),
			Offset: int32(offset),
		})
		if err != nil {
			return fmt.Errorf("list emails: %w", err)
		}
		items = make([]EmailListItem, 0, len(rows))
		for _, row := range rows {
			items = append(items, EmailListItem{
				EmailID:      uuidString(row.EmailID),
				InternalID:   row.InternalID,
				MessageID:    row.MessageID.String,
				SenderEmail:  row.SenderEmail.String,
				SenderName:   row.SenderName.String,
				SenderDomain: row.SenderDomain.String,
				Subject:      row.Subject.String,
				RiskScore:    int4Ptr(row.RiskScore),
				VerdictLabel: row.CurrentVerdictLabel.String,
				SentAt:       tsPtr(row.SentAt),
				FetchedAt:    tsPtr(row.FetchedAt),
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list emails tx: %w", err)
	}
	return items, nil
}

func (r *dbReader) GetEmailDetail(ctx context.Context, orgID int64, emailID string) (EmailDetail, error) {
	parsed, perr := uuid.Parse(emailID)
	if perr != nil {
		// A non-UUID id can never resolve to a row — treat as not-found rather
		// than a server error.
		return EmailDetail{}, ErrNotFound
	}

	var detail EmailDetail
	err := repository.WithOrgTx(ctx, r.pool, orgID, func(q *db.Queries) error {
		key, rerr := q.ResolveEmailByEmailID(ctx, db.ResolveEmailByEmailIDParams{
			OrgID:   orgID,
			EmailID: pgtype.UUID{Bytes: parsed, Valid: true},
		})
		if errors.Is(rerr, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if rerr != nil {
			return fmt.Errorf("resolve email_id: %w", rerr)
		}

		// ResolveEmailByEmailIDRow and GetEmailByInternalIDParams are structurally
		// identical (internal_id, fetched_at), so the composite key converts directly.
		email, eerr := q.GetEmailByInternalID(ctx, db.GetEmailByInternalIDParams(key))
		if errors.Is(eerr, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if eerr != nil {
			return fmt.Errorf("get email: %w", eerr)
		}

		detail = EmailDetail{
			EmailID:        emailID,
			InternalID:     email.InternalID,
			MessageID:      email.MessageID.String,
			SenderName:     email.SenderName.String,
			SenderEmail:    email.SenderEmail.String,
			SenderDomain:   email.SenderDomain.String,
			ReplyToEmail:   email.ReplyToEmail.String,
			ReturnPath:     email.ReturnPath.String,
			Subject:        email.Subject.String,
			AuthSPF:        email.AuthSpf.String,
			AuthDKIM:       email.AuthDkim.String,
			AuthDMARC:      email.AuthDmarc.String,
			BodyPlain:      email.BodyPlain.String,
			BodyHTML:       email.BodyHtml.String,
			RiskScore:      int4Ptr(email.RiskScore),
			HeaderRisk:     int4Ptr(email.HeaderRiskScore),
			ContentRisk:    int4Ptr(email.ContentRiskScore),
			URLRisk:        int4Ptr(email.UrlRiskScore),
			AttachmentRisk: int4Ptr(email.AttachmentRiskScore),
			SentAt:         tsPtr(email.SentAt),
			FetchedAt:      tsPtr(email.FetchedAt),
			VerdictHistory: []Verdict{},
			RuleHits:       []RuleHit{},
			URLs:           []EmailURL{},
			Attachments:    []Attachment{},
			Recipients:     []Recipient{},
		}

		// Current verdict (may be absent).
		cv, cverr := q.GetCurrentVerdictForEmail(ctx, key.InternalID)
		if cverr == nil {
			detail.CurrentVerdict = &Verdict{
				Label:        string(cv.Label),
				Confidence:   float8Ptr(cv.Confidence),
				Source:       string(cv.Source),
				ModelVersion: cv.ModelVersion.String,
				Notes:        cv.Notes.String,
				CreatedBy:    int8Ptr(cv.CreatedBy),
				CreatedAt:    tsPtr(cv.CreatedAt),
			}
		} else if !errors.Is(cverr, pgx.ErrNoRows) {
			return fmt.Errorf("current verdict: %w", cverr)
		}

		// Verdict history.
		vhist, verr := q.ListVerdictsForEmail(ctx, db.ListVerdictsForEmailParams{
			EntityID:       key.InternalID,
			EmailFetchedAt: key.FetchedAt,
		})
		if verr != nil {
			return fmt.Errorf("verdict history: %w", verr)
		}
		for _, v := range vhist {
			detail.VerdictHistory = append(detail.VerdictHistory, Verdict{
				ID:           v.ID,
				Label:        string(v.Label),
				Confidence:   float8Ptr(v.Confidence),
				Source:       string(v.Source),
				ModelVersion: v.ModelVersion.String,
				Notes:        v.Notes.String,
				CreatedBy:    int8Ptr(v.CreatedBy),
				CreatedAt:    tsPtr(v.CreatedAt),
			})
		}

		// Rule hits.
		hits, herr := q.ListRuleHitsForEmail(ctx, db.ListRuleHitsForEmailParams{
			EntityID:       key.InternalID,
			EmailFetchedAt: key.FetchedAt,
		})
		if herr != nil {
			return fmt.Errorf("rule hits: %w", herr)
		}
		for _, h := range hits {
			detail.RuleHits = append(detail.RuleHits, RuleHit{
				ID:              h.ID,
				RuleID:          int8Ptr(h.RuleID),
				RuleName:        h.RuleName.String,
				RuleDescription: h.RuleDescription.String,
				RuleTarget:      h.RuleTarget.String,
				RuleVersion:     h.RuleVersion,
				ScoreImpact:     h.ScoreImpact,
				MatchDetail:     rawJSON(h.MatchDetail),
				FiredAt:         tsPtr(h.FiredAt),
			})
		}

		// URLs + TI matches + resolved threat.
		urls, uerr := q.ListEmailURLs(ctx, db.ListEmailURLsParams{
			EmailID:        key.InternalID,
			EmailFetchedAt: key.FetchedAt,
		})
		if uerr != nil {
			return fmt.Errorf("email urls: %w", uerr)
		}
		for _, u := range urls {
			eu := EmailURL{
				ID:          u.ID,
				VisibleText: u.VisibleText.String,
				ThreatID:    int8Ptr(u.ThreatID),
				TIMatches:   []TIMatch{},
			}
			matches, merr := q.ListEmailURLTIMatches(ctx, u.ID)
			if merr != nil {
				return fmt.Errorf("ti matches: %w", merr)
			}
			for _, m := range matches {
				eu.TIMatches = append(eu.TIMatches, TIMatch{
					ID:            m.ID,
					TIIndicatorID: m.TiIndicatorID,
					MatchType:     m.MatchType,
					MatchedAt:     tsPtr(m.MatchedAt),
				})
			}
			if u.ThreatID.Valid {
				threat, terr := q.GetEnrichedThreatByID(ctx, u.ThreatID.Int64)
				if terr == nil {
					eu.Threat = toEnrichedThreat(threat)
				} else if !errors.Is(terr, pgx.ErrNoRows) {
					return fmt.Errorf("enriched threat: %w", terr)
				}
			}
			detail.URLs = append(detail.URLs, eu)
		}

		// Attachments.
		atts, aerr := q.ListEmailAttachments(ctx, db.ListEmailAttachmentsParams{
			EmailID:        key.InternalID,
			EmailFetchedAt: key.FetchedAt,
		})
		if aerr != nil {
			return fmt.Errorf("attachments: %w", aerr)
		}
		for _, a := range atts {
			detail.Attachments = append(detail.Attachments, Attachment{
				AttachmentID: a.AttachmentID,
				Filename:     a.Filename.String,
				ContentType:  a.ContentType.String,
				Disposition:  a.Disposition.String,
				RiskScore:    int4Ptr(a.RiskScore),
			})
		}

		// Recipients.
		recips, rcerr := q.ListEmailRecipients(ctx, db.ListEmailRecipientsParams{
			EmailID:        key.InternalID,
			EmailFetchedAt: key.FetchedAt,
		})
		if rcerr != nil {
			return fmt.Errorf("recipients: %w", rcerr)
		}
		for _, rc := range recips {
			detail.Recipients = append(detail.Recipients, Recipient{
				ID:            rc.ID,
				Address:       rc.Address,
				DisplayName:   rc.DisplayName.String,
				RecipientType: rc.RecipientType,
			})
		}
		return nil
	})
	if err != nil {
		// ErrNotFound is wrapped with %w below, so the handler's errors.Is check
		// still matches and maps it to a 404.
		return EmailDetail{}, fmt.Errorf("email detail tx: %w", err)
	}
	return detail, nil
}

func (r *dbReader) ListRules(ctx context.Context, orgID int64) ([]RuleSummary, error) {
	var out []RuleSummary
	err := repository.WithOrgTx(ctx, r.pool, orgID, func(q *db.Queries) error {
		rows, err := q.ListRulesForOrg(ctx, pgtype.Int8{Int64: orgID, Valid: true})
		if err != nil {
			return fmt.Errorf("list rules: %w", err)
		}
		out = make([]RuleSummary, 0, len(rows))
		for _, row := range rows {
			out = append(out, RuleSummary{
				ID:          row.ID,
				OrgID:       int8Ptr(row.OrgID),
				Name:        row.Name,
				Description: row.Description.String,
				Version:     row.Version,
				Status:      string(row.Status),
				Target:      row.Target,
				ScoreImpact: row.ScoreImpact,
				CreatedAt:   tsPtr(row.CreatedAt),
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list rules tx: %w", err)
	}
	return out, nil
}

func (r *dbReader) ThreatSummary(ctx context.Context, orgID int64) ([]ThreatStat, error) {
	// MVs are NOT RLS-forced; org scoping is the explicit SQL predicate. No tx needed.
	rows, err := r.q.GetThreatSummary(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("threat summary: %w", err)
	}
	out := make([]ThreatStat, 0, len(rows))
	for _, row := range rows {
		out = append(out, ThreatStat{
			ThreatType:   row.ThreatType,
			Country:      row.Country,
			ASN:          row.Asn,
			ASNName:      row.AsnName,
			IsGlobal:     row.IsGlobal,
			OrgID:        row.OrgID,
			Total:        row.Total,
			OnlineCount:  row.OnlineCount,
			OfflineCount: row.OfflineCount,
			AvgRiskScore: row.AvgRiskScore,
			MaxRiskScore: anyFloatPtr(row.MaxRiskScore),
			EarliestSeen: anyTimePtr(row.EarliestSeen),
			LatestSeen:   anyTimePtr(row.LatestSeen),
		})
	}
	return out, nil
}

func (r *dbReader) CampaignSummary(ctx context.Context, orgID int64) ([]CampaignStat, error) {
	rows, err := r.q.GetCampaignSummary(ctx, pgtype.Int8{Int64: orgID, Valid: true})
	if err != nil {
		return nil, fmt.Errorf("campaign summary: %w", err)
	}
	out := make([]CampaignStat, 0, len(rows))
	for _, row := range rows {
		out = append(out, CampaignStat{
			CampaignID:        row.CampaignID,
			OrgID:             int8Ptr(row.OrgID),
			Name:              row.Name,
			Fingerprint:       row.Fingerprint,
			ThreatType:        row.ThreatType.String,
			TargetBrand:       row.TargetBrand.String,
			RiskScore:         int4Ptr(row.RiskScore),
			FirstSeen:         tsPtr(row.FirstSeen),
			LastSeen:          tsPtr(row.LastSeen),
			EmailCount:        row.EmailCount,
			AvgEmailRiskScore: row.AvgEmailRiskScore,
			VerdictPhishing:   row.VerdictPhishing,
			VerdictMalware:    row.VerdictMalware,
			VerdictSuspicious: row.VerdictSuspicious,
			VerdictBenign:     row.VerdictBenign,
			VerdictSpam:       row.VerdictSpam,
			VerdictUnknown:    row.VerdictUnknown,
		})
	}
	return out, nil
}

func (r *dbReader) FeedHealth(ctx context.Context, _ int64) ([]FeedStat, error) {
	rows, err := r.q.GetFeedHealth(ctx)
	if err != nil {
		return nil, fmt.Errorf("feed health: %w", err)
	}
	out := make([]FeedStat, 0, len(rows))
	for _, row := range rows {
		out = append(out, FeedStat{
			FeedID:                  row.FeedID,
			Name:                    row.Name,
			DisplayName:             row.DisplayName.String,
			FeedType:                row.FeedType,
			ReliabilityWeight:       row.ReliabilityWeight,
			Enabled:                 boolPtr(row.Enabled),
			LastFetchedAt:           tsPtr(row.LastFetchedAt),
			SecondsSinceFetch:       numericPtr(row.SecondsSinceFetch),
			TotalThreatsContributed: row.TotalThreatsContributed,
			ActiveThreats:           row.ActiveThreats,
			AvgThreatRiskScore:      row.AvgThreatRiskScore,
		})
	}
	return out, nil
}

func (r *dbReader) RulePerformance(ctx context.Context, orgID int64) ([]RuleStat, error) {
	rows, err := r.q.GetRulePerformance(ctx, pgtype.Int8{Int64: orgID, Valid: true})
	if err != nil {
		return nil, fmt.Errorf("rule performance: %w", err)
	}
	out := make([]RuleStat, 0, len(rows))
	for _, row := range rows {
		out = append(out, RuleStat{
			RuleID:                row.RuleID,
			OrgID:                 int8Ptr(row.OrgID),
			Name:                  row.Name,
			Version:               row.Version,
			Status:                string(row.Status),
			Target:                row.Target,
			ScoreImpact:           row.ScoreImpact,
			TotalHits:             row.TotalHits,
			HitsLast24h:           row.HitsLast24h,
			HitsLast7d:            row.HitsLast7d,
			TotalScoreContributed: row.TotalScoreContributed,
			LastFiredAt:           anyTimePtr(row.LastFiredAt),
		})
	}
	return out, nil
}

func (r *dbReader) OrgIngestionSummary(ctx context.Context, orgID int64) (IngestionStat, error) {
	row, err := r.q.GetOrgIngestionSummary(ctx, pgtype.Int8{Int64: orgID, Valid: true})
	if errors.Is(err, pgx.ErrNoRows) {
		// No emails ingested yet: a zero-valued summary is the correct view.
		return IngestionStat{OrgID: &orgID}, nil
	}
	if err != nil {
		return IngestionStat{}, fmt.Errorf("ingestion summary: %w", err)
	}
	return IngestionStat{
		OrgID:             int8Ptr(row.OrgID),
		TotalEmails:       row.TotalEmails,
		EmailsLast24h:     row.EmailsLast24h,
		EmailsLast7d:      row.EmailsLast7d,
		EmailsLast30d:     row.EmailsLast30d,
		AvgRiskScore:      row.AvgRiskScore,
		MaxRiskScore:      anyInt32Ptr(row.MaxRiskScore),
		HighRiskCount:     row.HighRiskCount,
		MediumRiskCount:   row.MediumRiskCount,
		LowRiskCount:      row.LowRiskCount,
		ConfirmedPhishing: row.ConfirmedPhishing,
		ConfirmedMalware:  row.ConfirmedMalware,
		ConfirmedSpam:     row.ConfirmedSpam,
		ConfirmedBenign:   row.ConfirmedBenign,
		Unclassified:      row.Unclassified,
	}, nil
}

// verifyPassword bcrypt-compares password against the stored hash. A NULL or
// empty stored hash is rejected (a user with no local password can never log
// in) — the caller collapses any returned error into the generic
// ErrInvalidCredentials so the wire response never reveals which field failed.
func verifyPassword(storedHash pgtype.Text, password string) error {
	if !storedHash.Valid || storedHash.String == "" {
		return ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash.String), []byte(password)); err != nil {
		return ErrInvalidCredentials
	}
	return nil
}

// toEnrichedThreat projects a generated enriched_threats row onto the console DTO.
func toEnrichedThreat(t db.EnrichedThreat) *EnrichedThreat {
	out := &EnrichedThreat{
		ID:         t.ID,
		URL:        t.Url,
		Domain:     t.Domain.String,
		Online:     boolPtr(t.Online),
		ASN:        int4Ptr(t.Asn),
		ASNName:    t.AsnName.String,
		Country:    t.Country.String,
		ThreatType: t.ThreatType.String,
		Registrar:  t.Registrar.String,
		RiskScore:  int4Ptr(t.RiskScore),
		IsGlobal:   t.IsGlobal,
	}
	if t.IpAddress != nil {
		out.IPAddress = t.IpAddress.String()
	}
	return out
}

// ── pgtype → pointer / scalar helpers ───────────────────────────────────────

func int4Ptr(v pgtype.Int4) *int32 {
	if !v.Valid {
		return nil
	}
	val := v.Int32
	return &val
}

func int8Ptr(v pgtype.Int8) *int64 {
	if !v.Valid {
		return nil
	}
	val := v.Int64
	return &val
}

func float8Ptr(v pgtype.Float8) *float64 {
	if !v.Valid {
		return nil
	}
	val := v.Float64
	return &val
}

func boolPtr(v pgtype.Bool) *bool {
	if !v.Valid {
		return nil
	}
	val := v.Bool
	return &val
}

func tsPtr(v pgtype.Timestamptz) *time.Time {
	if !v.Valid {
		return nil
	}
	val := v.Time
	return &val
}

func numericPtr(v pgtype.Numeric) *float64 {
	if !v.Valid {
		return nil
	}
	f, err := v.Float64Value()
	if err != nil || !f.Valid {
		return nil
	}
	val := f.Float64
	return &val
}

func uuidString(v pgtype.UUID) string {
	if !v.Valid {
		return ""
	}
	return uuid.UUID(v.Bytes).String()
}

// rawJSON unmarshals a JSONB blob into a generic value for the response, or nil
// when empty/invalid so the field is omitted rather than emitted as a string.
func rawJSON(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil
	}
	return v
}

// anyFloatPtr / anyInt32Ptr / anyTimePtr coerce the `interface{}` columns sqlc
// emits for MV aggregate expressions (MAX/MIN over numeric/timestamp) whose type
// it cannot statically infer. pgx scans them into a small set of concrete types.
func anyFloatPtr(v any) *float64 {
	switch n := v.(type) {
	case nil:
		return nil
	case float64:
		return &n
	case float32:
		f := float64(n)
		return &f
	case int32:
		f := float64(n)
		return &f
	case int64:
		f := float64(n)
		return &f
	case pgtype.Numeric:
		return numericPtr(n)
	default:
		return nil
	}
}

func anyInt32Ptr(v any) *int32 {
	switch n := v.(type) {
	case nil:
		return nil
	case int32:
		return &n
	case int64:
		i := int32(n)
		return &i
	case float64:
		i := int32(n)
		return &i
	default:
		return nil
	}
}

func anyTimePtr(v any) *time.Time {
	switch t := v.(type) {
	case nil:
		return nil
	case time.Time:
		return &t
	case pgtype.Timestamptz:
		return tsPtr(t)
	default:
		return nil
	}
}

// compile-time assertion.
var _ ConsoleReader = (*dbReader)(nil)
