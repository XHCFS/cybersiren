// Package ingest is svc-01's ingestion core: the org-authenticated, deduped,
// quota-gated path that turns a normalised email (from any EmailSource adapter)
// into an emails.raw publish.
//
// It does NOT write the emails table — svc-02 is the SOLE emails writer (the v0
// INSERT shim is retired). svc-01's only persistence touch is the read-only
// email_identities dedup fallback (see internal/dedup). It assigns the logical
// email_id as a UUIDv7 (G17/#142) and carries the authenticating api_keys.id +
// source_adapter onto emails.raw.
package ingest

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/source"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// Deduper is the (org, message_id) dedup gate (internal/dedup). Release undoes a
// claim that did not result in a published email so the client's retry is not
// suppressed for the full dedup window.
type Deduper interface {
	Claim(ctx context.Context, orgID int64, messageID string) (bool, error)
	Release(ctx context.Context, orgID int64, messageID string) error
}

// QuotaLimiter enforces the monthly ingestion quota (internal/quota). Refund
// undoes an Allow whose request did not ultimately publish.
type QuotaLimiter interface {
	Allow(ctx context.Context, orgID int64, limit *int32) (bool, error)
	Refund(ctx context.Context, orgID int64, limit *int32) error
}

// OrgReader resolves an org's monthly_ingestion_limit (nil = unlimited).
type OrgReader interface {
	MonthlyLimit(ctx context.Context, orgID int64) (*int32, error)
}

// Publisher is the emails.raw Kafka producer. The concrete
// shared/kafka/producer.Producer satisfies it; narrowing to an interface keeps
// the core unit-testable without a live broker.
type Publisher interface {
	Publish(ctx context.Context, key, value []byte, retries int) error
}

// Core is the ingestion engine wired in svckit OnReady. It is safe for
// concurrent use (its collaborators are).
type Core struct {
	dedup    Deduper
	quota    QuotaLimiter
	orgs     OrgReader
	producer Publisher
	log      zerolog.Logger
	now      func() time.Time
}

// Config bundles Core's collaborators.
type Config struct {
	Dedup    Deduper
	Quota    QuotaLimiter
	Orgs     OrgReader
	Producer Publisher
	Log      zerolog.Logger
}

// NewCore builds a Core. Producer must be the emails.raw producer.
func NewCore(cfg Config) *Core {
	return &Core{
		dedup:    cfg.Dedup,
		quota:    cfg.Quota,
		orgs:     cfg.Orgs,
		producer: cfg.Producer,
		log:      cfg.Log,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// publishRetries is the extra kafka attempts after the first ProduceSync.
const publishRetries = 3

// Ingest runs the auth-bound ingestion path: dedup → quota → publish emails.raw.
// orgID and apiKeyID come from the authenticated API key (G10) — never from the
// request body. A duplicate or over-quota request is a terminal, non-error
// outcome (the caller renders 200/conflict or 429); only an infrastructure
// failure returns a non-nil error.
//
// Ordering and compensation matter for correctness:
//   - The dedup claim is taken FIRST so a retried/duplicate request consumes no
//     quota.
//   - The quota counter is incremented only AFTER a fresh claim; if the org is
//     over limit the claim is RELEASED (a 429'd request must not burn the dedup
//     window).
//   - On a publish failure the claim is RELEASED and the quota is REFUNDED, so
//     the client's retry actually re-publishes instead of being silently
//     swallowed as a "duplicate" for the full 7-day window.
//
// Releasing the claim on publish-failure means two concurrent identical
// requests can BOTH end up publishing. That is intended and safe: svc-02's
// RegisterEmailIdentity ON CONFLICT DO NOTHING dedups authoritatively, so the
// pipeline never double-persists. This is the documented at-least-once posture —
// we would rather emit a rare duplicate (deduped downstream) than drop a real
// email.
func (c *Core) Ingest(ctx context.Context, orgID, apiKeyID int64, req source.IngestRequest) (source.Outcome, error) {
	if orgID <= 0 {
		return source.Outcome{}, errors.New("ingest: orgID must come from the authenticated key")
	}
	if len(req.Raw) == 0 {
		return source.Outcome{}, errors.New("ingest: empty raw message")
	}

	// 1. Dedup claim FIRST. A duplicate is a terminal 200/conflict that consumes
	// no quota — do NOT republish. dedup fails open on infra errors (it returns
	// fresh=true rather than an error), so a non-nil error here is a real bug.
	fresh, err := c.dedup.Claim(ctx, orgID, req.MessageID)
	if err != nil {
		return source.Outcome{}, fmt.Errorf("dedup claim: %w", err)
	}
	if !fresh {
		c.log.Info().Int64("org_id", orgID).Str("message_id", req.MessageID).
			Msg("duplicate email suppressed (already seen within dedup window)")
		return source.Outcome{Status: source.StatusDuplicate}, nil
	}

	// 2. Monthly quota, AFTER the fresh claim. Over-limit is a terminal 429, not
	// an error — but the claim we just took must be released so a 429'd request
	// does not burn the dedup window.
	limit, err := c.orgs.MonthlyLimit(ctx, orgID)
	if err != nil {
		// Release the claim before bubbling the infra error so a retry is not
		// suppressed.
		c.releaseClaim(ctx, orgID, req.MessageID)
		return source.Outcome{}, fmt.Errorf("read org ingestion limit: %w", err)
	}
	allowed, err := c.quota.Allow(ctx, orgID, limit)
	if err != nil {
		// Allow already fails open and still returns true on a Valkey blip; a
		// returned error means it permitted the request but the cache hiccuped.
		c.log.Warn().Err(err).Int64("org_id", orgID).Msg("quota check degraded (fail-open)")
	}
	if !allowed {
		c.log.Info().Int64("org_id", orgID).Msg("monthly ingestion quota exceeded")
		c.releaseClaim(ctx, orgID, req.MessageID)
		return source.Outcome{Status: source.StatusQuotaExceeded}, nil
	}

	// 3. Assign the logical email_id (UUIDv7) and publish emails.raw.
	emailID, err := uuid.NewV7()
	if err != nil {
		c.releaseClaim(ctx, orgID, req.MessageID)
		c.refundQuota(ctx, orgID, limit)
		return source.Outcome{}, fmt.Errorf("generate email_id: %w", err)
	}
	emailIDStr := emailID.String()
	fetchedAt := c.now()

	adapterName := req.SourceAdapter
	if adapterName == "" {
		adapterName = "api"
	}

	payload := contracts.EmailsRaw{
		Meta:          contracts.NewMeta(emailIDStr, orgID),
		FetchedAt:     fetchedAt,
		SourceAdapter: adapterName,
		MessageID:     req.MessageID,
		RawMessageB64: base64.StdEncoding.EncodeToString(req.Raw),
		APIKeyID:      apiKeyID,
	}

	body, err := marshalEmailsRaw(payload)
	if err != nil {
		c.releaseClaim(ctx, orgID, req.MessageID)
		c.refundQuota(ctx, orgID, limit)
		return source.Outcome{}, err
	}
	if err := c.producer.Publish(ctx, []byte(emailIDStr), body, publishRetries); err != nil {
		// Compensate: drop the claim and refund the quota so the client's retry
		// re-publishes (see the method doc on the at-least-once posture).
		c.releaseClaim(ctx, orgID, req.MessageID)
		c.refundQuota(ctx, orgID, limit)
		return source.Outcome{}, fmt.Errorf("publish emails.raw: %w", err)
	}

	c.log.Info().
		Str("email_id", emailIDStr).
		Int64("org_id", orgID).
		Int64("api_key_id", apiKeyID).
		Str("source_adapter", adapterName).
		Str("message_id", req.MessageID).
		Msg("ingested email; published emails.raw")

	return source.Outcome{EmailID: emailIDStr, Status: source.StatusAccepted}, nil
}

// releaseClaim best-effort drops the dedup claim for a request that did not
// publish so the client's retry is not suppressed. The Deduper.Release itself is
// best-effort; we only log a surfaced error here.
func (c *Core) releaseClaim(ctx context.Context, orgID int64, messageID string) {
	if err := c.dedup.Release(ctx, orgID, messageID); err != nil {
		c.log.Warn().Err(err).Int64("org_id", orgID).Str("message_id", messageID).
			Msg("failed to release dedup claim after a non-published exit")
	}
}

// refundQuota best-effort decrements the month counter for a request that
// consumed quota but did not publish.
func (c *Core) refundQuota(ctx context.Context, orgID int64, limit *int32) {
	if err := c.quota.Refund(ctx, orgID, limit); err != nil {
		c.log.Warn().Err(err).Int64("org_id", orgID).
			Msg("failed to refund quota after a non-published exit")
	}
}
