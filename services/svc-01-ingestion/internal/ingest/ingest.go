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

// Deduper is the (org, message_id) dedup gate (internal/dedup).
type Deduper interface {
	Claim(ctx context.Context, orgID int64, messageID string) (bool, error)
}

// QuotaLimiter enforces the monthly ingestion quota (internal/quota).
type QuotaLimiter interface {
	Allow(ctx context.Context, orgID int64, limit *int32) (bool, error)
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

// Ingest runs the auth-bound ingestion path: quota → dedup → publish emails.raw.
// orgID and apiKeyID come from the authenticated API key (G10) — never from the
// request body. A duplicate or over-quota request is a terminal, non-error
// outcome (the caller renders 200/conflict or 429); only an infrastructure
// failure returns a non-nil error.
func (c *Core) Ingest(ctx context.Context, orgID, apiKeyID int64, req source.IngestRequest) (source.Outcome, error) {
	if orgID <= 0 {
		return source.Outcome{}, errors.New("ingest: orgID must come from the authenticated key")
	}
	if len(req.Raw) == 0 {
		return source.Outcome{}, errors.New("ingest: empty raw message")
	}

	// 1. Monthly quota. Over-limit is a terminal 429, not an error.
	limit, err := c.orgs.MonthlyLimit(ctx, orgID)
	if err != nil {
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
		return source.Outcome{Status: source.StatusQuotaExceeded}, nil
	}

	// 2. Dedup. A duplicate is a terminal 200/conflict — do NOT republish.
	fresh, err := c.dedup.Claim(ctx, orgID, req.MessageID)
	if err != nil {
		return source.Outcome{}, fmt.Errorf("dedup claim: %w", err)
	}
	if !fresh {
		c.log.Info().Int64("org_id", orgID).Str("message_id", req.MessageID).
			Msg("duplicate email suppressed (already seen within dedup window)")
		return source.Outcome{Status: source.StatusDuplicate}, nil
	}

	// 3. Assign the logical email_id (UUIDv7) and publish emails.raw.
	emailID, err := uuid.NewV7()
	if err != nil {
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
		return source.Outcome{}, err
	}
	if err := c.producer.Publish(ctx, []byte(emailIDStr), body, publishRetries); err != nil {
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
