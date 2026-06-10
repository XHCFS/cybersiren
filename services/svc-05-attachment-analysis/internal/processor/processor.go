// Package processor is SVC-05's per-message orchestrator: it consumes
// analysis.attachments, scores each attachment (hash lookup → VirusTotal →
// heuristics), takes the per-email MAX, writes the verdict back to
// attachment_library + email_attachments, and publishes the typed
// scores.attachment payload (ARCH-SPEC §1 step 3c, §15 gap #2).
package processor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/saif/cybersiren/services/svc-05-attachment-analysis/internal/scoring"
	"github.com/saif/cybersiren/services/svc-05-attachment-analysis/internal/store"
	"github.com/saif/cybersiren/services/svc-05-attachment-analysis/internal/vt"
	contractsk "github.com/saif/cybersiren/shared/contracts/kafka"
	sharedconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/observability/tracing"
)

// vtLookup is the slice of the VirusTotal client the processor depends on,
// declared as an interface so the handler is unit-testable with a fake.
type vtLookup interface {
	Enabled() bool
	Lookup(ctx context.Context, sha256 string) (vt.Result, error)
}

// publisher is the slice of the Kafka producer the processor depends on,
// declared as an interface so the handler is unit-testable with a fake. The
// shared producer (*kafka/producer.Producer) satisfies it.
type publisher interface {
	Publish(ctx context.Context, key, value []byte, retries int) error
}

// Config wires the processor's runtime parameters.
type Config struct {
	Scoring              scoring.Config
	VTCacheTTL           time.Duration
	PublishRetryAttempts int
}

// Processor scores each email's attachments and publishes scores.attachment.
type Processor struct {
	cfg      Config
	store    store.Store
	vt       vtLookup
	producer publisher
	metrics  *Metrics
	log      zerolog.Logger
	tracer   trace.Tracer
}

// New constructs a Processor.
func New(
	cfg Config,
	st store.Store,
	vtClient vtLookup,
	producer publisher,
	metrics *Metrics,
	log zerolog.Logger,
) *Processor {
	return &Processor{
		cfg:      cfg,
		store:    st,
		vt:       vtClient,
		producer: producer,
		metrics:  metrics,
		log:      log,
		tracer:   tracing.Tracer("svc-05-attachment-analysis"),
	}
}

// Handle is the Kafka consumer Handler. A non-nil return leaves the offset
// uncommitted (the message is redelivered).
func (p *Processor) Handle(ctx context.Context, msg sharedconsumer.Message) error {
	startedAt := time.Now()
	defer func() {
		if p.metrics != nil {
			p.metrics.Duration.Observe(time.Since(startedAt).Seconds())
		}
	}()

	ctx, span := p.tracer.Start(ctx, "attachment.process",
		trace.WithAttributes(
			attribute.Int("messaging.kafka.partition", msg.Partition),
			attribute.Int64("messaging.kafka.offset", msg.Offset),
		),
	)
	defer span.End()

	parsed, err := decodeMessage(msg.Value)
	if err != nil {
		// Malformed message: commit the offset (redelivery yields the same
		// failure forever and wedges the partition).
		p.metrics.incError("consume")
		span.RecordError(err)
		span.SetStatus(codes.Error, "decode failed")
		p.log.Error().Err(err).
			Int("partition", msg.Partition).
			Int64("offset", msg.Offset).
			Msg("malformed analysis.attachments message; skipping")
		p.markMessage("error")
		return nil
	}

	emailID := parsed.Meta.EmailID
	orgID := parsed.Meta.OrgID
	internalID := internalIDOf(parsed)
	span.SetAttributes(
		attribute.Int64("email_id", emailID),
		attribute.Int64("org_id", orgID),
		attribute.Int("attachment_count", len(parsed.Attachments)),
	)

	logCtx := p.log.With().
		Int64("email_id", emailID).
		Int64("org_id", orgID).
		Logger()
	if sc := msg.SpanContext; sc.IsValid() {
		logCtx = logCtx.With().Str("trace_id", sc.TraceID().String()).Logger()
	}

	details := make([]contractsk.AttachmentDetail, 0, len(parsed.Attachments))
	maxScore := 0
	maliciousCount := 0

	for i := range parsed.Attachments {
		att := parsed.Attachments[i]
		detail, writeErr := p.scoreOne(ctx, orgID, internalID, parsed.Meta.FetchedAt, att)
		if writeErr != nil {
			// A DB-write failure is a real persistence error: NACK so the
			// message redelivers rather than silently dropping the verdict.
			p.metrics.incError("db_write")
			span.RecordError(writeErr)
			span.SetStatus(codes.Error, "attachment write failed")
			logCtx.Error().Err(writeErr).
				Str("sha256", att.SHA256).
				Str("filename", att.Filename).
				Msg("attachment persistence failed; offset will NOT be committed")
			p.markMessage("error")
			return writeErr
		}
		details = append(details, detail)
		if detail.IndividualScore > maxScore {
			maxScore = detail.IndividualScore
		}
		if detail.IsMalicious {
			maliciousCount++
		}
	}

	out := contractsk.ScoresAttachment{
		Meta:              contractsk.NewMetaWithFetched(emailID, orgID, parsed.Meta.FetchedAt),
		Component:         contractsk.ComponentAttachment,
		Score:             maxScore,
		AttachmentCount:   len(parsed.Attachments),
		MaliciousCount:    maliciousCount,
		AttachmentDetails: details,
		ProcessingTimeMs:  int(time.Since(startedAt).Milliseconds()),
	}
	if vErr := out.Validate(); vErr != nil {
		// Should never happen (scores are clamped), but never publish an
		// out-of-range composite.
		p.metrics.incError("publish")
		span.RecordError(vErr)
		span.SetStatus(codes.Error, "score out of range")
		logCtx.Error().Err(vErr).Int("score", maxScore).Msg("computed score out of range")
		p.markMessage("error")
		return fmt.Errorf("validate scores.attachment: %w", vErr)
	}

	body, err := json.Marshal(out)
	if err != nil {
		p.metrics.incError("publish")
		span.RecordError(err)
		span.SetStatus(codes.Error, "marshal failed")
		logCtx.Error().Err(err).Msg("marshal scores.attachment failed")
		p.markMessage("error")
		return fmt.Errorf("marshal scores.attachment: %w", err)
	}

	if err := p.producer.Publish(ctx, encodeKey(emailID), body, p.cfg.PublishRetryAttempts); err != nil {
		p.metrics.incError("publish")
		span.RecordError(err)
		span.SetStatus(codes.Error, "publish failed")
		logCtx.Error().Err(err).Msg("publish scores.attachment failed")
		p.markMessage("error")
		return fmt.Errorf("publish scores.attachment: %w", err)
	}

	p.markMessage("ok")
	if p.metrics != nil {
		p.metrics.ScoreTotal.WithLabelValues(ScoreBucket(maxScore)).Inc()
	}

	logCtx.Info().
		Int("score", maxScore).
		Int("attachment_count", len(parsed.Attachments)).
		Int("malicious_count", maliciousCount).
		Int64("duration_ms", time.Since(startedAt).Milliseconds()).
		Msg("attachment analysis complete")

	span.SetAttributes(
		attribute.Int("score", maxScore),
		attribute.Int("malicious_count", maliciousCount),
	)
	span.SetStatus(codes.Ok, "")
	return nil
}

// scoreOne scores a single attachment and persists its verdict. It returns the
// per-attachment detail for the scores.attachment payload. A returned error is a
// DB-write failure (the caller NACKs); VT / hash-lookup READ failures degrade to
// "no signal" and never error so a transient enrichment hiccup doesn't wedge the
// partition.
func (p *Processor) scoreOne(
	ctx context.Context,
	orgID, internalID int64,
	fetchedAt time.Time,
	att contractsk.Attachment,
) (contractsk.AttachmentDetail, error) {
	detail := contractsk.AttachmentDetail{
		SHA256:      att.SHA256,
		Filename:    att.Filename,
		ContentType: att.ContentType,
		SizeBytes:   att.SizeBytes,
		Entropy:     att.Entropy,
	}

	// (1) Hash lookup against attachment_library (READ). A miss / read error is
	// non-fatal — heuristics still run.
	var libraryID int64
	hashMalicious := false
	if att.SHA256 != "" && p.store != nil && orgID > 0 {
		verdict, err := p.store.GetHashVerdict(ctx, orgID, att.SHA256)
		switch {
		case err != nil:
			p.metrics.incError("hash_lookup")
			p.log.Warn().Err(err).Str("sha256", att.SHA256).Msg("attachment hash lookup failed; continuing with heuristics")
		case verdict.Found:
			libraryID = verdict.ID
			hashMalicious = verdict.IsMalicious
			if verdict.IsMalicious {
				detail.TISource = strPtr("attachment_library")
			}
		}
	}

	// (2) VirusTotal: cache-first, then API (24h cache). Skipped when no key
	// (never errors), 429 fail-open, or the library id is unknown (no cache key).
	//
	// The libraryID>0 gate is an intentional, sound narrowing of spec
	// §1-step3c(ii) ("query if a VT key is configured"): SVC-02 always UPSERTs
	// the attachment_library row at parse time (email_attachments.attachment_id
	// is an FK to it), so every real pipeline attachment HAS a libraryID and the
	// gate is satisfied. We require it because the VT cache (GetFreshVT/CacheVT)
	// is keyed on the library id — with no row there is no cache key, so a lookup
	// could neither be cached nor deduped. A zero libraryID only occurs for a
	// hash-miss synthetic path that never reaches a real attachment.
	vtMalicious := false
	if p.store != nil && p.vt != nil && p.vt.Enabled() && libraryID > 0 && att.SHA256 != "" && orgID > 0 {
		vtRes := p.lookupVT(ctx, orgID, libraryID, fetchedAt, att.SHA256)
		if vtRes.Malicious() {
			vtMalicious = true
			if detail.TISource == nil {
				detail.TISource = strPtr("virustotal")
			}
		}
	}

	// (3) Heuristics + score combiner.
	res := scoring.Score(scoring.Attachment{
		SHA256:          att.SHA256,
		Filename:        att.Filename,
		ContentType:     att.ContentType,
		DetectedType:    att.DetectedType,
		SizeBytes:       att.SizeBytes,
		Entropy:         att.Entropy,
		HashIsMalicious: hashMalicious,
		VTMalicious:     vtMalicious,
	}, p.cfg.Scoring)

	p.observeHeuristics(res.Heuristics)

	detail.IsMalicious = res.Malicious
	detail.ExtensionMismatch = res.Heuristics.ExtensionMismatch
	detail.HasMacros = res.Heuristics.HasMacros
	detail.IsDangerousExtension = res.Heuristics.IsDangerousExtension
	detail.IndividualScore = res.Score

	// (4) Persist. attachment_library malware flag (only when malicious — the
	// UPSERT forces is_malicious=true) + email_attachments.risk_score write-back.
	if p.store != nil && orgID > 0 {
		if res.Malicious {
			if err := p.store.FlagMalicious(ctx, orgID, att.SHA256, res.Score, threatTagsFor(res, att)); err != nil {
				return detail, fmt.Errorf("flag malicious (sha256=%s): %w", att.SHA256, err)
			}
		}
		if libraryID > 0 && internalID > 0 {
			meta := buildAnalysisMetadata(att, res)
			affected, err := p.store.UpdateEmailAttachmentScore(ctx, store.EmailAttachmentScore{
				OrgID:            orgID,
				InternalID:       internalID,
				FetchedAt:        fetchedAt,
				AttachmentID:     libraryID,
				RiskScore:        res.Score,
				AnalysisMetadata: meta,
			})
			if err != nil {
				return detail, fmt.Errorf("update email_attachment risk_score (sha256=%s): %w", att.SHA256, err)
			}
			if affected == 0 {
				// SVC-02 has not (yet) persisted this link, or the id mismatched.
				// Not fatal: the scores.attachment payload still flows; log AND
				// count so a systematic write-back miss is visible on dashboards
				// (attachment_analysis_errors_total{stage="writeback_miss"})
				// rather than discoverable only by log-grep.
				p.metrics.incError("writeback_miss")
				p.log.Warn().
					Int64("internal_id", internalID).
					Int64("attachment_id", libraryID).
					Str("sha256", att.SHA256).
					Msg("email_attachments risk_score update matched 0 rows (link not yet persisted)")
			}
		}
	}

	return detail, nil
}

// lookupVT reads the 24h cache, falling back to the VT API on a miss and caching
// the fresh result. All failures degrade to a Skipped result (no error) so VT
// never blocks scoring.
func (p *Processor) lookupVT(ctx context.Context, orgID, libraryID int64, fetchedAt time.Time, sha256 string) vt.Result {
	cached, err := p.store.GetFreshVT(ctx, orgID, libraryID)
	if err != nil {
		p.metrics.incVT("error")
		p.log.Warn().Err(err).Str("sha256", sha256).Msg("vt cache read failed; querying VT")
	} else if cached.Found {
		p.metrics.incVT("cached")
		return vt.Result{
			MaliciousVotes:  cached.MaliciousVotes,
			SuspiciousVotes: cached.SuspiciousVotes,
			HarmlessVotes:   cached.HarmlessVotes,
			Raw:             cached.Raw,
		}
	}

	res, err := p.vt.Lookup(ctx, sha256)
	if err != nil {
		// Soft miss (transport / decode / auth). Fail-open: no signal, no NACK.
		p.metrics.incVT("error")
		p.log.Warn().Err(err).Str("sha256", sha256).Msg("vt lookup failed; treating as no signal")
		return vt.Result{Skipped: true}
	}
	if res.Skipped {
		// No key, 429, or unknown hash.
		p.metrics.incVT("skipped")
		return res
	}

	p.metrics.incVT("hit")
	// Cache the fresh result for 24h. A cache-write failure must not lose the
	// verdict — log and proceed.
	if cacheErr := p.store.CacheVT(ctx, orgID, libraryID, fetchedAt, store.VTCacheInput{
		MaliciousVotes:  res.MaliciousVotes,
		SuspiciousVotes: res.SuspiciousVotes,
		HarmlessVotes:   res.HarmlessVotes,
		Raw:             res.Raw,
	}, p.cfg.VTCacheTTL); cacheErr != nil {
		p.metrics.incError("vt")
		p.log.Warn().Err(cacheErr).Str("sha256", sha256).Msg("vt cache write failed")
	}
	return res
}

func (p *Processor) observeHeuristics(h scoring.Heuristics) {
	if h.HighEntropy {
		p.metrics.incHeuristic("entropy")
	}
	if h.ExtensionMismatch {
		p.metrics.incHeuristic("ext_mismatch")
	}
	if h.IsDangerousExtension {
		p.metrics.incHeuristic("dangerous_ext")
	}
	if h.HasMacros {
		p.metrics.incHeuristic("macro")
	}
	if h.DoubleExtension {
		p.metrics.incHeuristic("double_ext")
	}
}

func (p *Processor) markMessage(result string) {
	if p.metrics == nil || p.metrics.MessagesTotal == nil {
		return
	}
	p.metrics.MessagesTotal.WithLabelValues(result).Inc()
}

// decodeMessage parses and validates an analysis.attachments payload. An email
// with zero attachments is valid (SVC-05 still emits a neutral score so SVC-07's
// 5-component aggregation completes).
func decodeMessage(body []byte) (contractsk.AnalysisAttachments, error) {
	var out contractsk.AnalysisAttachments
	if len(body) == 0 {
		return out, errors.New("empty kafka payload")
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("unmarshal analysis.attachments: %w", err)
	}
	if out.Meta.EmailID <= 0 {
		return out, fmt.Errorf("analysis.attachments email_id must be > 0, got %d", out.Meta.EmailID)
	}
	return out, nil
}

// internalIDOf returns the DB surrogate id used to address email_attachments
// rows. Two-id model (G17): the parser writes email_attachments.email_id =
// emails.internal_id (the DB BIGSERIAL), which is distinct from the logical
// Meta.EmailID. SVC-02 stamps that internal_id on analysis.attachments, so we
// prefer it; we fall back to Meta.EmailID only while SVC-02 has not yet
// populated it (mirrors SVC-03's url-pipeline/main.go pattern). We do NOT
// re-derive internal_id via a DB lookup.
func internalIDOf(parsed contractsk.AnalysisAttachments) int64 {
	if parsed.InternalID != 0 {
		return parsed.InternalID
	}
	return parsed.Meta.EmailID
}

func encodeKey(emailID int64) []byte {
	return []byte(strconv.FormatInt(emailID, 10))
}

func strPtr(s string) *string { return &s }

// threatTagsFor builds the attachment_library.threat_tags set for a malicious
// verdict: the source that flagged it plus any fired heuristic labels.
func threatTagsFor(res scoring.Result, att contractsk.Attachment) []string {
	tags := make([]string, 0, 4)
	if att.SHA256 != "" {
		tags = append(tags, "malware")
	}
	if res.Heuristics.HasMacros {
		tags = append(tags, "macro")
	}
	if res.Heuristics.IsDangerousExtension {
		tags = append(tags, "dangerous-extension")
	}
	if res.Heuristics.DoubleExtension {
		tags = append(tags, "double-extension")
	}
	return tags
}

// buildAnalysisMetadata serialises the per-attachment signal trail into the
// email_attachments.analysis_metadata JSONB blob. Returns nil on a marshal error
// so the COALESCE UPDATE leaves the column unchanged.
func buildAnalysisMetadata(att contractsk.Attachment, res scoring.Result) []byte {
	meta := map[string]any{
		"source":       "svc-05-attachment-analysis",
		"score":        res.Score,
		"is_malicious": res.Malicious,
		"heuristics": map[string]bool{
			"high_entropy":           res.Heuristics.HighEntropy,
			"extension_mismatch":     res.Heuristics.ExtensionMismatch,
			"is_dangerous_extension": res.Heuristics.IsDangerousExtension,
			"has_macros":             res.Heuristics.HasMacros,
			"double_extension":       res.Heuristics.DoubleExtension,
		},
		"entropy": att.Entropy,
	}
	if att.ContentType != "" {
		meta["content_type"] = att.ContentType
	}
	if att.DetectedType != "" {
		meta["detected_type"] = att.DetectedType
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return nil
	}
	return b
}
