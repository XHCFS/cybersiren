// svc-05 attachment-analysis is the Kafka-side binary for SVC-05 Attachment
// Analysis. Per attachment it resolves the attachment_library row by sha256
// (written by SVC-02), scores it via hash-based TI lookup + the ARCH-SPEC
// Step 3c heuristics, writes the per-attachment risk back to email_attachments,
// and publishes the per-email max as scores.attachment.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/services/svc-05-attachment-analysis/internal/analyzer"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-05-attachment-analysis"

var (
	dbPool  *pgxpool.Pool
	metrics *analyzer.Metrics
)

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsDB:        true,
		ProducerTopics: []string{contracts.TopicScoresAttachment},
		ConsumerTopics: []string{contracts.TopicAnalysisAttachments},
		GroupID:        contracts.GroupAttachmentAnalysis,
		OnReady: func(_ context.Context, deps svckit.Deps) error {
			dbPool = deps.Pool
			metrics = analyzer.NewMetrics(deps.Registry)
			deps.Log.Info().Msg("attachment analyzer ready")
			return nil
		},
		Handler: handle,
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

// attachmentResult is the per-attachment detail aggregated into scores.attachment.
type attachmentResult struct {
	Filename  string   `json:"filename"`
	SHA256    string   `json:"sha256,omitempty"`
	Score     int      `json:"score"`
	Reasons   []string `json:"reasons,omitempty"`
	Malicious bool     `json:"malicious"`
}

func handle(ctx context.Context, msg kafkaconsumer.Message, deps svckit.Deps) error {
	var input contracts.AnalysisAttachments
	if err := json.Unmarshal(msg.Value, &input); err != nil {
		return fmt.Errorf("decode analysis.attachments: %w", err)
	}

	log := zerolog.Ctx(ctx).With().Int64("email_id", input.Meta.EmailID).Logger()
	ft := input.Meta.FetchedAt
	if ft.IsZero() {
		ft = time.Now().UTC()
	}

	maxScore := 0
	results := make([]attachmentResult, 0, len(input.Attachments))
	for _, att := range input.Attachments {
		r := scoreAttachment(ctx, input.Meta, ft, att, log)
		results = append(results, r)
		if r.Score > maxScore {
			maxScore = r.Score
		}
	}

	out := contracts.ScoreEnvelope{
		Meta:      contracts.NewMetaWithFetched(input.Meta.EmailID, input.Meta.OrgID, ft),
		Component: contracts.ComponentAttachment,
		Score:     float64(maxScore),
		Details: map[string]interface{}{
			"attachments_total": len(input.Attachments),
			"per_attachment":    results,
		},
	}

	body, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshal scores.attachment: %w", err)
	}
	prod, ok := deps.Producers[contracts.TopicScoresAttachment]
	if !ok {
		return fmt.Errorf("svc-05: producer for %s not configured", contracts.TopicScoresAttachment)
	}
	if err := prod.Publish(ctx, []byte(strconv.FormatInt(input.Meta.EmailID, 10)), body, 1); err != nil { // +1 kafka retry
		return fmt.Errorf("publish scores.attachment: %w", err)
	}

	log.Info().
		Int("attachments", len(input.Attachments)).
		Int("max_score", maxScore).
		Msg("scored attachments")
	return nil
}

// scoreAttachment resolves the library row, scores the attachment, and writes
// the score back to email_attachments (best-effort: a DB failure is logged +
// metered but never blocks scores.attachment). On a library miss it scores on
// the wire metadata alone (no entropy / malicious signal).
func scoreAttachment(
	ctx context.Context,
	meta contracts.MessageMeta,
	fetchedAt time.Time,
	att contracts.Attachment,
	log zerolog.Logger,
) attachmentResult {
	in := analyzer.Attachment{
		Filename:    att.Filename,
		ContentType: att.ContentType,
		SHA256:      att.SHA256,
		SizeBytes:   att.SizeBytes,
	}

	var (
		attachmentID int64
		haveID       bool
	)
	if dbPool != nil && att.SHA256 != "" {
		row, err := dbsqlc.New(dbPool).GetAttachmentBySHA256(ctx, att.SHA256)
		if err != nil {
			log.Warn().Err(err).Str("sha256", att.SHA256).Msg("attachment_library lookup failed; scoring on metadata only")
		} else {
			attachmentID, haveID = row.ID, true
			in.IsMalicious = row.IsMalicious.Bool
			in.Entropy = row.Entropy.Float64
			in.ActualExtension = row.ActualExtension.String
		}
	}

	res := analyzer.Score(in)

	switch {
	case in.IsMalicious:
		metrics.IncScore("malicious")
	case res.Score > 0:
		metrics.IncScore("heuristic")
	default:
		metrics.IncScore("clean")
	}
	for _, r := range res.Reasons {
		metrics.IncHeuristic(r)
	}

	if haveID && dbPool != nil {
		err := dbsqlc.New(dbPool).UpdateEmailAttachmentRiskScore(ctx, dbsqlc.UpdateEmailAttachmentRiskScoreParams{
			EmailID:        meta.EmailID,
			EmailFetchedAt: pgtype.Timestamptz{Time: fetchedAt, Valid: !fetchedAt.IsZero()},
			AttachmentID:   attachmentID,
			RiskScore:      pgtype.Int4{Int32: int32(res.Score), Valid: true},
		})
		if err != nil {
			metrics.IncPersistError()
			log.Warn().Err(err).Int64("attachment_id", attachmentID).Msg("email_attachments risk_score writeback failed")
		}
	}

	return attachmentResult{
		Filename:  att.Filename,
		SHA256:    att.SHA256,
		Score:     res.Score,
		Reasons:   res.Reasons,
		Malicious: in.IsMalicious,
	}
}
