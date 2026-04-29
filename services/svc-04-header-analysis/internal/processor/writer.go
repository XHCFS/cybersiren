package processor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/rules"
)

// RuleHitWriter inserts every fired rule into rule_hits inside a single
// transaction. ARCH-SPEC §6 mandates retry-with-backoff up to N attempts;
// a failure to write must NOT acknowledge the Kafka offset.
type RuleHitWriter struct {
	pool       *pgxpool.Pool
	maxRetries int
	log        zerolog.Logger
}

// NewRuleHitWriter constructs a RuleHitWriter. maxRetries < 0 is clamped to 0.
func NewRuleHitWriter(pool *pgxpool.Pool, maxRetries int, log zerolog.Logger) *RuleHitWriter {
	if maxRetries < 0 {
		maxRetries = 0
	}
	return &RuleHitWriter{pool: pool, maxRetries: maxRetries, log: log}
}

// Write persists fired rules for a single email atomically. When fired
// is empty, no transaction is opened. Returns nil on success.
//
// rule_hits is an append-only audit log and the schema intentionally does not
// dedupe (rule_id, entity_type, entity_id, rule_version); duplicate upstream
// deliveries create duplicate history rows.
//
// emailInternalID corresponds to emails.internal_id (BIGINT). See
// shared/contracts/kafka.AnalysisHeadersMessage.EmailID and
// ARCH-SPEC §14 step 3b.
func (w *RuleHitWriter) Write(ctx context.Context, emailInternalID int64, fired []rules.FiredRule) (retryOutcome string, err error) {
	if w == nil || w.pool == nil {
		return "exhausted", errors.New("rule_hits writer: not initialised")
	}
	if len(fired) == 0 {
		return "ok", nil
	}

	attempts := w.maxRetries + 1
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return "exhausted", err
		}

		err := w.runOnce(ctx, emailInternalID, fired)
		if err == nil {
			return "ok", nil
		}
		lastErr = err
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "exhausted", err
		}

		backoff := backoffDuration(attempt)
		w.log.Warn().
			Err(err).
			Int("attempt", attempt+1).
			Int("max_attempts", attempts).
			Dur("backoff", backoff).
			Int64("email_internal_id", emailInternalID).
			Int("fired_rules", len(fired)).
			Msg("rule_hits transaction failed; retrying")

		select {
		case <-ctx.Done():
			return "exhausted", ctx.Err()
		case <-time.After(backoff):
		}
	}

	return "exhausted", lastErr
}

func (w *RuleHitWriter) runOnce(ctx context.Context, emailInternalID int64, fired []rules.FiredRule) error {
	tx, err := w.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin rule_hits tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	q := dbsqlc.New(tx)

	for _, fr := range fired {
		_, err := q.InsertRuleHit(ctx, dbsqlc.InsertRuleHitParams{
			RuleID:      pgtype.Int8{Int64: fr.Rule.ID, Valid: true},
			RuleVersion: fr.Rule.Version,
			EntityType:  dbsqlc.EntityTypeEnumEmail,
			EntityID:    emailInternalID,
			ScoreImpact: int32(fr.Rule.ScoreImpact),
			MatchDetail: fr.MatchDetail,
		})
		if err != nil {
			return fmt.Errorf("insert rule_hit (rule_id=%d): %w", fr.Rule.ID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit rule_hits tx: %w", err)
	}
	return nil
}

func backoffDuration(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := 100 * time.Millisecond
	for i := 0; i < attempt; i++ {
		d *= 2
		if d > 5*time.Second {
			d = 5 * time.Second
			break
		}
	}
	return d
}
