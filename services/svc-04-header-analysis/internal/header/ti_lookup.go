package header

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/saif/cybersiren/shared/normalization"
)

// TIIndicatorLookup is the Postgres fallback used when Valkey misses or fails.
type TIIndicatorLookup interface {
	LookupTIIndicator(ctx context.Context, indicatorType, value string) (bool, int, string, error)
}

type PostgresTIIndicatorLookup struct {
	pool *pgxpool.Pool
}

func NewPostgresTIIndicatorLookup(pool *pgxpool.Pool) *PostgresTIIndicatorLookup {
	return &PostgresTIIndicatorLookup{pool: pool}
}

func (l *PostgresTIIndicatorLookup) LookupTIIndicator(
	ctx context.Context,
	indicatorType string,
	value string,
) (bool, int, string, error) {
	if l == nil || l.pool == nil {
		return false, 0, "", errors.New("ti postgres lookup: no db pool")
	}

	const query = `
SELECT risk_score, COALESCE(threat_type, '')
FROM ti_indicators
WHERE indicator_type::text = $1
  AND indicator_value = $2
  AND is_active = TRUE
ORDER BY risk_score DESC, last_seen DESC NULLS LAST
LIMIT 1`

	var riskScore int
	var threatType string
	err := l.pool.QueryRow(ctx, query, indicatorType, value).Scan(&riskScore, &threatType)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, 0, "", nil
	}
	if err != nil {
		return false, 0, "", fmt.Errorf("query ti_indicators: %w", err)
	}
	return true, riskScore, threatType, nil
}

// FallbackTILookup checks Valkey first, then Postgres. Errors from both tiers
// are returned to the caller so SVC-04 can increment its ti_lookup error metric
// while still treating the message as "no TI match" per ARCH-SPEC §6.
type FallbackTILookup struct {
	valkey valkeygo.Client
	db     TIIndicatorLookup
	log    zerolog.Logger
}

func NewFallbackTILookup(valkey valkeygo.Client, db TIIndicatorLookup, log zerolog.Logger) *FallbackTILookup {
	return &FallbackTILookup{valkey: valkey, db: db, log: log}
}

func (l *FallbackTILookup) IsBlocklisted(ctx context.Context, value string) (bool, int, string, error) {
	indicatorType, normalized := normalizeTIValue(value)
	if normalized == "" {
		return false, 0, "", nil
	}

	if l != nil && l.valkey != nil {
		hit, score, threat, err := l.lookupValkey(ctx, normalized)
		if err != nil {
			l.log.Debug().Err(err).Str("indicator_type", indicatorType).Msg("ti Valkey lookup failed; falling back to Postgres")
		} else if hit {
			return true, score, threat, nil
		}
	}

	if l == nil || l.db == nil {
		return false, 0, "", nil
	}
	return l.db.LookupTIIndicator(ctx, indicatorType, normalized)
}

func (l *FallbackTILookup) lookupValkey(ctx context.Context, value string) (bool, int, string, error) {
	key := fmt.Sprintf("ti_domain:{%s}", value)
	cmd := l.valkey.Do(ctx, l.valkey.B().Hgetall().Key(key).Build())
	if err := cmd.Error(); err != nil {
		return false, 0, "", fmt.Errorf("ti valkey hgetall: %w", err)
	}
	result, err := cmd.AsStrMap()
	if err != nil {
		return false, 0, "", fmt.Errorf("ti valkey decode: %w", err)
	}
	if len(result) == 0 {
		return false, 0, "", nil
	}
	score := 0
	if raw := result["risk_score"]; raw != "" {
		score, err = strconv.Atoi(raw)
		if err != nil {
			return false, 0, "", fmt.Errorf("ti valkey risk_score: %w", err)
		}
	}
	return true, score, result["threat_type"], nil
}

func normalizeTIValue(value string) (indicatorType string, normalized string) {
	v := strings.TrimSpace(value)
	v = strings.TrimPrefix(strings.TrimSuffix(v, "]"), "[")
	if addr, err := netip.ParseAddr(v); err == nil {
		return "ip", addr.String()
	}
	return "domain", normalization.NormalizeDomain(value)
}
