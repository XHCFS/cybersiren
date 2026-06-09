package persist

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// pgtype conversion helpers. Each maps a Go zero/empty value to a NULL pgtype so
// the COALESCE-based UPDATE leaves the corresponding column untouched (a partial
// enricher must never clobber data another pass populated).

func pgText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

func pgInt8(v int64) pgtype.Int8 {
	if v == 0 {
		return pgtype.Int8{}
	}
	return pgtype.Int8{Int64: v, Valid: true}
}

func pgInt4(v int32) pgtype.Int4 {
	return pgtype.Int4{Int32: v, Valid: true}
}

func pgFloat8(v float64) pgtype.Float8 {
	return pgtype.Float8{Float64: v, Valid: true}
}

func pgTimestamptz(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}
