// Package pgconv holds the canonical Go-to-pgtype conversion helpers shared by
// the persistence layers of every service.
//
// Two families of helpers exist and they MUST NOT be confused:
//
//   - The always-valid variants (Text, Int8, Float8, Timestamptz) set Valid:true
//     unconditionally. Use them for INSERT params, where the zero value is a real
//     value that should be written verbatim.
//
//   - The *OrNull variants (Int8OrNull, Int4OrNull, TimestamptzOrNull) map the Go
//     zero value to a NULL pgtype (Valid:false). Use them for COALESCE-based
//     UPDATEs, where a zero/empty input must leave the existing column untouched so
//     a partial writer never clobbers data another pass populated.
package pgconv

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Text returns an always-valid pgtype.Text for INSERT params, mapping the empty
// string to NULL (callers null empty text by convention).
func Text(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

// Int8 returns an always-valid pgtype.Int8 for INSERT params, where the zero
// value is a real value to be written.
func Int8(v int64) pgtype.Int8 {
	return pgtype.Int8{Int64: v, Valid: true}
}

// Int4 returns an always-valid pgtype.Int4 for INSERT/unconditional-SET params,
// where the zero value is a real value to be written (e.g. a benign attachment's
// risk_score of 0 written by an UPDATE with no COALESCE — distinct from "unknown").
func Int4(v int32) pgtype.Int4 {
	return pgtype.Int4{Int32: v, Valid: true}
}

// Float8 returns an always-valid pgtype.Float8 for INSERT params, where the zero
// value is a real value to be written.
func Float8(v float64) pgtype.Float8 {
	return pgtype.Float8{Float64: v, Valid: true}
}

// Timestamptz returns an always-valid pgtype.Timestamptz for INSERT params,
// storing the instant in UTC.
func Timestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}

// Int8OrNull returns a pgtype.Int8 for COALESCE UPDATE params, mapping a zero
// input to NULL so the existing column value is preserved.
func Int8OrNull(v int64) pgtype.Int8 {
	if v == 0 {
		return pgtype.Int8{}
	}
	return pgtype.Int8{Int64: v, Valid: true}
}

// Int4OrNull returns a pgtype.Int4 for COALESCE UPDATE params, mapping a zero
// input to NULL so the existing column value is preserved.
func Int4OrNull(v int32) pgtype.Int4 {
	if v == 0 {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: v, Valid: true}
}

// TimestamptzOrNull returns a pgtype.Timestamptz for COALESCE UPDATE params,
// mapping the zero time to NULL so the existing column value is preserved;
// otherwise the instant is stored in UTC.
func TimestamptzOrNull(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}

// UUIDOrNull parses a canonical UUID string into a pgtype.UUID, mapping the
// empty string OR an unparseable value to NULL (Valid:false). Use it for an
// optional logical id (e.g. the UUIDv7 email_id stamped on email_identities):
// an absent / malformed id must not abort the write, it simply leaves the
// column NULL so the row is not resolvable by that id.
func UUIDOrNull(s string) pgtype.UUID {
	if s == "" {
		return pgtype.UUID{}
	}
	u, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: u, Valid: true}
}
