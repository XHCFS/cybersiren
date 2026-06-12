package pgconv

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
)

func TestText(t *testing.T) {
	assert.Equal(t, pgtype.Text{}, Text(""), "empty string maps to NULL")
	assert.Equal(t, pgtype.Text{String: "x", Valid: true}, Text("x"))
}

func TestInt8AlwaysValid(t *testing.T) {
	// INSERT variant: zero is a real value and stays Valid.
	got := Int8(0)
	assert.True(t, got.Valid)
	assert.Equal(t, int64(0), got.Int64)

	assert.Equal(t, pgtype.Int8{Int64: 42, Valid: true}, Int8(42))
}

func TestFloat8AlwaysValid(t *testing.T) {
	got := Float8(0)
	assert.True(t, got.Valid)
	assert.Equal(t, float64(0), got.Float64)

	assert.Equal(t, pgtype.Float8{Float64: 1.5, Valid: true}, Float8(1.5))
}

func TestTimestamptzAlwaysValid(t *testing.T) {
	// INSERT variant: even the zero time is Valid.
	got := Timestamptz(time.Time{})
	assert.True(t, got.Valid)

	in := time.Date(2026, 6, 9, 12, 0, 0, 0, time.FixedZone("EET", 2*60*60))
	out := Timestamptz(in)
	assert.True(t, out.Valid)
	assert.Equal(t, in.UTC(), out.Time, "stored in UTC")
	assert.Equal(t, time.UTC, out.Time.Location())
}

func TestInt8OrNull(t *testing.T) {
	// COALESCE-UPDATE variant: zero maps to NULL, diverging from Int8(0).
	assert.Equal(t, pgtype.Int8{}, Int8OrNull(0))
	assert.False(t, Int8OrNull(0).Valid)
	assert.True(t, Int8(0).Valid, "Int8(0) stays Valid while Int8OrNull(0) is NULL")

	assert.Equal(t, pgtype.Int8{Int64: 7, Valid: true}, Int8OrNull(7))
}

func TestInt4OrNull(t *testing.T) {
	assert.Equal(t, pgtype.Int4{}, Int4OrNull(0))
	assert.False(t, Int4OrNull(0).Valid)
	assert.Equal(t, pgtype.Int4{Int32: 88, Valid: true}, Int4OrNull(88))
}

func TestTimestamptzOrNull(t *testing.T) {
	// COALESCE-UPDATE variant: zero time maps to NULL, diverging from Timestamptz(zero).
	assert.Equal(t, pgtype.Timestamptz{}, TimestamptzOrNull(time.Time{}))
	assert.False(t, TimestamptzOrNull(time.Time{}).Valid)
	assert.True(t, Timestamptz(time.Time{}).Valid, "Timestamptz(zero) Valid while TimestamptzOrNull(zero) is NULL")

	in := time.Date(2026, 6, 9, 12, 0, 0, 0, time.FixedZone("EET", 2*60*60))
	out := TimestamptzOrNull(in)
	assert.True(t, out.Valid)
	assert.Equal(t, in.UTC(), out.Time, "non-zero stored in UTC")
	assert.Equal(t, time.UTC, out.Time.Location())
}

func TestUUIDOrNull(t *testing.T) {
	// Empty / malformed map to NULL so an absent logical id never aborts a write.
	assert.Equal(t, pgtype.UUID{}, UUIDOrNull(""))
	assert.False(t, UUIDOrNull("").Valid)
	assert.False(t, UUIDOrNull("not-a-uuid").Valid, "unparseable maps to NULL, not an error")

	const raw = "018f3a2b-7c1d-7e2a-9b4c-0123456789ab"
	got := UUIDOrNull(raw)
	assert.True(t, got.Valid)
	u, err := uuid.Parse(raw)
	assert.NoError(t, err)
	assert.Equal(t, [16]byte(u), got.Bytes, "bytes round-trip the canonical UUID")
}
