package persist

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestInputValidate(t *testing.T) {
	t.Parallel()
	ok := Input{
		OrgID:       1,
		InternalID:  2,
		FetchedAt:   time.Now().UTC(),
		Fingerprint: "abc",
	}
	require.NoError(t, ok.validate())

	cases := []Input{
		{InternalID: 2, FetchedAt: time.Now().UTC(), Fingerprint: "abc"},
		{OrgID: 1, FetchedAt: time.Now().UTC(), Fingerprint: "abc"},
		{OrgID: 1, InternalID: 2, Fingerprint: "abc"},
		{OrgID: 1, InternalID: 2, FetchedAt: time.Now().UTC()},
	}
	for _, tc := range cases {
		require.Error(t, tc.validate())
	}
}

func TestBackoffDurationCapsAtFiveSeconds(t *testing.T) {
	t.Parallel()
	require.Equal(t, 100*time.Millisecond, backoffDuration(0))
	require.Equal(t, 200*time.Millisecond, backoffDuration(1))
	require.Equal(t, 400*time.Millisecond, backoffDuration(2))
	require.Equal(t, 5*time.Second, backoffDuration(99))
}

func TestNullableJSONBBytes(t *testing.T) {
	t.Parallel()
	require.Nil(t, nullableJSONBBytes(nil))
	require.Nil(t, nullableJSONBBytes([]byte{}))
	b := []byte(`{"x":1}`)
	require.Equal(t, b, nullableJSONBBytes(b))
}

func TestEmailCountToInt32(t *testing.T) {
	t.Parallel()
	require.Equal(t, int32(5), emailCountToInt32(int32(5)))
	require.Equal(t, int32(7), emailCountToInt32(int64(7)))
	require.Equal(t, int32(9), emailCountToInt32(9))
	require.Equal(t, int32(0), emailCountToInt32(nil))
	require.Equal(t, int32(0), emailCountToInt32("unexpected"))
}
