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

func TestNullableJSONB(t *testing.T) {
	t.Parallel()
	require.Nil(t, nullableJSONB(nil))
	require.Nil(t, nullableJSONB([]byte{}))
	b := []byte(`{"x":1}`)
	require.Equal(t, b, nullableJSONB(b))
}
