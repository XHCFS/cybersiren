package engine

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/saif/cybersiren/services/svc-08-decision/internal/persist"
)

func TestVerdictKafkaBody_PrefersStoredWire(t *testing.T) {
	t.Parallel()
	stored := json.RawMessage(`{"verdict_label":"benign","risk_score":12}`)
	body, err := verdictKafkaBody(persist.Output{
		KafkaVerdictWire: append([]byte(nil), stored...),
	}, func() ([]byte, error) {
		t.Fatal("fresh should not be called when stored wire exists")
		return nil, errors.New("unreachable")
	})
	require.NoError(t, err)
	require.JSONEq(t, string(stored), string(body))
}

func TestVerdictKafkaBody_FallbackFresh(t *testing.T) {
	t.Parallel()
	got, err := verdictKafkaBody(persist.Output{}, func() ([]byte, error) {
		return []byte(`{"x":1}`), nil
	})
	require.NoError(t, err)
	require.JSONEq(t, `{"x":1}`, string(got))
}
