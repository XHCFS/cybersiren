// STUB: replace with real implementation. Consumes emails.verdict for the
// future WebSocket feed (not wired in v0) and exposes /healthz on metrics
// port. Existing internal/handlers/* remain unwired in v0.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/rs/zerolog"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-10-api-dashboard"

// ringSize bounds the in-memory verdict buffer until the WebSocket feed lands.
const ringSize = 64

var (
	ringMu sync.Mutex
	ring   []contracts.EmailsVerdict
)

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsDB:        true,
		ConsumerTopics: []string{contracts.TopicEmailsVerdict},
		GroupID:        contracts.GroupDashboard,
		Handler:        handle,
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

func handle(ctx context.Context, msg kafkaconsumer.Message, _ svckit.Deps) error {
	var v contracts.EmailsVerdict
	if err := json.Unmarshal(msg.Value, &v); err != nil {
		return fmt.Errorf("decode verdict: %w", err)
	}

	ringMu.Lock()
	ring = append(ring, v)
	if len(ring) > ringSize {
		ring = ring[len(ring)-ringSize:]
	}
	ringMu.Unlock()

	zerolog.Ctx(ctx).Info().
		Int64("email_id", v.Meta.EmailID).
		Str("verdict", v.VerdictLabel).
		Msg("dashboard buffered verdict")
	return nil
}
