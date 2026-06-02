// svc-10-api-dashboard serves the dashboard REST API (Gin) and consumes
// emails.verdict into an in-memory ring that backs the recent-verdicts feed.
// The HTTP server and the Kafka consumer run together under svckit.Run.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/rs/zerolog"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
	apidashboard "github.com/saif/cybersiren/services/svc-10-api-dashboard/internal"
	"github.com/saif/cybersiren/shared/auth"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/svckit"
)

const (
	serviceName = "svc-10-api-dashboard"
	httpPort    = 8080
	ringSize    = 64
)

var (
	ringMu sync.Mutex
	ring   []contracts.EmailsVerdict
)

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsDB:        true,
		NeedsValkey:    true,
		ConsumerTopics: []string{contracts.TopicEmailsVerdict},
		GroupID:        contracts.GroupDashboard,
		HTTPPort:       httpPort,
		HTTPRoutes: func(mux *http.ServeMux, deps svckit.Deps) {
			authn := auth.New(dbsqlc.New(deps.Pool), deps.Cfg.Auth)
			engine := apidashboard.NewRouter(deps.Pool, deps.Valkey, authn, recentVerdicts, nil, deps.Log)
			mux.Handle("/", engine)
			deps.Log.Info().Int("port", httpPort).Msg("dashboard API ready")
		},
		Handler: handle,
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

// handle buffers each verdict into the bounded ring for the recent-verdicts feed.
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

	zerolog.Ctx(ctx).Info().Int64("email_id", v.Meta.EmailID).Str("verdict", v.VerdictLabel).Msg("buffered verdict")
	return nil
}

// recentVerdicts returns a newest-first copy of the verdict ring.
func recentVerdicts() []contracts.EmailsVerdict {
	ringMu.Lock()
	defer ringMu.Unlock()
	out := make([]contracts.EmailsVerdict, len(ring))
	for i, v := range ring {
		out[len(ring)-1-i] = v
	}
	return out
}
