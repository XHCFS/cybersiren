package gmail

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/source"
	"github.com/saif/cybersiren/shared/config"
)

// Build constructs a production Gmail adapter from configuration, the shared
// ingestion core, and the service's Valkey client (for the history cursor). It
// returns nil, nil when the Gmail adapter is disabled so the caller can simply
// skip wiring it. cfg.Validate() must already have passed.
func Build(cfg config.GmailConfig, core source.Ingestor, valkey valkeygo.Client, log zerolog.Logger) (*Adapter, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("gmail: invalid config: %w", err)
	}
	if valkey == nil {
		return nil, errors.New("gmail: a Valkey client is required to persist the history cursor")
	}

	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	httpClient := &http.Client{Timeout: timeout}

	tokens := newTokenSource(cfg.ClientID, cfg.ClientSecret, cfg.RefreshToken, cfg.TokenURL, httpClient)
	gclient := newClient(cfg.APIBaseURL, cfg.User, tokens, httpClient)

	return New(Options{
		Core:         core,
		OrgID:        cfg.OrgID,
		Client:       gclient,
		History:      NewValkeyHistoryStore(valkey),
		LabelIDs:     cfg.LabelIDs,
		WatchTopic:   cfg.WatchTopic,
		PushToken:    cfg.PushToken,
		PushAudience: cfg.PushAudience,
		PollInterval: cfg.PollInterval,
		Log:          log.With().Str("adapter", "gmail").Logger(),
	}), nil
}

// PushEnabled / PollEnabled re-expose the config toggles so the caller (main)
// can decide which loops to start without re-reading config.
func PushEnabled(cfg config.GmailConfig) bool { return cfg.Enabled && cfg.PushEnabled }
func PollEnabled(cfg config.GmailConfig) bool { return cfg.Enabled && cfg.PollEnabled }
