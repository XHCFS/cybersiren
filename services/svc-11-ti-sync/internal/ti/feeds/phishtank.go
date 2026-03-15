package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/saif/cybersiren/services/svc-11-ti-sync/internal/ti"
	"github.com/saif/cybersiren/shared/config"
	httputil "github.com/saif/cybersiren/shared/http"
	"github.com/saif/cybersiren/shared/normalization"
)

const (
	phishTankDefaultURLTemplate = "http://data.phishtank.com/data/{api_key}/online-valid.json"
)

type PhishTankFeed struct {
	feedID     int64
	apiKey     string
	httpClient httputil.Client
	log        zerolog.Logger

	URLTemplate string
}

var _ ti.Feed = (*PhishTankFeed)(nil)

func NewPhishTankFeed(feedID int64, cfg *config.Config, httpClient httputil.Client, log zerolog.Logger) (*PhishTankFeed, error) {
	if cfg == nil {
		return nil, fmt.Errorf("phishtank: config is nil")
	}

	apiKey := strings.TrimSpace(cfg.FeedPhishTankAPIKey)
	if apiKey == "" {
		return nil, ti.ErrPhishTankKeyMissing
	}

	return &PhishTankFeed{
		feedID:      feedID,
		apiKey:      apiKey,
		httpClient:  httpClient,
		log:         log,
		URLTemplate: phishTankDefaultURLTemplate,
	}, nil
}

func (f *PhishTankFeed) Fetch(ctx context.Context) (indicators []ti.TIIndicator, err error) {
	fetchCtx, cancel := context.WithTimeout(ctx, ti.FeedFetchTimeout)
	defer cancel()

	fetchCtx, span := ti.Tracer().Start(fetchCtx, "feeds.phishtank.Fetch")
	defer func() {
		span.SetAttributes(attribute.Int("indicator_count", len(indicators)))
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	if strings.TrimSpace(f.apiKey) == "" {
		return nil, fmt.Errorf("phishtank: %w", ti.ErrPhishTankKeyMissing)
	}
	if f.httpClient == nil {
		return nil, fmt.Errorf("phishtank: http client is nil")
	}

	urlTemplate := strings.TrimSpace(f.URLTemplate)
	if urlTemplate == "" {
		urlTemplate = phishTankDefaultURLTemplate
	}

	requestURL := strings.ReplaceAll(urlTemplate, "{api_key}", f.apiKey)

	response, reqErr := f.httpClient.Do(fetchCtx, httputil.NewClientRequest(http.MethodGet, requestURL), nil)
	if reqErr != nil {
		return nil, fmt.Errorf("phishtank: %w", reqErr)
	}

	var payload []json.RawMessage
	if decodeErr := json.Unmarshal(response.Body, &payload); decodeErr != nil {
		return nil, fmt.Errorf("phishtank: %w", decodeErr)
	}

	indicators = make([]ti.TIIndicator, 0, len(payload))
	for _, raw := range payload {
		var entry phishTankEntry
		if decodeErr := json.Unmarshal(raw, &entry); decodeErr != nil {
			return nil, fmt.Errorf("phishtank: %w", decodeErr)
		}

		if !ti.ParseJSONBool(entry.Verified) {
			continue
		}

		normalized, normErr := normalization.NormalizeURL(entry.URL)
		if normErr != nil {
			f.log.Warn().
				Err(normErr).
				Str("source_id", ti.RawJSONToString(entry.PhishID)).
				Str("raw_url", entry.URL).
				Msg("skipping invalid PhishTank URL")
			continue
		}

		indicators = append(indicators, ti.TIIndicator{
			FeedID:         f.feedID,
			IndicatorType:  ti.URLIndicatorType,
			IndicatorValue: normalized,
			ThreatType:     "phishing",
			ThreatTags:     []string{"phishtank", "verified"},
			RiskScore:      90,
			Confidence:     0.95,
			SourceID:       ti.RawJSONToString(entry.PhishID),
			RawMetadata:    append([]byte(nil), raw...),
		})
	}

	return indicators, nil
}

type phishTankEntry struct {
	PhishID  json.RawMessage `json:"phish_id"`
	URL      string          `json:"url"`
	Verified json.RawMessage `json:"verified"`
}
