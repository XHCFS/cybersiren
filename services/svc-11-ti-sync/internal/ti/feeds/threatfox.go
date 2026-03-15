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
	threatFoxDefaultURL    = "https://threatfox-api.abuse.ch/api/v1/"
	threatFoxQueryGetIOCs  = "get_iocs"
	threatFoxOKQueryStatus = "ok"
)

type ThreatFoxFeed struct {
	feedID     int64
	httpClient httputil.Client
	log        zerolog.Logger
	apiKey     string

	URL string
}

var _ ti.Feed = (*ThreatFoxFeed)(nil)

func NewThreatFoxFeed(feedID int64, cfg *config.Config, httpClient httputil.Client, log zerolog.Logger) *ThreatFoxFeed {
	apiKey := ""
	if cfg != nil {
		apiKey = strings.TrimSpace(cfg.FeedThreatFoxAPIKey)
	}

	return &ThreatFoxFeed{
		feedID:     feedID,
		httpClient: httpClient,
		log:        log,
		apiKey:     apiKey,
		URL:        threatFoxDefaultURL,
	}
}

func (f *ThreatFoxFeed) Fetch(ctx context.Context) (indicators []ti.TIIndicator, err error) {
	fetchCtx, cancel := context.WithTimeout(ctx, ti.FeedFetchTimeout)
	defer cancel()

	fetchCtx, span := ti.Tracer().Start(fetchCtx, "feeds.threatfox.Fetch")
	defer func() {
		span.SetAttributes(attribute.Int("indicator_count", len(indicators)))
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	if f.httpClient == nil {
		return nil, fmt.Errorf("threatfox: http client is nil")
	}

	requestURL := strings.TrimSpace(f.URL)
	if requestURL == "" {
		requestURL = threatFoxDefaultURL
	}

	requestBody := map[string]any{"query": threatFoxQueryGetIOCs, "days": 1}
	requestOptions := []httputil.ClientRequestOption{
		httputil.WithClientRequestHeader("Content-Type", "application/json"),
	}

	if apiKey := strings.TrimSpace(f.apiKey); apiKey != "" {
		requestBody["auth_key"] = apiKey
		requestOptions = append(requestOptions, httputil.WithClientRequestHeader("Auth-Key", apiKey))
	}

	requestOptions = append(requestOptions, httputil.WithClientRequestBody(requestBody))

	request := httputil.NewClientRequest(http.MethodPost, requestURL, requestOptions...)

	response, reqErr := f.httpClient.Do(fetchCtx, request, nil)
	if reqErr != nil {
		return nil, fmt.Errorf("threatfox: %w", reqErr)
	}

	var payload threatFoxResponse
	if decodeErr := json.Unmarshal(response.Body, &payload); decodeErr != nil {
		return nil, fmt.Errorf("threatfox: %w", decodeErr)
	}

	if !strings.EqualFold(strings.TrimSpace(payload.QueryStatus), threatFoxOKQueryStatus) {
		return nil, fmt.Errorf("threatfox: %w: query_status=%s", ti.ErrThreatFoxAPIError, strings.TrimSpace(payload.QueryStatus))
	}

	indicators = make([]ti.TIIndicator, 0, len(payload.Data))
	for _, raw := range payload.Data {
		var entry threatFoxEntry
		if decodeErr := json.Unmarshal(raw, &entry); decodeErr != nil {
			return nil, fmt.Errorf("threatfox: %w", decodeErr)
		}

		if !strings.EqualFold(strings.TrimSpace(entry.IOCType), ti.URLIndicatorType) {
			continue
		}

		normalized, normErr := normalization.NormalizeURL(entry.IOC)
		if normErr != nil {
			f.log.Warn().
				Err(normErr).
				Str("source_id", ti.RawJSONToString(entry.ID)).
				Str("raw_ioc", entry.IOC).
				Msg("skipping invalid ThreatFox IOC URL")
			continue
		}

		confidenceLevel := ti.ClampInt(ti.ParseJSONInt(entry.ConfidenceLevel), 0, 100)
		tags := append(ti.ParseJSONTags(entry.Tags), "threatfox")

		indicators = append(indicators, ti.TIIndicator{
			FeedID:         f.feedID,
			IndicatorType:  ti.URLIndicatorType,
			IndicatorValue: normalized,
			ThreatType:     strings.TrimSpace(entry.ThreatType),
			ThreatTags:     tags,
			RiskScore:      confidenceLevel,
			Confidence:     float64(confidenceLevel) / 100.0,
			SourceID:       ti.RawJSONToString(entry.ID),
			RawMetadata:    append([]byte(nil), raw...),
		})
	}

	return indicators, nil
}

type threatFoxResponse struct {
	QueryStatus string            `json:"query_status"`
	Data        []json.RawMessage `json:"data"`
}

type threatFoxEntry struct {
	ID              json.RawMessage `json:"id"`
	IOC             string          `json:"ioc"`
	IOCType         string          `json:"ioc_type"`
	ThreatType      string          `json:"threat_type"`
	Tags            json.RawMessage `json:"tags"`
	ConfidenceLevel json.RawMessage `json:"confidence_level"`
}
