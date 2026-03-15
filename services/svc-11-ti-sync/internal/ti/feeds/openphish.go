package feeds

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/saif/cybersiren/services/svc-11-ti-sync/internal/ti"
	httputil "github.com/saif/cybersiren/shared/http"
	"github.com/saif/cybersiren/shared/normalization"
)

const openPhishDefaultURL = "https://openphish.com/feed.txt"

type OpenPhishFeed struct {
	feedID     int64
	httpClient httputil.Client
	log        zerolog.Logger

	URL string
}

var _ ti.Feed = (*OpenPhishFeed)(nil)

func NewOpenPhishFeed(feedID int64, httpClient httputil.Client, log zerolog.Logger) *OpenPhishFeed {
	log.Warn().Err(ti.ErrOpenPhishNonCommercialNotice).Msg("OpenPhish free tier is non-commercial use only")

	return &OpenPhishFeed{
		feedID:     feedID,
		httpClient: httpClient,
		log:        log,
		URL:        openPhishDefaultURL,
	}
}

func (f *OpenPhishFeed) Fetch(ctx context.Context) (indicators []ti.TIIndicator, err error) {
	fetchCtx, cancel := context.WithTimeout(ctx, ti.FeedFetchTimeout)
	defer cancel()

	fetchCtx, span := ti.Tracer().Start(fetchCtx, "feeds.openphish.Fetch")
	defer func() {
		span.SetAttributes(attribute.Int("indicator_count", len(indicators)))
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	if f.httpClient == nil {
		return nil, fmt.Errorf("openphish: http client is nil")
	}

	requestURL := strings.TrimSpace(f.URL)
	if requestURL == "" {
		requestURL = openPhishDefaultURL
	}

	response, reqErr := f.httpClient.Do(fetchCtx, httputil.NewClientRequest(http.MethodGet, requestURL), nil)
	if reqErr != nil {
		return nil, fmt.Errorf("openphish: %w", reqErr)
	}

	scanner := bufio.NewScanner(bytes.NewReader(response.Body))
	indicators = make([]ti.TIIndicator, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		normalized, normErr := normalization.NormalizeURL(line)
		if normErr != nil {
			f.log.Warn().Err(normErr).Str("raw_url", line).Msg("skipping invalid OpenPhish URL")
			continue
		}

		hash := sha256.Sum256([]byte(normalized))
		sourceID := hex.EncodeToString(hash[:])

		indicators = append(indicators, ti.TIIndicator{
			FeedID:         f.feedID,
			IndicatorType:  ti.URLIndicatorType,
			IndicatorValue: normalized,
			ThreatType:     "phishing",
			ThreatTags:     []string{"openphish"},
			RiskScore:      85,
			Confidence:     0.80,
			SourceID:       sourceID,
		})
	}

	if scanErr := scanner.Err(); scanErr != nil {
		return nil, fmt.Errorf("openphish: %w", scanErr)
	}

	return indicators, nil
}
