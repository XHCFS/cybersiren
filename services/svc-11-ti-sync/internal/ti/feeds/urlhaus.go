package feeds

import (
	"context"
	"encoding/csv"
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

const urlHausDefaultURL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

type URLhausFeed struct {
	feedID     int64
	httpClient httputil.Client
	log        zerolog.Logger

	URL string
}

var _ ti.Feed = (*URLhausFeed)(nil)

func NewURLhausFeed(feedID int64, httpClient httputil.Client, log zerolog.Logger) *URLhausFeed {
	return &URLhausFeed{
		feedID:     feedID,
		httpClient: httpClient,
		log:        log,
		URL:        urlHausDefaultURL,
	}
}

func (f *URLhausFeed) Name() string  { return "urlhaus" }
func (f *URLhausFeed) FeedID() int64 { return f.feedID }

func (f *URLhausFeed) Fetch(ctx context.Context) (indicators []ti.TIIndicator, err error) {
	fetchCtx, cancel := context.WithTimeout(ctx, ti.FeedFetchTimeout)
	defer cancel()

	fetchCtx, span := ti.Tracer().Start(fetchCtx, "feeds.urlhaus.Fetch")
	defer func() {
		span.SetAttributes(attribute.Int("indicator_count", len(indicators)))
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	if f.httpClient == nil {
		return nil, fmt.Errorf("urlhaus: http client is nil")
	}

	requestURL := strings.TrimSpace(f.URL)
	if requestURL == "" {
		requestURL = urlHausDefaultURL
	}

	response, reqErr := f.httpClient.Do(fetchCtx, httputil.NewClientRequest(http.MethodGet, requestURL), nil)
	if reqErr != nil {
		return nil, fmt.Errorf("urlhaus: %w", reqErr)
	}

	csvPayload, prepErr := ti.StripCSVComments(response.Body)
	if prepErr != nil {
		return nil, fmt.Errorf("urlhaus: %w", prepErr)
	}
	if strings.TrimSpace(csvPayload) == "" {
		return []ti.TIIndicator{}, nil
	}

	csvReader := csv.NewReader(strings.NewReader(csvPayload))
	csvReader.FieldsPerRecord = -1

	records, readErr := csvReader.ReadAll()
	if readErr != nil {
		return nil, fmt.Errorf("urlhaus: %w", readErr)
	}
	if len(records) == 0 {
		return []ti.TIIndicator{}, nil
	}

	columns, columnErr := ti.CSVHeaderIndex(records[0], "id", "url", "url_status", "threat", "tags")
	startRow := 1
	if columnErr != nil {
		if looksLikeURLhausDataRow(records[0]) {
			columns = map[string]int{
				"id":         0,
				"url":        2,
				"url_status": 3,
				"threat":     5,
				"tags":       6,
			}
			startRow = 0
		} else {
			return nil, fmt.Errorf("urlhaus: %w", columnErr)
		}
	}

	indicators = make([]ti.TIIndicator, 0, len(records)-startRow)
	for _, row := range records[startRow:] {
		threat := strings.TrimSpace(ti.CSVColumnValue(row, columns, "threat"))
		threatLower := strings.ToLower(threat)
		if threatLower != "malware_download" && threatLower != "phishing" {
			continue
		}

		if strings.EqualFold(strings.TrimSpace(ti.CSVColumnValue(row, columns, "url_status")), "offline") {
			continue
		}

		normalized, normErr := normalization.NormalizeURL(ti.CSVColumnValue(row, columns, "url"))
		if normErr != nil {
			f.log.Warn().
				Err(normErr).
				Str("source_id", strings.TrimSpace(ti.CSVColumnValue(row, columns, "id"))).
				Str("raw_url", strings.TrimSpace(ti.CSVColumnValue(row, columns, "url"))).
				Msg("skipping invalid URLhaus URL")
			continue
		}

		tags := ti.SplitCommaTags(ti.CSVColumnValue(row, columns, "tags"))
		tags = append(tags, "urlhaus")

		indicators = append(indicators, ti.TIIndicator{
			FeedID:         f.feedID,
			IndicatorType:  ti.URLIndicatorType,
			IndicatorValue: normalized,
			ThreatType:     threat,
			ThreatTags:     tags,
			RiskScore:      80,
			Confidence:     0.75,
			SourceID:       strings.TrimSpace(ti.CSVColumnValue(row, columns, "id")),
		})
	}

	return indicators, nil
}

func looksLikeURLhausDataRow(row []string) bool {
	if len(row) < 7 {
		return false
	}

	if strings.TrimSpace(row[0]) == "" {
		return false
	}

	threat := strings.ToLower(strings.TrimSpace(row[5]))
	return threat != ""
}
