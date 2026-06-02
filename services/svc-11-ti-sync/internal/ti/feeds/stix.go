package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/saif/cybersiren/services/svc-11-ti-sync/internal/ti"
	httputil "github.com/saif/cybersiren/shared/http"
)

// stixObjectTypeMap maps a STIX Cyber-observable object type (the token before
// the colon in a pattern, e.g. "url" in `[url:value = '…']`) to our internal
// ti_indicators indicator_type.
var stixObjectTypeMap = map[string]string{
	"url":         "url",
	"domain-name": "domain",
	"ipv4-addr":   "ip",
	"ipv6-addr":   "ip",
	"file":        "hash",
	"email-addr":  "email_address",
}

// stixComparison matches one `object-type:path = 'value'` comparison inside a
// STIX 2.x pattern. Patterns may contain several joined by AND/OR.
var stixComparison = regexp.MustCompile(`([a-z0-9-]+):[^=<>!]*?=\s*'([^']+)'`)

// stixBundle is the minimal STIX 2.x bundle shape we consume.
type stixBundle struct {
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Pattern    string   `json:"pattern"`
	Name       string   `json:"name"`
	Labels     []string `json:"labels"`
	Confidence int      `json:"confidence"`
}

// ParseSTIXBundle extracts indicator rows from a STIX 2.x bundle. Each Indicator
// object's pattern is decomposed into one or more (type, value) comparisons,
// each mapped to a ti_indicators row. Unsupported object types are skipped.
func ParseSTIXBundle(data []byte, feedID int64) ([]ti.TIIndicator, error) {
	var bundle stixBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("stix: decode bundle: %w", err)
	}

	var out []ti.TIIndicator
	for _, obj := range bundle.Objects {
		if obj.Type != "indicator" || obj.Pattern == "" {
			continue
		}
		threatType := "stix"
		if len(obj.Labels) > 0 {
			threatType = obj.Labels[0]
		}
		for _, m := range stixComparison.FindAllStringSubmatch(obj.Pattern, -1) {
			indType, ok := stixObjectTypeMap[strings.ToLower(m[1])]
			if !ok {
				continue
			}
			out = append(out, ti.TIIndicator{
				FeedID:         feedID,
				IndicatorType:  indType,
				IndicatorValue: m[2],
				ThreatType:     threatType,
				ThreatTags:     obj.Labels,
				Confidence:     float64(obj.Confidence) / 100.0,
				RiskScore:      obj.Confidence,
				SourceID:       obj.ID,
			})
		}
	}
	return out, nil
}

// STIXFeed fetches a STIX 2.x bundle from a URL and parses it into indicators.
// It satisfies ti.Feed, so it plugs into the runner like any other feed.
type STIXFeed struct {
	feedID     int64
	URL        string
	httpClient httputil.Client
	log        zerolog.Logger
}

// NewSTIXFeed constructs a STIX feed for the given feed row id and bundle URL.
func NewSTIXFeed(feedID int64, url string, httpClient httputil.Client, log zerolog.Logger) *STIXFeed {
	return &STIXFeed{feedID: feedID, URL: url, httpClient: httpClient, log: log}
}

// Name identifies the feed.
func (f *STIXFeed) Name() string { return "stix" }

// FeedID returns the feeds-table id.
func (f *STIXFeed) FeedID() int64 { return f.feedID }

// Fetch downloads and parses the configured STIX bundle.
func (f *STIXFeed) Fetch(ctx context.Context) (indicators []ti.TIIndicator, err error) {
	fetchCtx, cancel := context.WithTimeout(ctx, ti.FeedFetchTimeout)
	defer cancel()
	fetchCtx, span := ti.Tracer().Start(fetchCtx, "feeds.stix.Fetch")
	defer func() {
		span.SetAttributes(attribute.Int("indicator_count", len(indicators)))
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	if f.httpClient == nil {
		return nil, fmt.Errorf("stix: http client is nil")
	}
	url := strings.TrimSpace(f.URL)
	if url == "" {
		return nil, fmt.Errorf("stix: empty feed URL")
	}

	resp, reqErr := f.httpClient.Do(fetchCtx, httputil.NewClientRequest(http.MethodGet, url), nil)
	if reqErr != nil {
		return nil, fmt.Errorf("stix: fetch %s: %w", url, reqErr)
	}
	return ParseSTIXBundle(resp.Body, f.feedID)
}
