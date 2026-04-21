package nlp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	sharedhttp "github.com/saif/cybersiren/shared/http"
)

var nlpTracer = otel.Tracer("svc-06-nlp/internal/nlp")

// PredictRequest mirrors the Python PredictRequest model (spec §8.3).
type PredictRequest struct {
	Subject   string `json:"subject"`
	BodyPlain string `json:"body_plain"`
	BodyHTML  string `json:"body_html,omitempty"`
}

// TokenScore holds a token and its LIME importance weight.
type TokenScore struct {
	Token string  `json:"token"`
	Score float64 `json:"score"`
}

// PredictResponse mirrors the Python PredictResponse model (spec §8.3).
type PredictResponse struct {
	Classification      string       `json:"classification"`       // "phishing" | "spam" | "legitimate"
	Confidence          float64      `json:"confidence"`           // 0.0 – 1.0
	PhishingProbability float64      `json:"phishing_probability"` // 0.0 – 1.0
	SpamProbability     float64      `json:"spam_probability"`     // 0.0 – 1.0
	ContentRiskScore    int          `json:"content_risk_score"`   // 0 – 100
	IntentLabels        []string     `json:"intent_labels"`
	UrgencyScore        float64      `json:"urgency_score"` // 0.0 – 1.0
	ObfuscationDetected bool         `json:"obfuscation_detected"`
	TopTokens           []TokenScore `json:"top_tokens"` // always [] in production
}

// healthResponse is the Python /healthz response shape.
type healthResponse struct {
	Status     string `json:"status"`
	ModelReady bool   `json:"model_ready"`
}

// StatusResponse is the Python /status response shape (always 200).
type StatusResponse struct {
	ModelReady         bool   `json:"model_ready"`
	LoadingStage       string `json:"loading_stage"`
	LoadingProgressPct int    `json:"loading_progress_pct"`
}

// Client wraps the shared HTTP client to call the Python NLP inference service.
type Client struct {
	http            sharedhttp.Client
	baseURL         string
	log             zerolog.Logger
	requestsTotal   *prometheus.CounterVec
	requestDuration prometheus.Histogram
	errorsTotal     prometheus.Counter
}

// NewClient constructs a Client targeting the given baseURL (e.g. http://localhost:8001).
// reg must be the shared registry from metrics.Init() — custom NLP metrics are registered on it.
func NewClient(baseURL string, reg *prometheus.Registry, log zerolog.Logger) *Client {
	c := sharedhttp.NewClient(
		sharedhttp.WithClientBaseURL(baseURL),
		sharedhttp.WithClientTimeout(10*time.Second),
		// Disable retries: 503 from the NLP service means "model not loaded",
		// not a transient error. Retrying immediately will not help.
		sharedhttp.WithClientRetry(0, 0, 0),
	)

	requestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nlp_predict_requests_total",
		Help: "Total NLP predict requests completed, labelled by classification result.",
	}, []string{"classification"})
	reg.MustRegister(requestsTotal)

	requestDuration := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "nlp_predict_duration_seconds",
		Help:    "Round-trip latency of POST /predict calls to the Python NLP service.",
		Buckets: []float64{.05, .1, .15, .2, .3, .5, 1, 2, 5},
	})
	reg.MustRegister(requestDuration)

	errorsTotal := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "nlp_predict_errors_total",
		Help: "Total NLP predict errors (network failures or non-2xx responses).",
	})
	reg.MustRegister(errorsTotal)

	return &Client{
		http:            c,
		baseURL:         baseURL,
		log:             log,
		requestsTotal:   requestsTotal,
		requestDuration: requestDuration,
		errorsTotal:     errorsTotal,
	}
}

// Predict calls POST /predict on the Python NLP service.
// Returns the response, the upstream HTTP status code (for error propagation), and any error.
func (c *Client) Predict(ctx context.Context, req PredictRequest) (*PredictResponse, int, error) {
	ctx, span := nlpTracer.Start(ctx, "Client.Predict")
	defer span.End()

	start := time.Now()
	var resp PredictResponse
	_, err := c.http.PostJSON(ctx, "/predict", req, &resp)
	c.requestDuration.Observe(time.Since(start).Seconds())

	if err != nil {
		c.errorsTotal.Inc()
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		var ce *sharedhttp.ClientError
		if errors.As(err, &ce) {
			return nil, ce.StatusCode, fmt.Errorf("nlp service error %d: %s", ce.StatusCode, ce.Message)
		}
		return nil, 0, fmt.Errorf("nlp service unreachable: %w", err)
	}

	// Whitelist classification label to bound Prometheus cardinality.
	// Python should only return one of these three values; anything
	// else gets bucketed as "unknown" instead of creating new series.
	classification := resp.Classification
	switch classification {
	case "phishing", "spam", "legitimate":
		// pass-through
	default:
		classification = "unknown"
	}
	c.requestsTotal.WithLabelValues(classification).Inc()
	span.SetAttributes(
		attribute.String("nlp.classification", resp.Classification),
		attribute.Float64("nlp.confidence", resp.Confidence),
		attribute.Int("nlp.content_risk_score", resp.ContentRiskScore),
		attribute.Bool("nlp.obfuscation_detected", resp.ObfuscationDetected),
	)

	return &resp, http.StatusOK, nil
}

// Health calls GET /healthz on the Python NLP service.
// Returns true when the model is loaded and ready.
func (c *Client) Health(ctx context.Context) (bool, error) {
	ctx, span := nlpTracer.Start(ctx, "Client.Health")
	defer span.End()

	var resp healthResponse
	_, err := c.http.GetJSON(ctx, "/healthz", &resp)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return false, fmt.Errorf("nlp healthz: %w", err)
	}
	return resp.ModelReady, nil
}

// Status calls GET /status on the Python NLP service.
// Always succeeds (Python returns 200 regardless of model readiness).
func (c *Client) Status(ctx context.Context) (*StatusResponse, error) {
	ctx, span := nlpTracer.Start(ctx, "Client.Status")
	defer span.End()

	var resp StatusResponse
	_, err := c.http.GetJSON(ctx, "/status", &resp)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("nlp status: %w", err)
	}
	return &resp, nil
}
