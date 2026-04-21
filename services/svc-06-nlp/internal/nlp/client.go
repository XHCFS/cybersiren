package nlp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	sharedhttp "github.com/saif/cybersiren/shared/http"
)

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
	UrgencyScore        float64      `json:"urgency_score"`        // 0.0 – 1.0
	ObfuscationDetected bool         `json:"obfuscation_detected"`
	TopTokens           []TokenScore `json:"top_tokens"` // always [] in production
}

// healthResponse is the Python /healthz response shape.
type healthResponse struct {
	Status     string `json:"status"`
	ModelReady bool   `json:"model_ready"`
}

// Client wraps the shared HTTP client to call the Python NLP inference service.
type Client struct {
	http    sharedhttp.Client
	baseURL string
	log     zerolog.Logger
}

// NewClient constructs a Client targeting the given baseURL (e.g. http://localhost:8001).
func NewClient(baseURL string, log zerolog.Logger) *Client {
	c := sharedhttp.NewClient(
		sharedhttp.WithClientBaseURL(baseURL),
		sharedhttp.WithClientTimeout(10*time.Second),
		// Disable retries: 503 from the NLP service means "model not loaded",
		// not a transient error. Retrying immediately will not help.
		sharedhttp.WithClientRetry(0, 0, 0),
	)
	return &Client{http: c, baseURL: baseURL, log: log}
}

// Predict calls POST /predict on the Python NLP service.
// Returns the response, the upstream HTTP status code (for error propagation), and any error.
func (c *Client) Predict(ctx context.Context, req PredictRequest) (*PredictResponse, int, error) {
	var resp PredictResponse
	_, err := c.http.PostJSON(ctx, "/predict", req, &resp)
	if err != nil {
		var ce *sharedhttp.ClientError
		if errors.As(err, &ce) {
			return nil, ce.StatusCode, fmt.Errorf("nlp service error %d: %s", ce.StatusCode, ce.Message)
		}
		return nil, 0, fmt.Errorf("nlp service unreachable: %w", err)
	}
	return &resp, http.StatusOK, nil
}

// Health calls GET /healthz on the Python NLP service.
// Returns true when the model is loaded and ready.
func (c *Client) Health(ctx context.Context) (bool, error) {
	var resp healthResponse
	_, err := c.http.GetJSON(ctx, "/healthz", &resp)
	if err != nil {
		return false, fmt.Errorf("nlp healthz: %w", err)
	}
	return resp.ModelReady, nil
}
