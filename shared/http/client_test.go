package httputil

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	resty "resty.dev/v3"
)

func TestClientGetJSONSuccess(t *testing.T) {
	var gotMethod string
	var gotDomain string
	var gotAPIKey string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotDomain = r.URL.Query().Get("domain")
		gotAPIKey = r.Header.Get("X-API-Key")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"domain":"example.com","ok":true}`))
	}))
	defer ts.Close()

	client := NewClient(WithClientRetry(0, 0, 0))

	var out struct {
		Domain string `json:"domain"`
		OK     bool   `json:"ok"`
	}

	resp, err := client.GetJSON(context.Background(), ts.URL+"/lookup", &out,
		WithClientRequestQueryParam("domain", "example.com"),
		WithClientRequestHeader("X-API-Key", "secret"),
	)
	if err != nil {
		t.Fatalf("GetJSON returned error: %v", err)
	}

	if resp == nil {
		t.Fatal("response is nil")
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if gotMethod != http.MethodGet {
		t.Fatalf("method = %s, want %s", gotMethod, http.MethodGet)
	}

	if gotDomain != "example.com" {
		t.Fatalf("query domain = %q, want %q", gotDomain, "example.com")
	}

	if gotAPIKey != "secret" {
		t.Fatalf("header X-API-Key = %q, want %q", gotAPIKey, "secret")
	}

	if out.Domain != "example.com" || !out.OK {
		t.Fatalf("decoded response = %+v, want domain=example.com ok=true", out)
	}
}

func TestClientUnexpectedStatusReturnsClientError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	defer ts.Close()

	client := NewClient(WithClientRetry(0, 0, 0))

	var out map[string]any
	resp, err := client.GetJSON(context.Background(), ts.URL+"/lookup", &out)
	if err == nil {
		t.Fatal("expected error for unexpected status, got nil")
	}

	if resp == nil {
		t.Fatal("expected non-nil response on status error")
	}

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}

	var clientErr *ClientError
	if !errors.As(err, &clientErr) {
		t.Fatalf("error type = %T, want *ClientError", err)
	}

	if clientErr.StatusCode != http.StatusNotFound {
		t.Fatalf("client error status = %d, want %d", clientErr.StatusCode, http.StatusNotFound)
	}

	if !strings.Contains(clientErr.ResponseBody, "not found") {
		t.Fatalf("client error response body = %q, expected to contain %q", clientErr.ResponseBody, "not found")
	}
}

func TestClientRequestTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	client := NewClient(WithClientRetry(0, 0, 0))
	req := NewClientRequest(http.MethodGet, ts.URL+"/slow", WithClientRequestTimeout(10*time.Millisecond))

	resp, err := client.Do(context.Background(), req, nil)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}

	if resp != nil {
		t.Fatalf("expected nil response for timeout, got status=%d", resp.StatusCode)
	}

	var clientErr *ClientError
	if !errors.As(err, &clientErr) {
		t.Fatalf("error type = %T, want *ClientError", err)
	}

	if clientErr.Err == nil {
		t.Fatal("expected wrapped timeout error")
	}
}

func TestShouldRetryRequest(t *testing.T) {
	tests := []struct {
		name     string
		response *resty.Response
		err      error
		want     bool
	}{
		{
			name: "context canceled is not retried",
			err:  context.Canceled,
			want: false,
		},
		{
			name: "context deadline exceeded is not retried",
			err:  context.DeadlineExceeded,
			want: false,
		},
		{
			name: "generic error is retried",
			err:  errors.New("temporary network failure"),
			want: true,
		},
		{
			name: "nil response and nil error is not retried",
			want: false,
		},
		{
			name:     "429 is retried",
			response: &resty.Response{RawResponse: &http.Response{StatusCode: http.StatusTooManyRequests}},
			want:     true,
		},
		{
			name:     "5xx is retried",
			response: &resty.Response{RawResponse: &http.Response{StatusCode: http.StatusInternalServerError}},
			want:     true,
		},
		{
			name:     "4xx other than 429 is not retried",
			response: &resty.Response{RawResponse: &http.Response{StatusCode: http.StatusBadRequest}},
			want:     false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := shouldRetryRequest(test.response, test.err)
			if got != test.want {
				t.Fatalf("shouldRetryRequest() = %v, want %v", got, test.want)
			}
		})
	}
}
