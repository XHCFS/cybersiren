package httputil

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

type createThingRequest struct {
	Name string `json:"name"`
}

func (r *createThingRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("name is required")
	}
	return nil
}

func TestParseAndValidateJSONSuccess(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/things", strings.NewReader(`{"name":"widget"}`))
	req.Header.Set("Content-Type", "application/json")

	var payload createThingRequest
	err := ParseAndValidateJSON(req, &payload)
	if err != nil {
		t.Fatalf("ParseAndValidateJSON returned error: %v", err)
	}

	if payload.Name != "widget" {
		t.Fatalf("payload name = %q, want %q", payload.Name, "widget")
	}
}

func TestParseJSONUnknownField(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/things", strings.NewReader(`{"name":"widget","extra":1}`))
	req.Header.Set("Content-Type", "application/json")

	var payload createThingRequest
	err := ParseJSON(req, &payload)
	if err == nil {
		t.Fatal("expected parse error for unknown field, got nil")
	}

	if err.Status != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", err.Status, http.StatusBadRequest)
	}

	if err.Code != "unknown_field" {
		t.Fatalf("code = %q, want %q", err.Code, "unknown_field")
	}
}

func TestParseJSONBodyTooLarge(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/things", strings.NewReader(`{"name":"longvalue"}`))
	req.Header.Set("Content-Type", "application/json")

	var payload map[string]string
	err := ParseJSONWithLimit(req, &payload, 8)
	if err == nil {
		t.Fatal("expected body-too-large error, got nil")
	}

	if err.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", err.Status, http.StatusRequestEntityTooLarge)
	}

	if err.Code != "body_too_large" {
		t.Fatalf("code = %q, want %q", err.Code, "body_too_large")
	}
}

func TestWriteSuccessAndErrorEnvelopes(t *testing.T) {
	successRecorder := httptest.NewRecorder()
	if err := WriteCreated(successRecorder, map[string]any{"id": 10}); err != nil {
		t.Fatalf("WriteCreated returned error: %v", err)
	}

	if successRecorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", successRecorder.Code, http.StatusCreated)
	}

	var successPayload map[string]any
	if err := json.Unmarshal(successRecorder.Body.Bytes(), &successPayload); err != nil {
		t.Fatalf("failed to decode success body: %v", err)
	}

	if successPayload["success"] != true {
		t.Fatalf("success envelope = %v, want true", successPayload["success"])
	}

	errorRecorder := httptest.NewRecorder()
	if err := WriteError(errorRecorder, http.StatusBadRequest, "bad_input", "invalid body"); err != nil {
		t.Fatalf("WriteError returned error: %v", err)
	}

	if errorRecorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", errorRecorder.Code, http.StatusBadRequest)
	}

	var errorPayload map[string]any
	if err := json.Unmarshal(errorRecorder.Body.Bytes(), &errorPayload); err != nil {
		t.Fatalf("failed to decode error body: %v", err)
	}

	if errorPayload["success"] != false {
		t.Fatalf("error envelope success = %v, want false", errorPayload["success"])
	}
}

func TestServerRouteUsesHelpers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv := NewServer()
	srv.POST("/things", func(c Context) {
		var payload createThingRequest
		if err := c.ParseAndValidateJSON(&payload); err != nil {
			_ = c.RequestError(err)
			return
		}

		_ = c.OK(map[string]any{"name": payload.Name})
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/things", strings.NewReader(`{"name":"widget"}`))
	req.Header.Set("Content-Type", "application/json")

	srv.Engine().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if payload["success"] != true {
		t.Fatalf("success = %v, want true", payload["success"])
	}
}
