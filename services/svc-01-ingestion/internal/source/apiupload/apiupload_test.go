package apiupload

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/auth"
	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/source"
)

// fakeCore records the normalised request and returns a canned outcome.
type fakeCore struct {
	got     source.IngestRequest
	gotOrg  int64
	gotKey  int64
	outcome source.Outcome
	err     error
	calls   int
}

func (f *fakeCore) Ingest(_ context.Context, orgID, apiKeyID int64, req source.IngestRequest) (source.Outcome, error) {
	f.calls++
	f.got = req
	f.gotOrg = orgID
	f.gotKey = apiKeyID
	return f.outcome, f.err
}

// withPrincipal wraps a request context with an authenticated principal, as the
// auth middleware would.
func withPrincipal(r *http.Request, org, key int64) *http.Request {
	ctx := auth.NewContext(r.Context(), auth.Principal{OrgID: org, APIKeyID: key})
	return r.WithContext(ctx)
}

const rawEML = "From: a@b.test\r\nMessage-Id: <abc-123@b.test>\r\nSubject: hi\r\n\r\nbody"

func TestHandleScan_RawEML_ExtractsMessageIDAndOrg(t *testing.T) {
	core := &fakeCore{outcome: source.Outcome{EmailID: "e-uuid", Status: source.StatusAccepted}}
	a := New(core, zerolog.Nop())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(rawEML))
	req.Header.Set("Content-Type", "message/rfc822")
	req = withPrincipal(req, 7, 55)
	rr := httptest.NewRecorder()
	a.handleScan(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rr.Code)
	}
	if core.calls != 1 {
		t.Fatalf("core called %d times, want 1", core.calls)
	}
	if core.gotOrg != 7 || core.gotKey != 55 {
		t.Errorf("org/key = %d/%d, want 7/55 (from principal)", core.gotOrg, core.gotKey)
	}
	if core.got.MessageID != "abc-123@b.test" {
		t.Errorf("message_id = %q, want abc-123@b.test (angle brackets stripped)", core.got.MessageID)
	}
	if string(core.got.Raw) != rawEML {
		t.Error("raw bytes must be forwarded verbatim")
	}
	if core.got.SourceAdapter != "api" {
		t.Errorf("source_adapter = %q, want api", core.got.SourceAdapter)
	}
}

func TestHandleScan_JSONBase64(t *testing.T) {
	core := &fakeCore{outcome: source.Outcome{EmailID: "e-uuid", Status: source.StatusAccepted}}
	a := New(core, zerolog.Nop())

	bodyJSON, _ := json.Marshal(map[string]string{
		"raw_rfc822": base64.StdEncoding.EncodeToString([]byte(rawEML)),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, 1, 2)
	rr := httptest.NewRecorder()
	a.handleScan(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rr.Code)
	}
	if string(core.got.Raw) != rawEML {
		t.Error("base64 raw_rfc822 must decode to the original bytes")
	}
	// message_id derived from the decoded RFC-822 when not supplied in JSON.
	if core.got.MessageID != "abc-123@b.test" {
		t.Errorf("message_id = %q, want abc-123@b.test", core.got.MessageID)
	}
}

// TestHandleScan_JSONMessageIDStripsBrackets pins the cross-path dedup fix: a
// JSON client that supplies message_id with its native angle brackets must dedup
// on the SAME canonical key the raw-.eml/Gmail paths derive (via rfc822), not on
// the bracketed form — else the same email via two shapes double-persists.
func TestHandleScan_JSONMessageIDStripsBrackets(t *testing.T) {
	core := &fakeCore{outcome: source.Outcome{EmailID: "e-uuid", Status: source.StatusAccepted}}
	a := New(core, zerolog.Nop())

	bodyJSON, _ := json.Marshal(map[string]string{
		"raw_rfc822": base64.StdEncoding.EncodeToString([]byte(rawEML)),
		"message_id": "<supplied-id@b.test>",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, 1, 2)
	rr := httptest.NewRecorder()
	a.handleScan(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rr.Code)
	}
	if core.got.MessageID != "supplied-id@b.test" {
		t.Errorf("message_id = %q, want supplied-id@b.test (angle brackets stripped)", core.got.MessageID)
	}
}

func TestHandleScan_NoPrincipal_401(t *testing.T) {
	core := &fakeCore{}
	a := New(core, zerolog.Nop())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(rawEML))
	rr := httptest.NewRecorder()
	a.handleScan(rr, req) // no principal in context

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 when no principal bound", rr.Code)
	}
	if core.calls != 0 {
		t.Error("must not ingest without an authenticated principal")
	}
}

func TestHandleScan_OutcomeRendering(t *testing.T) {
	cases := []struct {
		name   string
		out    source.Outcome
		status int
	}{
		{"duplicate", source.Outcome{Status: source.StatusDuplicate}, http.StatusOK},
		{"quota", source.Outcome{Status: source.StatusQuotaExceeded}, http.StatusTooManyRequests},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(&fakeCore{outcome: tc.out}, zerolog.Nop())
			req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(rawEML))
			req = withPrincipal(req, 1, 1)
			rr := httptest.NewRecorder()
			a.handleScan(rr, req)
			if rr.Code != tc.status {
				t.Errorf("status = %d, want %d", rr.Code, tc.status)
			}
		})
	}
}

func TestHandleScan_EmptyBody_400(t *testing.T) {
	a := New(&fakeCore{}, zerolog.Nop())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(""))
	req = withPrincipal(req, 1, 1)
	rr := httptest.NewRecorder()
	a.handleScan(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an empty body", rr.Code)
	}
}

func TestHandleScan_GET_405(t *testing.T) {
	a := New(&fakeCore{}, zerolog.Nop())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan", nil)
	rr := httptest.NewRecorder()
	a.handleScan(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}
