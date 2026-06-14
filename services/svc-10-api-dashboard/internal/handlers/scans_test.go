package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// newScanAPI builds an API whose scan proxy targets the given svc-01 base URL.
func newScanAPI(scanURL, apiKey string) *API {
	return &API{
		Log:  zerolog.Nop(),
		Scan: NewScanForwarder(scanURL, apiKey, zerolog.Nop()),
	}
}

func TestHandleScan_Success(t *testing.T) {
	var gotAuth, gotCT string
	var gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"accepted","email_id":"0190abcd-0000-7000-8000-000000000001"}`))
	}))
	defer upstream.Close()

	api := newScanAPI(upstream.URL, "cs_serverside_secret_key")
	rr := postRaw(t, api, "From: a@b.c\r\nSubject: hi\r\n\r\nbody")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var res ScanResult
	mustJSON(t, rr, &res)
	if res.Status != "accepted" || res.EmailID == "" {
		t.Errorf("scan result = %+v, want accepted + email_id", res)
	}
	// The SERVER-SIDE key must be presented to svc-01 (and never to the browser).
	if gotAuth != "Bearer cs_serverside_secret_key" {
		t.Errorf("upstream Authorization = %q, want server-side bearer key", gotAuth)
	}
	if gotCT != "message/rfc822" {
		t.Errorf("upstream Content-Type = %q, want message/rfc822", gotCT)
	}
	if !strings.Contains(gotBody, "Subject: hi") {
		t.Errorf("upstream did not receive the raw message body: %q", gotBody)
	}
}

func TestHandleScan_UpstreamUnauthorized(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	api := newScanAPI(upstream.URL, "bad_key")
	rr := postRaw(t, api, "From: a@b.c\r\n\r\nbody")

	// A rejected forwarding credential is a server misconfiguration → 502, and
	// the response must not echo the upstream 401 (the credential is ours).
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 on upstream 401", rr.Code)
	}
}

func TestHandleScan_UpstreamDown(t *testing.T) {
	// Point at a closed server to force a transport error.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	api := newScanAPI(url, "key")
	rr := postRaw(t, api, "From: a@b.c\r\n\r\nbody")

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 when svc-01 is unreachable", rr.Code)
	}
}

func TestHandleScan_EmptyBody(t *testing.T) {
	api := newScanAPI("http://unused", "key")
	rr := postRaw(t, api, "   ")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for empty body", rr.Code)
	}
}

func TestHandleScan_NotConfigured(t *testing.T) {
	api := &API{Log: zerolog.Nop()} // no Scan forwarder
	rr := postRaw(t, api, "From: a@b.c\r\n\r\nbody")
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when scan forwarding unconfigured", rr.Code)
	}
}

func postRaw(t *testing.T, api *API, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(body))
	req.Header.Set("Content-Type", "message/rfc822")
	rr := httptest.NewRecorder()
	api.HandleScan(rr, req)
	return rr
}
