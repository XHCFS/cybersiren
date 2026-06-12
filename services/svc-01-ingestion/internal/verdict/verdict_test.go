package verdict

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/auth"
)

// newHandler builds a Handler with a nil pool. Every assertion below exercises a
// branch that returns BEFORE the DB is touched (method / auth / input
// validation), so the nil pool is never dereferenced — the DB-backed resolution
// is covered by the sqlc layer + integration tests, not here.
func newHandler() *Handler { return New(nil, zerolog.Nop()) }

func withPrincipal(r *http.Request, org int64) *http.Request {
	return r.WithContext(auth.NewContext(r.Context(), auth.Principal{OrgID: org, APIKeyID: 1}))
}

func TestVerdict_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newHandler()
	for _, path := range []string{"/verdict", "/verdict/latest"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req = withPrincipal(req, 1)
		rr := httptest.NewRecorder()
		if path == "/verdict" {
			h.handleByEmailID(rr, req)
		} else {
			h.handleLatest(rr, req)
		}
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s POST: want 405, got %d", path, rr.Code)
		}
	}
}

func TestVerdict_NoPrincipal_401(t *testing.T) {
	t.Parallel()
	h := newHandler()
	// No principal on the context: the route was reached unwrapped — fail closed.
	req := httptest.NewRequest(http.MethodGet, "/verdict?email_id="+sampleUUID, nil)
	rr := httptest.NewRecorder()
	h.handleByEmailID(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing principal: want 401, got %d", rr.Code)
	}
}

func TestVerdict_MissingEmailID_400(t *testing.T) {
	t.Parallel()
	h := newHandler()
	req := httptest.NewRequest(http.MethodGet, "/verdict", nil)
	req = withPrincipal(req, 1)
	rr := httptest.NewRecorder()
	h.handleByEmailID(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing email_id: want 400, got %d", rr.Code)
	}
}

func TestVerdict_NonUUIDEmailID_400(t *testing.T) {
	t.Parallel()
	h := newHandler()
	req := httptest.NewRequest(http.MethodGet, "/verdict?email_id=not-a-uuid", nil)
	req = withPrincipal(req, 1)
	rr := httptest.NewRecorder()
	h.handleByEmailID(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("non-uuid email_id: want 400, got %d", rr.Code)
	}
}

const sampleUUID = "018f3a2b-7c1d-7e2a-9b4c-0123456789ab"
