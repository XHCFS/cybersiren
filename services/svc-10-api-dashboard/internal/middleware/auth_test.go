package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	sharedauth "github.com/saif/cybersiren/shared/auth"
)

// fakeVerifier returns canned claims/errors for a token, simulating
// shared/auth.Manager without minting real HS256 tokens.
type fakeVerifier struct {
	want   string
	claims *sharedauth.Claims
	err    error
}

func (f *fakeVerifier) Verify(token string) (*sharedauth.Claims, error) {
	if f.err != nil {
		return nil, f.err
	}
	if token != f.want {
		return nil, sharedauth.ErrInvalidToken
	}
	return f.claims, nil
}

// nextProbe records whether the wrapped handler ran and what claims it saw.
func nextProbe() (http.Handler, *bool, **sharedauth.Claims) {
	ran := false
	var seen *sharedauth.Claims
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		if c, ok := ClaimsFromContext(r.Context()); ok {
			seen = c
		}
		w.WriteHeader(http.StatusOK)
	})
	return h, &ran, &seen
}

func TestAuth_MissingToken(t *testing.T) {
	next, ran, _ := nextProbe()
	v := &fakeVerifier{want: "good"}
	h := Auth(v)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil) // no Authorization
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if *ran {
		t.Error("next handler ran despite missing token")
	}
}

func TestAuth_InvalidToken(t *testing.T) {
	next, ran, _ := nextProbe()
	v := &fakeVerifier{want: "good", err: errors.New("bad signature")}
	h := Auth(v)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer tampered")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if *ran {
		t.Error("next handler ran despite invalid token")
	}
}

func TestAuth_ValidToken(t *testing.T) {
	next, ran, seen := nextProbe()
	claims := &sharedauth.Claims{UserID: 7, OrgID: 1, Role: sharedauth.RoleAnalyst, Email: "a@b.c"}
	v := &fakeVerifier{want: "good", claims: claims}
	h := Auth(v)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer good")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !*ran {
		t.Fatal("next handler did not run for a valid token")
	}
	if *seen == nil || (*seen).UserID != 7 || (*seen).OrgID != 1 {
		t.Errorf("claims injected into context = %+v, want uid7/org1", *seen)
	}
}

func TestAuth_NonBearerScheme(t *testing.T) {
	next, ran, _ := nextProbe()
	v := &fakeVerifier{want: "good"}
	h := Auth(v)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz") // not Bearer
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for non-Bearer scheme", rr.Code)
	}
	if *ran {
		t.Error("next handler ran for non-Bearer auth")
	}
}
