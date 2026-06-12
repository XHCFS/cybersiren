package gmail

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/saif/cybersiren/shared/rfc822"
)

// decodeB64 decodes a standard-base64 string (used for the emails.raw
// raw_rfc822 field, which the core encodes with StdEncoding).
func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode std base64: %v", err)
	}
	return b
}

// TestDecodeRawRFC822_WebSafe asserts the adapter decodes Gmail's web-safe
// (URL-safe, unpadded) base64 raw field and recovers the Message-ID.
func TestDecodeRawRFC822_WebSafe(t *testing.T) {
	original := "From: a@b.test\r\nMessage-ID: <id-1@b.test>\r\nSubject: hi\r\n\r\nbody"
	// Gmail emits URL-safe base64 without padding.
	webSafe := base64.RawURLEncoding.EncodeToString([]byte(original))

	got, err := decodeRawRFC822(webSafe)
	if err != nil {
		t.Fatalf("decodeRawRFC822: %v", err)
	}
	if string(got) != original {
		t.Errorf("decoded = %q, want %q", string(got), original)
	}
	if mid := rfc822.MessageID(got); mid != "id-1@b.test" {
		t.Errorf("message_id = %q, want id-1@b.test (brackets stripped)", mid)
	}
}

// TestDecodeRawRFC822_PaddedAndEmpty covers the padded fallback and the empty
// guard.
func TestDecodeRawRFC822_PaddedAndEmpty(t *testing.T) {
	padded := base64.URLEncoding.EncodeToString([]byte("hello"))
	got, err := decodeRawRFC822(padded)
	if err != nil || string(got) != "hello" {
		t.Errorf("padded decode = %q, %v; want hello, nil", string(got), err)
	}
	if _, err := decodeRawRFC822("   "); err == nil {
		t.Error("empty raw must error")
	}
}

// TestMessageIDFromRaw_Absent asserts an unparseable / header-less message
// yields "" (not deduplicated) rather than erroring.
func TestMessageIDFromRaw_Absent(t *testing.T) {
	if mid := rfc822.MessageID([]byte("not a valid email")); mid != "" {
		t.Errorf("message_id = %q, want empty for header-less message", mid)
	}
}

// TestTokenSource_RefreshAndCache asserts the token source mints from the
// refresh token and caches the result (one token call for two reads).
func TestTokenSource_RefreshAndCache(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %q, want refresh_token", r.Form.Get("grant_type"))
		}
		if r.Form.Get("refresh_token") != "rt-123" {
			t.Errorf("refresh_token = %q, want rt-123", r.Form.Get("refresh_token"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-xyz","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	ts := newTokenSource("cid", "secret", "rt-123", srv.URL, srv.Client())
	tok, err := ts.token(context.Background())
	if err != nil || tok != "at-xyz" {
		t.Fatalf("token = %q, %v; want at-xyz, nil", tok, err)
	}
	if _, err := ts.token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("token endpoint called %d times, want 1 (cached)", calls)
	}
}

// TestTokenSource_ErrorBody surfaces an OAuth error payload.
func TestTokenSource_ErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Token has been expired or revoked."}`))
	}))
	defer srv.Close()

	ts := newTokenSource("cid", "secret", "bad", srv.URL, srv.Client())
	if _, err := ts.token(context.Background()); err == nil {
		t.Fatal("expected an error for invalid_grant")
	}
}

// TestVerifyPush_Token covers the shared-secret token gate.
func TestVerifyPush_Token(t *testing.T) {
	a := &Adapter{opts: Options{PushToken: "s3cret"}}

	pass := httptest.NewRequest(http.MethodPost, "/gmail/push?token=s3cret", nil)
	if !a.verifyPush(pass) {
		t.Error("matching token must pass")
	}
	fail := httptest.NewRequest(http.MethodPost, "/gmail/push?token=wrong", nil)
	if a.verifyPush(fail) {
		t.Error("wrong token must fail")
	}
	none := httptest.NewRequest(http.MethodPost, "/gmail/push", nil)
	if a.verifyPush(none) {
		t.Error("missing token must fail when a token is configured")
	}
}

// TestVerifyPush_FailsClosedWhenUnconfigured asserts that an endpoint with NO
// verification configured rejects every caller (fail-closed). The /gmail/push
// route is bound outside the API-key middleware, so an open default would be a
// public, unauthenticated trigger for Gmail API traffic.
func TestVerifyPush_FailsClosedWhenUnconfigured(t *testing.T) {
	a := &Adapter{opts: Options{}}
	req := httptest.NewRequest(http.MethodPost, "/gmail/push", nil)
	if a.verifyPush(req) {
		t.Error("unconfigured endpoint must reject (fail-closed), not accept")
	}

	// Even a request bearing a token/JWT must be rejected when nothing is
	// configured to check against.
	withToken := httptest.NewRequest(http.MethodPost, "/gmail/push?token=anything", nil)
	if a.verifyPush(withToken) {
		t.Error("unconfigured endpoint must reject even a token-bearing caller")
	}
}

// TestVerifyPush_Audience covers the OIDC-audience defence-in-depth check.
func TestVerifyPush_Audience(t *testing.T) {
	a := &Adapter{opts: Options{PushAudience: "https://svc-01.example/gmail/push"}}

	jwt := makeUnsignedJWT(t, map[string]any{"aud": "https://svc-01.example/gmail/push"})
	pass := httptest.NewRequest(http.MethodPost, "/gmail/push", nil)
	pass.Header.Set("Authorization", "Bearer "+jwt)
	if !a.verifyPush(pass) {
		t.Error("matching audience must pass")
	}

	bad := makeUnsignedJWT(t, map[string]any{"aud": "https://attacker.example"})
	fail := httptest.NewRequest(http.MethodPost, "/gmail/push", nil)
	fail.Header.Set("Authorization", "Bearer "+bad)
	if a.verifyPush(fail) {
		t.Error("wrong audience must fail")
	}
}

// TestHandlePush_RejectsBadMethodAndToken asserts the HTTP guards.
func TestHandlePush_RejectsBadMethodAndToken(t *testing.T) {
	a := newAdapter(t, newGmailFixtureServer(t), &recordingPublisher{}, &fakeDedup{fresh: true}, NewMemoryHistoryStore())

	// GET → 405.
	get := httptest.NewRequest(http.MethodGet, "/gmail/push?token=shared-secret", nil)
	rr := httptest.NewRecorder()
	a.handlePush(rr, get)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", rr.Code)
	}

	// Wrong token → 401.
	bad := httptest.NewRequest(http.MethodPost, "/gmail/push?token=nope", nil)
	rr = httptest.NewRecorder()
	a.handlePush(rr, bad)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("bad-token status = %d, want 401", rr.Code)
	}
}

// makeUnsignedJWT builds a JWT with the given claims and a dummy signature
// (verifyPush only reads the unsigned aud claim — see push.go).
func makeUnsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b := mustJSON(t, v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]string{"alg": "RS256", "typ": "JWT"})
	payload := enc(claims)
	return header + "." + payload + ".c2ln" // "sig" base64; unverified
}
