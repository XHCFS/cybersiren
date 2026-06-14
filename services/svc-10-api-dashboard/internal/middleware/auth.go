// Package middleware holds the svc-10 analyst-console HTTP middleware: JWT
// authentication, CORS for the SPA dev origin, and request logging.
package middleware

import (
	"context"
	"net/http"
	"strings"

	sharedauth "github.com/saif/cybersiren/shared/auth"
)

// ctxKey is the unexported context-key type for the authenticated claims.
type ctxKey int

const claimsKey ctxKey = 0

// Verifier is the subset of shared/auth.Manager the auth middleware needs.
// Narrowed to an interface so handlers/tests can inject a fake without minting
// real HS256 tokens.
type Verifier interface {
	Verify(token string) (*sharedauth.Claims, error)
}

// Auth wraps next so every request must present a valid Bearer JWT. On success
// the verified *Claims are bound onto the request context (read via
// ClaimsFromContext); on a missing/malformed/invalid token it writes 401 and
// does not call next. The failure response is deliberately generic so a caller
// cannot distinguish "no token" from "bad token".
func Auth(v Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerToken(r)
			if token == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			claims, err := v.Verify(token)
			if err != nil || claims == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
		})
	}
}

// bearerToken extracts the token from "Authorization: Bearer <token>".
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}

// WithClaims binds verified claims onto ctx. Used by the middleware on success
// and by tests to simulate an authenticated request.
func WithClaims(ctx context.Context, c *sharedauth.Claims) context.Context {
	return context.WithValue(ctx, claimsKey, c)
}

// ClaimsFromContext returns the verified claims bound by Auth. ok is false when
// the request was not authenticated (route not wrapped).
func ClaimsFromContext(ctx context.Context) (*sharedauth.Claims, bool) {
	c, ok := ctx.Value(claimsKey).(*sharedauth.Claims)
	return c, ok && c != nil
}
