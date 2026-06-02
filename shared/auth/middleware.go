package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// ctxKey is an unexported context key type so values can't collide with other
// packages' context entries.
type ctxKey int

const (
	ctxKeyOrgID ctxKey = iota
	ctxKeyUserID
	ctxKeyScopes
)

// OrgIDFromContext returns the authenticated org id, or 0 when unauthenticated.
func OrgIDFromContext(ctx context.Context) int64 {
	v, _ := ctx.Value(ctxKeyOrgID).(int64)
	return v
}

// UserIDFromContext returns the authenticated user id, or 0 for an org-level
// API key or an unauthenticated request.
func UserIDFromContext(ctx context.Context) int64 {
	v, _ := ctx.Value(ctxKeyUserID).(int64)
	return v
}

// ScopesFromContext returns the API-key scopes on the request, or nil.
func ScopesFromContext(ctx context.Context) []string {
	v, _ := ctx.Value(ctxKeyScopes).([]string)
	return v
}

// RequireAPIKey authenticates the request via an API key taken from the
// Authorization: Bearer header or the X-API-Key header, putting org_id, user_id,
// and scopes on the request context. Any failure responds 401.
func (a *Authenticator) RequireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := apiKeyFromRequest(r)
		if key == "" {
			unauthorized(w, "missing api key")
			return
		}
		res, err := a.LookupAPIKey(r.Context(), key)
		if err != nil {
			// A last_used_at touch failure returns a non-nil error with a valid
			// result; treat only an empty result as a rejection.
			if res.OrgID == 0 {
				unauthorized(w, "invalid api key")
				return
			}
		}
		ctx := context.WithValue(r.Context(), ctxKeyOrgID, res.OrgID)
		ctx = context.WithValue(ctx, ctxKeyUserID, res.UserID)
		ctx = context.WithValue(ctx, ctxKeyScopes, res.Scopes)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireJWT authenticates the request via a Bearer JWT, putting org_id and
// user_id on the context. Any failure responds 401.
func (a *Authenticator) RequireJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			unauthorized(w, "missing bearer token")
			return
		}
		claims, err := a.VerifyJWT(token)
		if err != nil {
			unauthorized(w, "invalid token")
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyOrgID, claims.OrgID)
		ctx = context.WithValue(ctx, ctxKeyUserID, claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireScope guards a handler behind an API-key scope. It must run after
// RequireAPIKey. A missing scope responds 403.
func (a *Authenticator) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !HasScope(ScopesFromContext(r.Context()), scope) {
				writeJSONError(w, http.StatusForbidden, "missing required scope: "+scope)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// apiKeyFromRequest extracts an API key from X-API-Key or a Bearer header.
func apiKeyFromRequest(r *http.Request) string {
	if k := strings.TrimSpace(r.Header.Get("X-API-Key")); k != "" {
		return k
	}
	return bearerToken(r)
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

func unauthorized(w http.ResponseWriter, msg string) {
	writeJSONError(w, http.StatusUnauthorized, msg)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
