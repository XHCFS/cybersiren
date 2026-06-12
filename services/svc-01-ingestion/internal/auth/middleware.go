// Package auth is svc-01's API-key authentication middleware. It resolves the
// presented key to an org via the api_keys control-plane table and binds the
// org id + api_keys.id onto the request context. org is ALWAYS taken from the
// key, never from the request body (G10 / RLS): a client cannot spoof a tenant.
package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"

	sharedauth "github.com/saif/cybersiren/shared/auth"
)

// ctxKey is the unexported context-key type for the authenticated principal.
type ctxKey int

const principalKey ctxKey = 0

// Principal is the authenticated identity bound onto the request context: the
// owning tenant (org_id) and the api_keys.id that authenticated, both resolved
// from the presented key. Downstream handlers read org_id from here, NEVER from
// the request body.
type Principal struct {
	OrgID    int64
	APIKeyID int64
}

// KeyReader is the subset of generated db.Queries the middleware needs. Narrowed
// to an interface so the auth flow is unit-testable with a fake store.
type KeyReader interface {
	GetAPIKeyByPrefix(ctx context.Context, keyPrefix string) ([]APIKeyRow, error)
	TouchAPIKeyLastUsed(ctx context.Context, id int64) error
}

// APIKeyRow is the candidate api_keys row used for authentication. It mirrors
// the fields of db.GetAPIKeyByPrefixRow the middleware consumes; the adapter in
// the service maps the generated row onto it so this package does not import the
// generated db package directly.
type APIKeyRow struct {
	ID        int64
	OrgID     int64
	KeyHash   string
	ExpiresAt *time.Time
	RevokedAt *time.Time
}

// Authenticator resolves a presented API key to a Principal.
type Authenticator struct {
	keys KeyReader
	km   *sharedauth.KeyManager
	log  zerolog.Logger
}

// NewAuthenticator builds an Authenticator over the key store and the shared
// KeyManager (which knows the lookup-prefix length and validation rules).
func NewAuthenticator(keys KeyReader, km *sharedauth.KeyManager, log zerolog.Logger) *Authenticator {
	return &Authenticator{keys: keys, km: km, log: log}
}

// ErrUnauthorized is the single opaque auth failure. The middleware never
// distinguishes "no such key" from "bad key"/"revoked"/"expired" on the wire —
// a 401 with no detail — so an attacker cannot probe which keys exist.
var ErrUnauthorized = errors.New("auth: invalid API key")

// Middleware wraps next so every request must present a valid API key. On
// success the Principal is bound onto the request context (read via FromContext)
// and api_keys.last_used_at is touched best-effort. On failure it writes 401 and
// does not call next.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := a.authenticate(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Best-effort: a failure to record last_used_at must not reject the
		// request (the auth decision already stands).
		if touchErr := a.keys.TouchAPIKeyLastUsed(r.Context(), principal.APIKeyID); touchErr != nil {
			a.log.Warn().Err(touchErr).Int64("api_key_id", principal.APIKeyID).
				Msg("failed to touch api_keys.last_used_at")
		}
		next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), principal)))
	})
}

// NewContext binds a Principal onto ctx (read via FromContext). The middleware
// uses it after a successful auth; tests use it to simulate an authenticated
// request without exercising the full key lookup.
func NewContext(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// authenticate extracts the presented key, resolves the candidate row(s) by
// prefix, rejects revoked/expired rows, and bcrypt-validates the plaintext.
func (a *Authenticator) authenticate(r *http.Request) (Principal, error) {
	presented := extractKey(r)
	if presented == "" {
		return Principal{}, ErrUnauthorized
	}

	prefix := a.km.LookupPrefix(presented)
	rows, err := a.keys.GetAPIKeyByPrefix(r.Context(), prefix)
	if err != nil {
		a.log.Error().Err(err).Msg("api_keys prefix lookup failed")
		return Principal{}, ErrUnauthorized
	}

	now := time.Now()
	for _, row := range rows {
		if row.RevokedAt != nil {
			continue // revoked
		}
		if row.ExpiresAt != nil && row.ExpiresAt.Before(now) {
			continue // expired
		}
		// A prefix is selective but not unique; bcrypt-validate against each
		// surviving candidate. The first match wins.
		if validateErr := sharedauth.ValidateKey(presented, row.KeyHash); validateErr == nil {
			return Principal{OrgID: row.OrgID, APIKeyID: row.ID}, nil
		}
	}
	return Principal{}, ErrUnauthorized
}

// extractKey reads the presented key from either Authorization: Bearer <key> or
// X-API-Key: <key>. Authorization wins when both are present.
func extractKey(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if after, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
	}
	return strings.TrimSpace(r.Header.Get("X-API-Key"))
}

// FromContext returns the authenticated Principal bound by Middleware. ok is
// false when the context carries no principal (the route was not wrapped).
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey).(Principal)
	return p, ok
}
