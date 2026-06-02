// Package auth provides the shared authentication primitives consumed by both
// SVC-01 ingestion and the SVC-10 API: API-key hashing + lookup against the
// api_keys table, JWT issue/verify, and net/http middleware. Centralising these
// keeps the two services on one implementation (ARCH-SPEC §1 step 1).
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/shared/config"
)

// Authentication failures. They are deliberately coarse so handlers can map any
// of them to 401 without leaking which check failed.
var (
	// ErrKeyNotFound is returned when no api_keys row matches the presented key.
	ErrKeyNotFound = errors.New("auth: api key not found")
	// ErrKeyRevoked is returned for a key whose revoked_at is set.
	ErrKeyRevoked = errors.New("auth: api key revoked")
	// ErrKeyExpired is returned for a key past its expires_at.
	ErrKeyExpired = errors.New("auth: api key expired")
)

// APIKeyQuerier is the slice of the sqlc Queries that API-key auth needs.
// *dbsqlc.Queries satisfies it; tests provide a fake.
type APIKeyQuerier interface {
	GetAPIKeyByHash(ctx context.Context, keyHash string) (dbsqlc.GetAPIKeyByHashRow, error)
	TouchAPIKeyLastUsed(ctx context.Context, id int64) error
}

// Authenticator validates API keys and issues/verifies JWTs. It is the single
// auth entry point shared by SVC-01 and SVC-10. A zero jwtSecret disables JWT
// operations (they return an error) but API-key auth still works.
type Authenticator struct {
	q         APIKeyQuerier
	jwtSecret []byte
	jwtExpiry time.Duration
}

// New builds an Authenticator from the api_keys querier and AuthConfig. The
// querier may be nil for JWT-only use (e.g. token verification middleware).
func New(q APIKeyQuerier, cfg config.AuthConfig) *Authenticator {
	expiry := cfg.JWTExpiry
	if expiry <= 0 {
		expiry = 24 * time.Hour
	}
	return &Authenticator{q: q, jwtSecret: []byte(cfg.JWTSecret), jwtExpiry: expiry}
}

// HashKey returns the hex-encoded sha256 of a plaintext API key. API keys are
// high-entropy random strings, so a fast deterministic hash (not bcrypt) is
// used: bcrypt is salted — which prevents the by-hash lookup — and too slow for
// a per-request check. The plaintext is never stored.
func HashKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// GenerateKey mints a new API key: a `prefix`-prefixed random string. It returns
// the plaintext (shown to the user once), the key_prefix to store for
// identification, and the key_hash to persist. suffixLen is the number of random
// bytes; the api_keys.key_prefix column stores exactly 8 chars.
func GenerateKey(prefix string, suffixLen int) (plaintext, keyPrefix, keyHash string, err error) {
	if suffixLen <= 0 {
		suffixLen = 24
	}
	buf := make([]byte, suffixLen)
	if _, err = rand.Read(buf); err != nil {
		return "", "", "", fmt.Errorf("auth: generate api key: %w", err)
	}
	plaintext = prefix + base64.RawURLEncoding.EncodeToString(buf)
	keyPrefix = plaintext
	if len(keyPrefix) > 8 {
		keyPrefix = keyPrefix[:8]
	}
	return plaintext, keyPrefix, HashKey(plaintext), nil
}

// APIKeyResult is the identity resolved from a valid API key.
type APIKeyResult struct {
	KeyID  int64
	OrgID  int64
	UserID int64 // 0 when the key is org-level (not tied to a user)
	Scopes []string
}

// LookupAPIKey validates a plaintext API key and returns its identity. It
// rejects revoked and expired keys, and records last_used_at on success
// (best-effort: a touch failure is not fatal to the auth decision but is
// surfaced so callers can log it). A nil error means the key is valid.
func (a *Authenticator) LookupAPIKey(ctx context.Context, plaintext string) (APIKeyResult, error) {
	if plaintext == "" || a.q == nil {
		return APIKeyResult{}, ErrKeyNotFound
	}
	row, err := a.q.GetAPIKeyByHash(ctx, HashKey(plaintext))
	if err != nil {
		// Any lookup error (incl. no rows) is an auth failure, not a 500.
		return APIKeyResult{}, ErrKeyNotFound
	}
	if row.RevokedAt.Valid {
		return APIKeyResult{}, ErrKeyRevoked
	}
	if row.ExpiresAt.Valid && !row.ExpiresAt.Time.After(time.Now()) {
		return APIKeyResult{}, ErrKeyExpired
	}

	if err := a.q.TouchAPIKeyLastUsed(ctx, row.ID); err != nil {
		// Don't fail auth on a metadata write error; report it for logging.
		return resultFrom(row), fmt.Errorf("auth: touch last_used_at: %w", err)
	}
	return resultFrom(row), nil
}

func resultFrom(row dbsqlc.GetAPIKeyByHashRow) APIKeyResult {
	return APIKeyResult{
		KeyID:  row.ID,
		OrgID:  row.OrgID,
		UserID: row.UserID.Int64, // 0 when NULL
		Scopes: row.Scopes,
	}
}

// HasScope reports whether scopes grants want. A "*" scope grants everything.
// The comparison is constant-time per entry to avoid leaking scope contents via
// timing (cheap given the tiny set).
func HasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == "*" {
			return true
		}
		if subtle.ConstantTimeCompare([]byte(s), []byte(want)) == 1 {
			return true
		}
	}
	return false
}
