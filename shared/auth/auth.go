// Package auth provides the authentication primitives shared by the API-facing
// services: JSON Web Token (JWT) issue/verify for interactive dashboard users
// (svc-10) and API-key hash/validate for machine callers (svc-01).
//
// The package is deliberately self-contained and stateless: it never touches
// the database. Callers load secrets/parameters from shared/config's
// AuthConfig and pass them in. Storage of users and api_keys rows, and the
// org-scoping that follows a successful authentication, are the caller's
// concern (and, for the DB layer, RLS enforced via app.current_org_id — G10).
//
// Two distinct credential types live here:
//
//   - JWT — a signed bearer token carrying the authenticated user's identity
//     (user_id, org_id, role, email). Issued at login, verified on every
//     request. See jwt.go.
//   - API key — an opaque secret of the form "<prefix><random>" (e.g.
//     "cs_AbC123…"). Only a bcrypt hash of the full key is persisted
//     (api_keys.key_hash); the human-readable lookup fragment is persisted in
//     api_keys.key_prefix. See apikey.go.
package auth

import "errors"

// Role mirrors the database user_role enum (migration 002): admin, analyst,
// viewer. It is carried in JWT claims so downstream authorisation checks do
// not need a DB round-trip for coarse role gating.
type Role string

const (
	RoleAdmin   Role = "admin"
	RoleAnalyst Role = "analyst"
	RoleViewer  Role = "viewer"
)

// Valid reports whether r is one of the known roles.
func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleAnalyst, RoleViewer:
		return true
	default:
		return false
	}
}

// String returns the role as its enum string.
func (r Role) String() string { return string(r) }

// Sentinel errors. Callers should compare with errors.Is rather than string
// matching so the underlying library errors can stay wrapped.
var (
	// ErrInvalidToken is returned when a JWT fails to parse, has a bad
	// signature, is expired, or carries malformed claims.
	ErrInvalidToken = errors.New("auth: invalid token")
	// ErrInvalidAPIKey is returned when an API key does not match the stored
	// hash or is structurally malformed.
	ErrInvalidAPIKey = errors.New("auth: invalid api key")
	// ErrEmptySecret is returned when a Manager/Hasher is constructed without
	// the secret material it requires.
	ErrEmptySecret = errors.New("auth: signing secret must not be empty")
	// ErrWeakSecret is returned when a non-empty JWT signing secret is shorter
	// than MinJWTSecretLen — too little entropy to resist offline brute-forcing
	// of HS256 tokens.
	ErrWeakSecret = errors.New("auth: signing secret too short")
	// ErrEmptyCredential is returned when an empty token/key is passed for
	// verification.
	ErrEmptyCredential = errors.New("auth: empty credential")
)
