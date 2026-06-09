package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// issuer is stamped into the "iss" claim and required on verification so a
// token minted for a different CyberSiren deployment/audience is rejected even
// if it happened to share a secret.
const issuer = "cybersiren"

// MinJWTSecretLen is the smallest HS256 signing secret NewManager accepts. HS256
// security rests entirely on the secret's entropy; RFC 7518 §3.2 requires a key
// at least as long as the hash output (32 bytes for SHA-256). A shorter secret
// is offline-brute-forceable, which would allow full token forgery and defeat
// tenant isolation, so it is rejected at construction. shared/config mirrors
// this floor in Config.Validate via this exported constant so the two cannot
// drift.
const MinJWTSecretLen = 32

// Claims is the typed JWT payload for an authenticated dashboard user. The
// custom fields sit alongside the standard registered claims (exp/iat/iss/sub).
//
// Subject (sub) carries the user_id as a string for interoperability; UserID
// is the same value in numeric form for convenient use by callers.
type Claims struct {
	UserID int64  `json:"uid"`
	OrgID  int64  `json:"org"`
	Role   Role   `json:"role"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// Validate implements jwt.ClaimsValidator so role/tenant invariants are checked
// as part of parsing (after signature + time-based validation succeed).
func (c Claims) Validate() error {
	if c.UserID <= 0 {
		return errors.New("uid must be positive")
	}
	if c.OrgID <= 0 {
		return errors.New("org must be positive")
	}
	if !c.Role.Valid() {
		return fmt.Errorf("unknown role %q", c.Role)
	}
	return nil
}

// Manager issues and verifies JWTs using a single HMAC (HS256) secret. It is
// safe for concurrent use: it holds only immutable configuration.
type Manager struct {
	secret []byte
	expiry time.Duration
	now    func() time.Time // injectable clock; defaults to time.Now
}

// NewManager builds a Manager from the JWT half of shared/config.AuthConfig.
// secret is AuthConfig.JWTSecret and expiry is AuthConfig.JWTExpiry. An empty
// secret is rejected (ErrEmptySecret) and a non-empty secret shorter than
// MinJWTSecretLen is rejected (ErrWeakSecret) so a misconfigured service fails
// fast instead of minting brute-forceable tokens; a non-positive expiry falls
// back to 24h so a misconfigured zero value never mints non-expiring tokens.
func NewManager(secret string, expiry time.Duration) (*Manager, error) {
	if secret == "" {
		return nil, ErrEmptySecret
	}
	if len(secret) < MinJWTSecretLen {
		return nil, fmt.Errorf("%w: need at least %d bytes, got %d", ErrWeakSecret, MinJWTSecretLen, len(secret))
	}
	if expiry <= 0 {
		expiry = 24 * time.Hour
	}
	return &Manager{
		secret: []byte(secret),
		expiry: expiry,
		now:    time.Now,
	}, nil
}

// Issue mints a signed token for the given identity. The exp claim is set to
// now+expiry. UserID/OrgID must be positive and role must be known, otherwise
// the resulting token would be rejected by its own Validate on verify.
func (m *Manager) Issue(userID, orgID int64, role Role, email string) (string, error) {
	now := m.now()
	claims := Claims{
		UserID: userID,
		OrgID:  orgID,
		Role:   role,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", userID),
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.expiry)),
		},
	}
	if err := claims.Validate(); err != nil {
		return "", fmt.Errorf("auth: refusing to issue token: %w", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("auth: sign token: %w", err)
	}
	return signed, nil
}

// Verify parses and validates a token string, returning its claims on success.
// Validation pins the signing method to HS256 (defeating the alg=none and
// HMAC/RSA-confusion attacks), requires a non-empty expiry, and enforces the
// expected issuer. Any failure is reported as ErrInvalidToken with the
// underlying cause wrapped for logging.
func (m *Manager) Verify(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, ErrEmptyCredential
	}
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(t *jwt.Token) (any, error) { return m.secret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
