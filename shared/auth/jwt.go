package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrJWTNotConfigured is returned by JWT operations when no signing secret was
// provided to New.
var ErrJWTNotConfigured = errors.New("auth: jwt secret not configured")

// ErrInvalidToken is returned when a token fails signature or claim validation.
var ErrInvalidToken = errors.New("auth: invalid token")

// Claims is the CyberSiren JWT payload: the authenticated user and their org,
// plus the standard registered claims (exp/iat).
type Claims struct {
	UserID int64 `json:"uid"`
	OrgID  int64 `json:"org"`
	jwt.RegisteredClaims
}

// IssueJWT signs a token for the given user/org. ttl <= 0 falls back to the
// configured expiry. Tokens are HS256-signed with the Authenticator's secret.
func (a *Authenticator) IssueJWT(userID, orgID int64, ttl time.Duration) (string, error) {
	if len(a.jwtSecret) == 0 {
		return "", ErrJWTNotConfigured
	}
	if ttl <= 0 {
		ttl = a.jwtExpiry
	}
	now := time.Now()
	claims := Claims{
		UserID: userID,
		OrgID:  orgID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.jwtSecret)
	if err != nil {
		return "", fmt.Errorf("auth: sign jwt: %w", err)
	}
	return token, nil
}

// VerifyJWT validates a token's signature and expiry and returns its claims.
// Only HS256 is accepted — rejecting any other alg defends against algorithm
// confusion (e.g. a forged "none" or RS256 token).
func (a *Authenticator) VerifyJWT(token string) (*Claims, error) {
	if len(a.jwtSecret) == 0 {
		return nil, ErrJWTNotConfigured
	}
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(_ *jwt.Token) (any, error) {
		return a.jwtSecret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if !parsed.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
