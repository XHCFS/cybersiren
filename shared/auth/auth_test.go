package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var _ jwt.Claims = (*Claims)(nil)
var _ func(Claims, string, time.Duration) (string, error) = IssueJWT
var _ func(string, string) (*Claims, error) = VerifyJWT
var _ func(string) string = HashAPIKey
var _ func(string, string) bool = ValidateAPIKey

func TestClaimsFields(t *testing.T) {
	claims := Claims{
		OrgID:  42,
		UserID: 7,
		Email:  "analyst@example.com",
		Scopes: []string{"emails:read", "rules:write"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "cybersiren",
		},
	}

	if claims.OrgID != 42 || claims.UserID != 7 || claims.Email != "analyst@example.com" {
		t.Fatalf("claims identity fields were not retained: %+v", claims)
	}
	if len(claims.Scopes) != 2 || claims.Scopes[0] != "emails:read" || claims.Scopes[1] != "rules:write" {
		t.Fatalf("claims scopes were not retained: %+v", claims.Scopes)
	}
	if claims.Issuer != "cybersiren" {
		t.Fatalf("registered claims were not embedded: issuer=%q", claims.Issuer)
	}
}
