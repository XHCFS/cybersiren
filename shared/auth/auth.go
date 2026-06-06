package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	OrgID  int64    `json:"org_id"`
	UserID int64    `json:"user_id"`
	Email  string   `json:"email"`
	Scopes []string `json:"scopes"`
	jwt.RegisteredClaims
}

func IssueJWT(claims Claims, secret string, ttl time.Duration) (string, error) {
	panic("not implemented")
}

func VerifyJWT(token, secret string) (*Claims, error) {
	panic("not implemented")
}

func HashAPIKey(rawKey string) string {
	panic("not implemented")
}

func ValidateAPIKey(rawKey, storedHash string) bool {
	panic("not implemented")
}
