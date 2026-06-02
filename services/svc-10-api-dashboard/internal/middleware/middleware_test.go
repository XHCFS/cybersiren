package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/saif/cybersiren/shared/auth"
	"github.com/saif/cybersiren/shared/config"
)

func testRouter(a *auth.Authenticator) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/protected", RequireJWT(a), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"org": OrgID(c), "user": UserID(c)})
	})
	return r
}

func TestRequireJWT(t *testing.T) {
	t.Parallel()
	a := auth.New(nil, config.AuthConfig{JWTSecret: "test-secret", JWTExpiry: time.Hour})
	tok, err := a.IssueJWT(11, 7, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	r := testRouter(a)

	t.Run("valid token → 200 + context", func(t *testing.T) {
		t.Parallel()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d body %s, want 200", rr.Code, rr.Body.String())
		}
	})

	for _, tc := range []struct {
		name, hdr string
	}{
		{"missing", ""},
		{"garbage", "Bearer not.a.jwt"},
		{"wrong scheme", "Basic abc"},
	} {
		tc := tc
		t.Run(tc.name+" → 401", func(t *testing.T) {
			t.Parallel()
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if tc.hdr != "" {
				req.Header.Set("Authorization", tc.hdr)
			}
			r.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rr.Code)
			}
		})
	}
}
