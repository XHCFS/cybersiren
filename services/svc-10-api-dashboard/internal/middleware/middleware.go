// Package middleware holds the SVC-10 Gin middleware: CORS, request logging, a
// Redis rate limiter, and JWT authentication backed by shared/auth.
package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/saif/cybersiren/shared/auth"
)

const (
	ctxOrgID  = "auth_org_id"
	ctxUserID = "auth_user_id"
)

// CORS allows the configured origins (or all when none are configured — dev).
func CORS(origins []string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(origins))
	for _, o := range origins {
		allowed[o] = true
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && (len(allowed) == 0 || allowed[origin]) {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Authorization,Content-Type,X-API-Key")
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// Logger logs one structured line per request (method, path, status, latency).
func Logger(log zerolog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.Info().
			Str("method", c.Request.Method).
			Str("path", c.Request.URL.Path).
			Int("status", c.Writer.Status()).
			Dur("latency", time.Since(start)).
			Msg("http request")
	}
}

// RateLimit applies a per-client fixed-window limit in Valkey (keyed by client
// IP, since it runs before auth). It fails open on a cache error so a Redis blip
// never takes the API down.
func RateLimit(vk valkeygo.Client, log zerolog.Logger, perMinute int) gin.HandlerFunc {
	return func(c *gin.Context) {
		if vk == nil || perMinute <= 0 {
			c.Next()
			return
		}
		key := fmt.Sprintf("apirate:{%s}:%d", c.ClientIP(), time.Now().Unix()/60)
		count, err := vk.Do(c.Request.Context(), vk.B().Incr().Key(key).Build()).ToInt64()
		if err != nil {
			log.Warn().Err(err).Msg("rate-limit check failed; allowing")
			c.Next()
			return
		}
		if count == 1 {
			_ = vk.Do(c.Request.Context(), vk.B().Expire().Key(key).Seconds(60).Build()).Error()
		}
		if count > int64(perMinute) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		c.Next()
	}
}

// RequireJWT authenticates a Bearer JWT and stores org_id/user_id on the gin
// context for handlers. A missing or invalid token aborts with 401.
func RequireJWT(a *auth.Authenticator) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := bearer(c.GetHeader("Authorization"))
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		claims, err := a.VerifyJWT(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		c.Set(ctxOrgID, claims.OrgID)
		c.Set(ctxUserID, claims.UserID)
		c.Next()
	}
}

// OrgID returns the authenticated org id from the gin context (0 if absent).
func OrgID(c *gin.Context) int64 {
	v, ok := c.Get(ctxOrgID)
	if !ok {
		return 0
	}
	id, _ := v.(int64)
	return id
}

// UserID returns the authenticated user id from the gin context (0 if absent).
func UserID(c *gin.Context) int64 {
	v, ok := c.Get(ctxUserID)
	if !ok {
		return 0
	}
	id, _ := v.(int64)
	return id
}

func bearer(h string) string {
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}
