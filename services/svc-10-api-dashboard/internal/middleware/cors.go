package middleware

import "net/http"

// defaultAllowedOrigin is the React SPA dev origin (Vite default port 5173).
// CORS with credentials forbids the "*" wildcard origin, so a SPECIFIC origin
// is echoed back when (and only when) it matches the allow-list.
const defaultAllowedOrigin = "http://localhost:5173"

// CORS wraps next with permissive-but-credentialed CORS for the SPA dev origins.
// It reflects the request Origin only when it is in allowed (never "*" alongside
// Allow-Credentials), sets the standard allow headers/methods, and short-circuits
// the preflight OPTIONS request with 204. An empty allowed list falls back to the
// Vite default origin.
func CORS(allowed ...string) func(http.Handler) http.Handler {
	if len(allowed) == 0 {
		allowed = []string{defaultAllowedOrigin}
	}
	allowSet := make(map[string]struct{}, len(allowed))
	for _, o := range allowed {
		allowSet[o] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if _, ok := allowSet[origin]; ok && origin != "" {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Vary", "Origin")
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				h.Set("Access-Control-Max-Age", "600")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
