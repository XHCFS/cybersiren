package handlers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-10-api-dashboard/internal/middleware"
	sharedauth "github.com/saif/cybersiren/shared/auth"
)

// Issuer is the subset of shared/auth.Manager the login handler needs to mint a
// session token. Narrowed to an interface for testability.
type Issuer interface {
	Issue(userID, orgID int64, role sharedauth.Role, email string) (string, error)
}

// API holds the shared dependencies for the console handlers.
type API struct {
	Reader ConsoleReader
	Issuer Issuer
	Log    zerolog.Logger
	// OrgID is the single hardcoded tenant (MVP-1) used to resolve the login
	// user. Post-login, org scoping always comes from the verified JWT claim.
	OrgID int64
	// Scan is the scan-submission proxy to svc-01.
	Scan *ScanForwarder
}

// loginRequest is the POST /api/v1/auth/login body.
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// loginResponse is returned on a successful login.
type loginResponse struct {
	Token string   `json:"token"`
	User  AuthUser `json:"user"`
}

// maxLoginBody caps the login request body.
const maxLoginBody = 1 << 16

// HandleLogin authenticates (email, password) against the single MVP-1 org and
// returns a signed JWT + the user record. Any failure returns a generic 401 so
// the caller cannot tell an unknown user from a wrong password.
func (a *API) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxLoginBody))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	var req loginRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, errBody("email and password are required"))
		return
	}

	user, err := a.Reader.Login(r.Context(), a.OrgID, req.Email, req.Password)
	if err != nil {
		// Generic message for every failure (unknown user / wrong password /
		// NULL hash) — never reveal which field was wrong.
		writeJSON(w, http.StatusUnauthorized, errBody("invalid email or password"))
		return
	}

	token, err := a.Issuer.Issue(user.ID, user.OrgID, sharedauth.Role(user.Role), user.Email)
	if err != nil {
		a.Log.Error().Err(err).Int64("user_id", user.ID).Msg("failed to mint session token")
		writeJSON(w, http.StatusInternalServerError, errBody("could not issue token"))
		return
	}
	writeJSON(w, http.StatusOK, loginResponse{Token: token, User: user})
}

// HandleMe returns the current user derived from the verified JWT claims. The
// auth middleware guarantees claims are present.
func (a *API) HandleMe(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, AuthUser{
		ID:    claims.UserID,
		Email: claims.Email,
		Role:  string(claims.Role),
		OrgID: claims.OrgID,
	})
}

// writeJSON renders v as JSON with the given status.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errBody(msg string) map[string]string {
	return map[string]string{"error": msg}
}
