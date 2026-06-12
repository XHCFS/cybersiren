package gmail

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// maxPushBodyBytes caps the Pub/Sub push envelope. The body is a tiny
// {emailAddress, historyId} notification, so 64 KiB is generous.
const maxPushBodyBytes = 64 << 10

// pushEnvelope is the Pub/Sub push-subscription POST body: the actual Gmail
// notification is base64 JSON inside message.data.
type pushEnvelope struct {
	Message struct {
		Data        string `json:"data"`
		MessageID   string `json:"messageId"`
		PublishTime string `json:"publishTime"`
	} `json:"message"`
	Subscription string `json:"subscription"`
}

// gmailNotification is the decoded message.data: which mailbox changed and the
// new historyId. We delta-sync from the stored cursor rather than trusting this
// historyId blindly, so a missed/duplicated push is self-healing.
type gmailNotification struct {
	EmailAddress string `json:"emailAddress"`
	HistoryID    uint64 `json:"historyId"`
}

// handlePush is the Pub/Sub PUSH endpoint (POST /gmail/push). It verifies the
// request, decodes the notification, and triggers a history sync. Verification
// is intentionally before any work so an unverified caller cannot drive Gmail
// API traffic. It always returns 2xx for an accepted-or-ignorable message so
// Pub/Sub does not redeliver indefinitely; a 401/400 is returned only for
// verification/parse failures.
func (a *Adapter) handlePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !a.verifyPush(r) {
		a.log.Warn().Str("remote", r.RemoteAddr).Msg("gmail: push verification failed")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxPushBodyBytes))
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}

	var env pushEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		http.Error(w, "invalid push envelope", http.StatusBadRequest)
		return
	}

	// Decode the inner notification for logging/observability. A decode failure
	// is non-fatal: we still trigger a history sync (the stored cursor drives
	// it), so even a malformed data field self-heals.
	if env.Message.Data != "" {
		if raw, derr := base64.StdEncoding.DecodeString(env.Message.Data); derr == nil {
			var n gmailNotification
			if json.Unmarshal(raw, &n) == nil {
				a.log.Debug().
					Str("mailbox", n.EmailAddress).
					Uint64("notified_history_id", n.HistoryID).
					Str("pubsub_message_id", env.Message.MessageID).
					Msg("gmail: push notification received")
			}
		}
	}

	// Run the sync synchronously and ack. Errors are logged but still ack'd —
	// the fallback poll loop + next push will re-cover any gap, and a 5xx here
	// only causes Pub/Sub to hammer us with redeliveries.
	if err := a.syncHistory(r.Context()); err != nil {
		a.log.Error().Err(err).Msg("gmail: push-triggered sync failed (poll loop will recover)")
	}

	w.WriteHeader(http.StatusNoContent)
}

// verifyPush authenticates an inbound push request. Two mechanisms, checked in
// order; the request passes if EITHER configured check passes (and is rejected
// when a configured check fails OR when nothing is configured at all):
//
//  1. Shared-secret token: the push subscription endpoint is registered as
//     .../gmail/push?token=<secret>; we constant-time-compare the query token.
//  2. OIDC bearer: Google signs the push with a Google-issued OIDC JWT whose
//     `aud` claim is the configured PushAudience. We verify the audience claim
//     here; full signature verification (fetch Google's JWKS, validate
//     iss/exp/signature) is a documented hardening step left as-is for now.
//
// The /gmail/push route is bound OUTSIDE the API-key auth middleware, so this is
// the only gate on it. We therefore fail CLOSED: when neither a token nor an
// audience is configured we reject every caller (an open public endpoint that
// drives Gmail API traffic on demand is not acceptable). The operator is warned
// at startup (see main.go) that the endpoint rejects until one is set.
func (a *Adapter) verifyPush(r *http.Request) bool {
	if a.opts.PushToken != "" {
		got := r.URL.Query().Get("token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(a.opts.PushToken)) == 1 {
			return true
		}
	}

	if a.opts.PushAudience != "" {
		if aud, ok := bearerAudience(r.Header.Get("Authorization")); ok &&
			subtle.ConstantTimeCompare([]byte(aud), []byte(a.opts.PushAudience)) == 1 {
			return true
		}
	}

	// Fail closed: nothing configured → reject (not an open endpoint). Something
	// configured but we reached here → every configured check failed → reject.
	return false
}

// bearerAudience extracts the unverified `aud` claim from a "Bearer <jwt>"
// header. It does NOT verify the signature — that is a documented hardening step
// (fetch Google's JWKS, validate iss/exp/signature). For the demo the shared
// token is the primary gate; the audience check is a defence-in-depth sanity
// check that the JWT at least targets this service.
func bearerAudience(authHeader string) (string, bool) {
	tok, ok := strings.CutPrefix(authHeader, "Bearer ")
	if !ok {
		return "", false
	}
	parts := strings.Split(strings.TrimSpace(tok), ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		Aud string `json:"aud"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return "", false
	}
	return claims.Aud, claims.Aud != ""
}
