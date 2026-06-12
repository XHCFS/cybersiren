package gmail

import (
	"encoding/base64"
	"fmt"
	"net/mail"
	"strings"
)

// decodeRawRFC822 decodes the web-safe-base64 `raw` field of a Gmail
// messages.get?format=raw reply into the verbatim RFC-822 message bytes. Gmail
// uses URL-safe base64 (RFC 4648 §5: '-'/'_' instead of '+'/'/') and may omit
// padding, so we tolerate both padded and raw encodings.
func decodeRawRFC822(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty raw message")
	}
	// Try the unpadded URL-safe alphabet first (what Gmail emits), then fall
	// back to the padded variant in case a caller normalised it.
	if b, err := base64.RawURLEncoding.DecodeString(raw); err == nil {
		return b, nil
	}
	b, err := base64.URLEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode web-safe base64: %w", err)
	}
	return b, nil
}

// messageIDFromRaw extracts the RFC 5322 Message-ID from an RFC-822 message,
// stripping the angle brackets so the dedup key matches svc-02's
// email_identities registration (which trims "<>"). Returns "" when the header
// is absent or the message is unparseable — such messages are simply not
// deduplicated (mirrors the API-upload adapter).
func messageIDFromRaw(raw []byte) string {
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return ""
	}
	return strings.Trim(msg.Header.Get("Message-Id"), "<>")
}
