package gmail

import (
	"encoding/base64"
	"fmt"
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
