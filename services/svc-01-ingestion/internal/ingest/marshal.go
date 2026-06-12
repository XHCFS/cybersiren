package ingest

import (
	"encoding/json"
	"fmt"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// marshalEmailsRaw serialises an emails.raw payload. Isolated so the Ingest body
// reads as the auth/dedup/quota/publish flow without a JSON detour.
func marshalEmailsRaw(p contracts.EmailsRaw) ([]byte, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal emails.raw: %w", err)
	}
	return body, nil
}
