package aggregator

import (
	"encoding/json"
	"fmt"
)

// jsonMarshal is the package-private indirection used by the var-overrideable
// marshalEmailsScored. Wrapping encoding/json.Marshal lets tests substitute
// without exporting an entire codec interface.
func jsonMarshal(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("json marshal: %w", err)
	}
	return b, nil
}
