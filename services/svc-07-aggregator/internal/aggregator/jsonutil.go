package aggregator

import "encoding/json"

// jsonMarshal is the package-private indirection used by the var-overrideable
// marshalEmailsScored. Wrapping encoding/json.Marshal lets tests substitute
// without exporting an entire codec interface.
func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}
