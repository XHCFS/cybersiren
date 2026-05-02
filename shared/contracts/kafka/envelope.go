package kafkacontracts

import "time"

// SchemaVersion is the current envelope schema version. Bump when any wire
// shape is broken; downstream consumers may reject mismatched versions.
const SchemaVersion = 1

// MessageMeta is the envelope embedded in every pipeline message. The
// partition key for every message in this pipeline is EmailID.
type MessageMeta struct {
	EmailID       string    `json:"email_id"`
	OrgID         string    `json:"org_id"`
	Timestamp     time.Time `json:"timestamp"`
	TraceID       string    `json:"trace_id,omitempty"`
	SpanID        string    `json:"span_id,omitempty"`
	SchemaVersion int       `json:"schema_version"`
}

// NewMeta returns a MessageMeta with Timestamp = now and SchemaVersion set.
// TraceID/SpanID are filled in by the producer wrapper from the active span.
func NewMeta(emailID, orgID string) MessageMeta {
	return MessageMeta{
		EmailID:       emailID,
		OrgID:         orgID,
		Timestamp:     time.Now().UTC(),
		SchemaVersion: SchemaVersion,
	}
}
