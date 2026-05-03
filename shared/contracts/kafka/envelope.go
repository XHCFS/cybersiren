package kafka

import "time"

// SchemaVersion is the current envelope schema version. Bump when any wire
// shape is broken; downstream consumers may reject mismatched versions.
const SchemaVersion = 1

// MessageMeta is the envelope embedded in every pipeline message that uses
// the spine v0 generic shape (URLs, Text, Plan, scores.*, scored, verdict).
// It does NOT cover analysis.headers / scores.header — those use the
// flatter AnalysisHeadersMessage / ScoresHeaderMessage types from
// header.go (svc-04's authoritative contract).
//
// EmailID and OrgID are int64 BIGINT values so they line up with the
// emails.internal_id / orgs.id PKs used by svc-04 and svc-08 when they
// write to Postgres. The aggregator (svc-07) carries them along as the
// partition key on every produce.
type MessageMeta struct {
	EmailID       int64     `json:"email_id"`
	OrgID         int64     `json:"org_id"`
	Timestamp     time.Time `json:"timestamp"`
	TraceID       string    `json:"trace_id,omitempty"`
	SpanID        string    `json:"span_id,omitempty"`
	SchemaVersion int       `json:"schema_version"`
}

// NewMeta returns a MessageMeta with Timestamp = now and SchemaVersion set.
// TraceID/SpanID are filled in by the producer wrapper from the active span.
func NewMeta(emailID, orgID int64) MessageMeta {
	return MessageMeta{
		EmailID:       emailID,
		OrgID:         orgID,
		Timestamp:     time.Now().UTC(),
		SchemaVersion: SchemaVersion,
	}
}
