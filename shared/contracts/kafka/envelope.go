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
// OrgID is an int64 BIGINT that lines up with the orgs.id PK used by svc-04
// and svc-08 when they write to Postgres. EmailID is the canonical email
// identifier: per ARCH-SPEC §1 its contract type is a UUIDv7 string (#142).
// The aggregator (svc-07) carries both along as the partition key on every
// produce.
//
// FetchedAt is emails.fetched_at (partition discriminator on the emails
// table). Producers SHOULD set this on analysis.plans and every scores.*
// envelope meta so svc-07 can forward it verbatim on emails.scored; when
// omitted, downstream consumers cannot address partitioned rows reliably.
type MessageMeta struct {
	// EmailID is the canonical, logical email identifier. ARCH-SPEC §1
	// (Canonical Identifier Strategy) pins its contract type as a UUIDv7
	// string: assigned once by SVC-01 (uuid.NewV7()), carried verbatim in
	// every Kafka message and Redis key, and used as the partition key end to
	// end. It is distinct from the Postgres row identity (emails.internal_id
	// BIGINT + fetched_at), which travels alongside it on emails.scored.
	// Downstream code must treat it as an opaque string and never depend on
	// its shape.
	EmailID       string    `json:"email_id"`
	OrgID         int64     `json:"org_id"`
	FetchedAt     time.Time `json:"fetched_at,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
	TraceID       string    `json:"trace_id,omitempty"`
	SpanID        string    `json:"span_id,omitempty"`
	SchemaVersion int       `json:"schema_version"`
}

// NewMeta returns a MessageMeta with Timestamp = now and SchemaVersion set.
// TraceID/SpanID are filled in by the producer wrapper from the active span.
func NewMeta(emailID string, orgID int64) MessageMeta {
	return MessageMeta{
		EmailID:       emailID,
		OrgID:         orgID,
		Timestamp:     time.Now().UTC(),
		SchemaVersion: SchemaVersion,
	}
}

// NewMetaWithFetched returns a MessageMeta with FetchedAt populated (emails
// table partition key). Use on analysis.plans and scores.* producers.
func NewMetaWithFetched(emailID string, orgID int64, fetchedAt time.Time) MessageMeta {
	m := NewMeta(emailID, orgID)
	m.FetchedAt = fetchedAt.UTC()
	return m
}
