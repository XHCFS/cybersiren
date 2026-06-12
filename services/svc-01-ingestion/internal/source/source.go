// Package source defines the EmailSource abstraction: the small interface every
// svc-01 ingestion adapter implements, plus the named-adapter registry the
// service wires in svckit OnReady. Modelled on svc-09's notifier.Channel +
// BuildChannels pattern (one small interface, a name-keyed map).
//
// Adapter scope (D2 / G2): API-upload + Gmail ONLY. IMAP and Outlook are
// deferred (P2) and MUST NOT be built here.
package source

import "context"

// IngestRequest is the normalised email an adapter hands to the ingestion core.
// An adapter's only job is to turn its transport-specific input (an HTTP body,
// a Gmail history record) into this shape; the core owns auth/dedup/quota and
// the emails.raw publish.
type IngestRequest struct {
	// Raw is the full RFC-822 message bytes. The core base64-encodes it onto
	// emails.raw (raw_rfc822) and svc-02 is the sole parser.
	Raw []byte
	// MessageID is the RFC 5322 Message-ID with angle brackets stripped, used
	// as the dedup discriminator. Empty when the message carries none (such
	// messages are not deduplicated — see the ingestion core).
	MessageID string
	// SourceAdapter labels the origin on emails.raw ("api" | "gmail").
	SourceAdapter string
}

// EmailSource is one ingestion adapter. Name is its registry key; the transport
// wiring (HTTP routes, a Gmail poller) lives inside the adapter and calls the
// ingestion core it was constructed with. The interface is intentionally tiny —
// adapters differ only in how they receive a message, not in what the core does
// with it. The API-upload adapter additionally exposes a Register(*http.ServeMux)
// method to bind its routes.
type EmailSource interface {
	// Name is the adapter's registry key ("api" | "gmail").
	Name() string
}

// Ingestor is the ingestion core an adapter calls once it has a normalised
// request. It returns the outcome so the adapter can map it onto its transport
// (an HTTP status, a Pub/Sub ack).
type Ingestor interface {
	// Ingest authenticates the org (already resolved by the caller), enforces
	// dedup + quota, and publishes emails.raw. orgID and apiKeyID come from the
	// authenticated key, never from the request body (G10).
	Ingest(ctx context.Context, orgID, apiKeyID int64, req IngestRequest) (Outcome, error)
}

// Outcome is the terminal result of an ingestion attempt.
type Outcome struct {
	// EmailID is the UUIDv7 logical id assigned to a newly accepted email.
	// Empty for a duplicate or quota rejection.
	EmailID string
	// Status is the coarse result the adapter renders onto its transport.
	Status Status
}

// Status enumerates the ingestion outcomes.
type Status int

const (
	// StatusAccepted: the email was new and emails.raw was published.
	StatusAccepted Status = iota
	// StatusDuplicate: a same (org, message_id) email was already seen within
	// the dedup window; nothing was republished.
	StatusDuplicate
	// StatusQuotaExceeded: the org is over its monthly ingestion limit.
	StatusQuotaExceeded
)
