package ingest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/source"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// ---- fakes -----------------------------------------------------------------

type fakeDedup struct {
	fresh bool
	err   error
	calls int
}

func (f *fakeDedup) Claim(_ context.Context, _ int64, _ string) (bool, error) {
	f.calls++
	return f.fresh, f.err
}

type fakeQuota struct {
	allow bool
	err   error
}

func (f *fakeQuota) Allow(_ context.Context, _ int64, _ *int32) (bool, error) {
	return f.allow, f.err
}

type fakeOrgs struct {
	limit *int32
	err   error
}

func (f *fakeOrgs) MonthlyLimit(_ context.Context, _ int64) (*int32, error) {
	return f.limit, f.err
}

type fakePublisher struct {
	key   []byte
	value []byte
	err   error
	calls int
}

func (f *fakePublisher) Publish(_ context.Context, key, value []byte, _ int) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	f.key = key
	f.value = value
	return nil
}

func newCore(d Deduper, q QuotaLimiter, o OrgReader, p Publisher) *Core {
	return NewCore(Config{Dedup: d, Quota: q, Orgs: o, Producer: p, Log: zerolog.Nop()})
}

func sampleReq() source.IngestRequest {
	return source.IngestRequest{
		Raw:           []byte("From: a@b.test\r\nMessage-Id: <m1@b.test>\r\n\r\nhi"),
		MessageID:     "m1@b.test",
		SourceAdapter: "api",
	}
}

// ---- tests -----------------------------------------------------------------

func TestIngest_Accepted_PublishesUUIDv7KeyedRaw(t *testing.T) {
	pub := &fakePublisher{}
	core := newCore(&fakeDedup{fresh: true}, &fakeQuota{allow: true}, &fakeOrgs{}, pub)

	out, err := core.Ingest(context.Background(), 7, 99, sampleReq())
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if out.Status != source.StatusAccepted {
		t.Fatalf("status = %v, want accepted", out.Status)
	}
	if out.EmailID == "" {
		t.Fatal("accepted ingest must assign an email_id")
	}
	// The Kafka partition key is the UUIDv7 email_id verbatim.
	if string(pub.key) != out.EmailID {
		t.Errorf("partition key = %q, want email_id %q", pub.key, out.EmailID)
	}

	var raw contracts.EmailsRaw
	if err := json.Unmarshal(pub.value, &raw); err != nil {
		t.Fatalf("decode emails.raw: %v", err)
	}
	if raw.Meta.EmailID != out.EmailID {
		t.Errorf("meta.email_id = %q, want %q", raw.Meta.EmailID, out.EmailID)
	}
	if raw.Meta.OrgID != 7 {
		t.Errorf("org_id = %d, want 7 (from the key, not the body)", raw.Meta.OrgID)
	}
	if raw.APIKeyID != 99 {
		t.Errorf("api_key_id = %d, want 99", raw.APIKeyID)
	}
	if raw.SourceAdapter != "api" {
		t.Errorf("source_adapter = %q, want api", raw.SourceAdapter)
	}
	// raw_rfc822 carries the base64 of the original bytes.
	wantB64 := base64.StdEncoding.EncodeToString(sampleReq().Raw)
	if raw.RawMessageB64 != wantB64 {
		t.Errorf("raw_rfc822 mismatch")
	}
}

func TestIngest_Duplicate_DoesNotPublish(t *testing.T) {
	pub := &fakePublisher{}
	core := newCore(&fakeDedup{fresh: false}, &fakeQuota{allow: true}, &fakeOrgs{}, pub)

	out, err := core.Ingest(context.Background(), 7, 1, sampleReq())
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if out.Status != source.StatusDuplicate {
		t.Fatalf("status = %v, want duplicate", out.Status)
	}
	if pub.calls != 0 {
		t.Errorf("a duplicate must NOT republish, got %d publishes", pub.calls)
	}
}

func TestIngest_OverQuota_429AndNoPublish(t *testing.T) {
	pub := &fakePublisher{}
	dd := &fakeDedup{fresh: true}
	core := newCore(dd, &fakeQuota{allow: false}, &fakeOrgs{}, pub)

	out, err := core.Ingest(context.Background(), 7, 1, sampleReq())
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if out.Status != source.StatusQuotaExceeded {
		t.Fatalf("status = %v, want quota_exceeded", out.Status)
	}
	if pub.calls != 0 {
		t.Errorf("over-quota must not publish, got %d", pub.calls)
	}
	if dd.calls != 0 {
		t.Errorf("quota is checked before dedup; dedup must not run, got %d calls", dd.calls)
	}
}

func TestIngest_OrgFromKeyNotBody(t *testing.T) {
	// There is no body org_id to spoof — Ingest takes orgID as a parameter that
	// the caller binds from the authenticated key. Passing org 0 is rejected.
	core := newCore(&fakeDedup{fresh: true}, &fakeQuota{allow: true}, &fakeOrgs{}, &fakePublisher{})
	if _, err := core.Ingest(context.Background(), 0, 1, sampleReq()); err == nil {
		t.Fatal("expected error when orgID is not bound from a key")
	}
}

func TestIngest_PublishFailure_Errors(t *testing.T) {
	pub := &fakePublisher{err: errors.New("broker down")}
	core := newCore(&fakeDedup{fresh: true}, &fakeQuota{allow: true}, &fakeOrgs{}, pub)
	if _, err := core.Ingest(context.Background(), 7, 1, sampleReq()); err == nil {
		t.Fatal("expected a publish failure to surface as an error")
	}
}

func TestIngest_EmptyRaw_Errors(t *testing.T) {
	core := newCore(&fakeDedup{fresh: true}, &fakeQuota{allow: true}, &fakeOrgs{}, &fakePublisher{})
	req := sampleReq()
	req.Raw = nil
	if _, err := core.Ingest(context.Background(), 7, 1, req); err == nil {
		t.Fatal("expected an empty raw message to error")
	}
}
