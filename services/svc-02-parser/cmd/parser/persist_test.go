package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-02-parser/internal/email"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	"github.com/saif/cybersiren/shared/objectstore"
	"github.com/saif/cybersiren/shared/svckit"
)

// A non-RFC822 body that email.Parse cannot handle must NOT be dropped: the
// degraded fallback still extracts the embedded phish URL and reports HasBody()
// so the malformed message reaches a verdict instead of vanishing (Fix #2).
func TestDegradedParseExtractsURL(t *testing.T) {
	t.Parallel()
	raw := []byte("this is not a valid \x00\x01 rfc822 message but visit http://evil.test/x now")

	parsed := degradedParse(raw)

	if !parsed.HasBody() {
		t.Fatalf("degraded parse HasBody() = false, want true (body=%q)", parsed.BodyPlain)
	}
	var found bool
	for _, u := range parsed.URLs {
		if u.URL == "http://evil.test/x" {
			found = true
		}
	}
	if !found {
		t.Fatalf("degraded parse did not extract the phish URL: %+v", parsed.URLs)
	}
	if len(parsed.Attachments) != 0 || len(parsed.Recipients) != 0 {
		t.Fatalf("degraded parse must carry no attachments/recipients: %+v / %+v", parsed.Attachments, parsed.Recipients)
	}
}

// An HTML-looking malformed body is stripped to text by the degraded path, and
// the URL inside the markup is still recovered.
func TestDegradedParseStripsHTML(t *testing.T) {
	t.Parallel()
	raw := []byte(`<div>Click <a href="http://evil.test/x">here</a></div> not-a-real-email`)

	parsed := degradedParse(raw)

	if strings.Contains(parsed.BodyPlain, "<a ") || strings.Contains(parsed.BodyPlain, "<div") {
		t.Fatalf("degraded HTML body not stripped: %q", parsed.BodyPlain)
	}
	if !parsed.HasBody() {
		t.Fatal("degraded HTML parse HasBody() = false, want true")
	}
	var found bool
	for _, u := range parsed.URLs {
		if u.URL == "http://evil.test/x" {
			found = true
		}
	}
	if !found {
		t.Fatalf("degraded HTML parse did not extract the href URL: %+v", parsed.URLs)
	}
}

// failingStore is an objectstore.Store whose Put always fails, used to prove the
// upload-failure-retry path (Fix #3).
type failingStore struct{}

func (failingStore) Put(context.Context, string, io.Reader, objectstore.PutOptions) (objectstore.ObjectInfo, error) {
	return objectstore.ObjectInfo{}, errors.New("simulated storage outage")
}

func (failingStore) Get(context.Context, string) (io.ReadCloser, objectstore.ObjectInfo, error) {
	return nil, objectstore.ObjectInfo{}, errors.New("not implemented")
}

func (failingStore) Stat(context.Context, string) (objectstore.ObjectInfo, error) {
	return objectstore.ObjectInfo{}, errors.New("not implemented")
}

func (failingStore) Exists(context.Context, string) (bool, error) {
	return false, errors.New("not implemented")
}

func (failingStore) PresignGet(context.Context, string, time.Duration) (string, error) {
	return "", errors.New("not implemented")
}

func (failingStore) Bucket() string { return "test-bucket" }

func nopDeps() svckit.Deps {
	return svckit.Deps{Log: zerolog.Nop()}
}

// When the store is configured and Put fails, uploadAttachments must SURFACE the
// error (not swallow it) so handle() returns and Kafka redelivers — the binary
// must be retained, never persisted blob-less (Fix #3, G6).
func TestUploadAttachmentsSurfacesPutFailure(t *testing.T) {
	t.Parallel()
	app := &parserApp{store: failingStore{}}
	atts := []email.Attachment{{SHA256: "abc", Data: []byte("payload"), SizeBytes: 7}}

	uris, err := app.uploadAttachments(context.Background(), nopDeps(), atts)
	if err == nil {
		t.Fatal("uploadAttachments returned nil error on a configured-store Put failure")
	}
	if uris != nil {
		t.Fatalf("uploadAttachments returned URIs %v on failure, want nil", uris)
	}
}

// With no store configured (Batch-7 env gap) uploadAttachments proceeds: empty
// URIs and a nil error, so persistence still happens without storage_uri.
func TestUploadAttachmentsNoStoreProceeds(t *testing.T) {
	t.Parallel()
	app := &parserApp{} // store == nil
	atts := []email.Attachment{{SHA256: "abc", Data: []byte("payload"), SizeBytes: 7}}

	uris, err := app.uploadAttachments(context.Background(), nopDeps(), atts)
	if err != nil {
		t.Fatalf("uploadAttachments with no store returned error: %v", err)
	}
	if len(uris) != 1 || uris[0] != "" {
		t.Fatalf("uploadAttachments with no store = %v, want one empty uri", uris)
	}
}

// analysis.urls must carry the DB-assigned internal_id so svc-03 can look up
// email_urls by the real surrogate key (Fix #5). buildAnalysisURLs is the single
// place that stamps it; assert both the struct field and the wire tag.
func TestBuildAnalysisURLsStampsInternalID(t *testing.T) {
	t.Parallel()

	meta := contracts.NewMetaWithFetched(42, 7, time.Now().UTC())
	parsed := &email.ParsedEmail{
		URLs: []email.ExtractedURL{{URL: "http://evil.test/x", Position: "body", HTMLContext: "plain_text"}},
	}

	got := buildAnalysisURLs(meta, 5005, parsed)
	if got.InternalID != 5005 {
		t.Fatalf("analysis.urls internal_id = %d, want 5005 (the DB surrogate)", got.InternalID)
	}
	if len(got.URLs) != 1 || got.URLs[0].URL != "http://evil.test/x" {
		t.Fatalf("analysis.urls URLs not carried: %+v", got.URLs)
	}

	payload, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal analysis.urls: %v", err)
	}
	if !strings.Contains(string(payload), `"internal_id":5005`) {
		t.Fatalf("analysis.urls wire payload missing internal_id: %s", payload)
	}

	// And when internal_id is zero (svc-02 has not assigned one), the omitempty
	// tag drops it so the wire stays clean for the un-persisted case.
	zero := buildAnalysisURLs(meta, 0, parsed)
	zp, err := json.Marshal(zero)
	if err != nil {
		t.Fatalf("marshal zero analysis.urls: %v", err)
	}
	if strings.Contains(string(zp), "internal_id") {
		t.Fatalf("analysis.urls with zero internal_id must omit the field: %s", zp)
	}
}
