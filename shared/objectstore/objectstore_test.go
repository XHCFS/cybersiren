package objectstore

import (
	"context"
	"errors"
	"testing"
)

func TestAttachmentKeyAndURI(t *testing.T) {
	t.Parallel()
	if got := AttachmentKey("  ABC123  "); got != "attachments/abc123" {
		t.Errorf("AttachmentKey = %q, want attachments/abc123", got)
	}
	if got := URI("attachments", "attachments/abc123"); got != "s3://attachments/attachments/abc123" {
		t.Errorf("URI = %q", got)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	t.Parallel()
	if _, err := New(context.Background(), Config{Bucket: "b"}); err == nil {
		t.Error("missing endpoint should error")
	}
	if _, err := New(context.Background(), Config{Endpoint: "minio:9000"}); err == nil {
		t.Error("missing bucket should error")
	}
}

// fakeStore shows the Store interface is fakeable by callers' tests.
type fakeStore struct{ objects map[string][]byte }

func (f *fakeStore) Put(_ context.Context, key string, data []byte, _ string) (string, error) {
	f.objects[key] = data
	return URI("test", key), nil
}
func (f *fakeStore) Get(_ context.Context, key string) ([]byte, error) {
	d, ok := f.objects[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return d, nil
}

func TestStoreInterfaceRoundTrip(t *testing.T) {
	t.Parallel()
	var s Store = &fakeStore{objects: map[string][]byte{}}
	key := AttachmentKey("deadbeef")
	uri, err := s.Put(context.Background(), key, []byte("payload"), "application/octet-stream")
	if err != nil || uri != "s3://test/attachments/deadbeef" {
		t.Fatalf("Put = %q, %v", uri, err)
	}
	got, err := s.Get(context.Background(), key)
	if err != nil || string(got) != "payload" {
		t.Fatalf("Get = %q, %v", got, err)
	}
}
