package objectstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// --- New() input validation (no network) -----------------------------------

func TestNew_Validation(t *testing.T) {
	log := zerolog.Nop()
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "missing bucket",
			cfg:  Config{AccessKey: "a", SecretKey: "s"},
			want: "bucket is required",
		},
		{
			name: "missing access key",
			cfg:  Config{Bucket: "b", SecretKey: "s"},
			want: "access key and secret key are required",
		},
		{
			name: "missing secret key",
			cfg:  Config{Bucket: "b", AccessKey: "a"},
			want: "access key and secret key are required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(context.Background(), tc.cfg, log)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

// --- Interface behaviour against an in-memory S3 stub -----------------------

// stubS3 implements just enough of the S3 HTTP API for minio-go's
// PutObject/StatObject/GetObject/PresignedGetObject to work end-to-end.
type stubS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	parts   map[string][]byte
}

func newStubS3() *stubS3 {
	return &stubS3{objects: map[string][]byte{}, parts: map[string][]byte{}}
}

// readBody reads the request body, decoding the AWS v4 streaming chunked
// payload framing (STREAMING-AWS4-HMAC-SHA256-PAYLOAD) that minio-go uses for
// non-TLS, seekable single-part puts.
func (s *stubS3) readBody(r *http.Request) []byte {
	raw, _ := io.ReadAll(r.Body)
	if !strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
		return raw
	}
	return decodeAWSChunked(raw)
}

// decodeAWSChunked parses the chunk framing:
//
//	<hex-size>;chunk-signature=<sig>\r\n<data>\r\n  ... terminated by a 0-size chunk.
func decodeAWSChunked(raw []byte) []byte {
	var out []byte
	for len(raw) > 0 {
		nl := bytes.Index(raw, []byte("\r\n"))
		if nl < 0 {
			break
		}
		header := raw[:nl]
		if semi := bytes.IndexByte(header, ';'); semi >= 0 {
			header = header[:semi]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(string(header)), 16, 64)
		if err != nil || size == 0 {
			break
		}
		dataStart := nl + 2
		if int64(len(raw)) < int64(dataStart)+size {
			break
		}
		out = append(out, raw[dataStart:int64(dataStart)+size]...)
		raw = raw[int64(dataStart)+size+2:] // skip trailing \r\n
	}
	return out
}

func (s *stubS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Path-style addressing: /<bucket>/<key...>
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if len(parts) < 2 || parts[1] == "" {
		// Bucket-level op (e.g. BucketExists HEAD). Always "exists".
		w.WriteHeader(http.StatusOK)
		return
	}
	key := parts[1]
	q := r.URL.Query()

	s.mu.Lock()
	defer s.mu.Unlock()

	// --- Multipart upload flow (used for unknown-size streaming puts) ------
	if r.Method == http.MethodPost && q.Has("uploads") {
		// Initiate multipart upload.
		s.parts[key] = nil
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult><Bucket>b</Bucket><Key>`+key+`</Key><UploadId>stub-upload</UploadId></InitiateMultipartUploadResult>`)
		return
	}
	if r.Method == http.MethodPut && q.Has("partNumber") {
		// Upload a single part.
		body := s.readBody(r)
		s.parts[key] = append(s.parts[key], body...)
		w.Header().Set("ETag", `"stub-part-etag"`)
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method == http.MethodPost && q.Has("uploadId") {
		// Complete multipart upload.
		s.objects[key] = s.parts[key]
		delete(s.parts, key)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult><Bucket>b</Bucket><Key>`+key+`</Key><ETag>"stub-etag"</ETag></CompleteMultipartUploadResult>`)
		return
	}

	switch r.Method {
	case http.MethodPut:
		s.objects[key] = s.readBody(r)
		w.Header().Set("ETag", `"stub-etag"`)
		w.WriteHeader(http.StatusOK)
	case http.MethodHead:
		data, ok := s.objects[key]
		if !ok {
			writeNotFound(w)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Header().Set("ETag", `"stub-etag"`)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		data, ok := s.objects[key]
		if !ok {
			writeNotFound(w)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Header().Set("ETag", `"stub-etag"`)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func writeNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`)
}

func newStubStore(t *testing.T) (Store, *stubS3) {
	t.Helper()
	stub := newStubS3()
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	client, err := minio.New(u.Host, &minio.Options{
		Creds:  credentials.NewStaticV4("test", "testsecret", ""),
		Secure: false,
		Region: defaultRegion,
	})
	require.NoError(t, err)

	return NewWithClient(client, "test-bucket"), stub
}

func TestStore_PutGetStatExists(t *testing.T) {
	store, _ := newStubStore(t)
	ctx := context.Background()

	require.Equal(t, "test-bucket", store.Bucket())

	payload := []byte("attachment-bytes")
	info, err := store.Put(ctx, "att/abc.bin", bytes.NewReader(payload), PutOptions{
		ContentType: "application/octet-stream",
		Size:        int64(len(payload)),
	})
	require.NoError(t, err)
	require.Equal(t, "att/abc.bin", info.Key)

	exists, err := store.Exists(ctx, "att/abc.bin")
	require.NoError(t, err)
	require.True(t, exists)

	stat, err := store.Stat(ctx, "att/abc.bin")
	require.NoError(t, err)
	require.Equal(t, int64(len(payload)), stat.Size)

	rc, _, err := store.Get(ctx, "att/abc.bin")
	require.NoError(t, err)
	defer rc.Close()
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

func TestStore_MissingObject(t *testing.T) {
	store, _ := newStubStore(t)
	ctx := context.Background()

	exists, err := store.Exists(ctx, "nope")
	require.NoError(t, err)
	require.False(t, exists)

	_, err = store.Stat(ctx, "nope")
	require.ErrorIs(t, err, ErrNotFound)

	_, _, err = store.Get(ctx, "nope")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestStore_PresignGet(t *testing.T) {
	store, _ := newStubStore(t)

	signed, err := store.PresignGet(context.Background(), "att/abc.bin", 5*time.Minute)
	require.NoError(t, err)
	require.Contains(t, signed, "test-bucket/att/abc.bin")
	require.Contains(t, signed, "X-Amz-Signature")
}

func TestStore_PutStreamUnknownSize(t *testing.T) {
	store, _ := newStubStore(t)
	ctx := context.Background()

	payload := strings.Repeat("x", 1024)
	_, err := store.Put(ctx, "stream.bin", strings.NewReader(payload), PutOptions{Size: -1})
	require.NoError(t, err)

	rc, _, err := store.Get(ctx, "stream.bin")
	require.NoError(t, err)
	defer rc.Close()
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.Equal(t, payload, string(got))
}

func TestIsNotFound(t *testing.T) {
	require.False(t, isNotFound(nil))
	require.False(t, isNotFound(errors.New("some other error")))
}
