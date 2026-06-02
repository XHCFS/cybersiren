// Package objectstore is a thin S3/MinIO helper for attachment binaries. SVC-02
// uploads decoded attachments to s3://{bucket}/attachments/{sha256} and records
// the returned URI in attachment_library.storage_uri; SVC-05 and the dashboard
// can fetch them back. Keeping this behind a small Store interface lets callers
// fake it in tests and lets us swap backends without touching call sites.
package objectstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// attachmentPrefix is the key prefix for attachment binaries within the bucket.
const attachmentPrefix = "attachments/"

// Store is the object-storage surface the services depend on.
type Store interface {
	Put(ctx context.Context, key string, data []byte, contentType string) (uri string, err error)
	Get(ctx context.Context, key string) ([]byte, error)
}

// Config configures a MinIO/S3 store. It is self-contained so callers can build
// it from env/config without this package importing shared/config.
type Config struct {
	Endpoint  string // host:port, e.g. "minio:9000"
	AccessKey string
	SecretKey string
	Bucket    string
	UseSSL    bool
}

// MinIOStore is a Store backed by a MinIO/S3 endpoint.
type MinIOStore struct {
	client *minio.Client
	bucket string
}

// New connects to the endpoint and ensures the bucket exists.
func New(ctx context.Context, cfg Config) (*MinIOStore, error) {
	if cfg.Endpoint == "" || cfg.Bucket == "" {
		return nil, errors.New("objectstore: endpoint and bucket are required")
	}
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("objectstore: connect: %w", err)
	}
	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("objectstore: bucket check: %w", err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{}); err != nil {
			return nil, fmt.Errorf("objectstore: create bucket %q: %w", cfg.Bucket, err)
		}
	}
	return &MinIOStore{client: client, bucket: cfg.Bucket}, nil
}

// Put stores data under key and returns its s3:// URI. It is idempotent — the
// same key overwrites with identical content.
func (s *MinIOStore) Put(ctx context.Context, key string, data []byte, contentType string) (string, error) {
	_, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return "", fmt.Errorf("objectstore: put %q: %w", key, err)
	}
	return URI(s.bucket, key), nil
}

// Get retrieves the object stored under key.
func (s *MinIOStore) Get(ctx context.Context, key string) ([]byte, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("objectstore: get %q: %w", key, err)
	}
	defer func() { _ = obj.Close() }()
	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, fmt.Errorf("objectstore: read %q: %w", key, err)
	}
	return data, nil
}

// AttachmentKey returns the object key for an attachment by its sha256.
func AttachmentKey(sha256 string) string {
	return attachmentPrefix + strings.ToLower(strings.TrimSpace(sha256))
}

// URI formats the canonical s3:// URI for a bucket/key pair.
func URI(bucket, key string) string {
	return "s3://" + bucket + "/" + key
}
