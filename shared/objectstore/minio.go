package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/rs/zerolog"
)

// Config holds the connection parameters for the MinIO/S3 store.
//
// Field names mirror the CYBERSIREN_STORAGE__* convention used elsewhere so a
// service can map its shared/config values straight onto this struct:
//
//	Endpoint  -> CYBERSIREN_STORAGE__ENDPOINT  (host:port, no scheme; blank = AWS S3)
//	Bucket    -> CYBERSIREN_STORAGE__BUCKET
//	Region    -> CYBERSIREN_STORAGE__REGION
//	AccessKey -> CYBERSIREN_STORAGE__ACCESS_KEY
//	SecretKey -> CYBERSIREN_STORAGE__SECRET_KEY
//	UseSSL    -> CYBERSIREN_STORAGE__USE_SSL
type Config struct {
	// Endpoint is the host:port of the S3/MinIO server with no scheme
	// (e.g. "minio:9000"). Leave blank to target AWS S3 ("s3.amazonaws.com").
	Endpoint string
	// Bucket is the target bucket. Required.
	Bucket string
	// Region is the bucket region. Defaults to "us-east-1" when empty.
	Region string
	// AccessKey / SecretKey are the static credentials. Required.
	AccessKey string
	SecretKey string
	// UseSSL toggles TLS for the connection.
	UseSSL bool
	// CreateBucket, when true, creates the bucket on New if it is absent.
	// Handy for local/dev so callers do not have to pre-provision it; the
	// compose bucket-bootstrap covers the same ground for the up-infra stack.
	CreateBucket bool
}

const defaultRegion = "us-east-1"

// minioStore is the MinIO/S3 implementation of Store.
type minioStore struct {
	client *minio.Client
	bucket string
}

// compile-time assertion that minioStore satisfies Store.
var _ Store = (*minioStore)(nil)

// New constructs a Store backed by MinIO/S3 using cfg. It verifies
// connectivity by checking the target bucket exists (and optionally creating
// it when cfg.CreateBucket is set).
func New(ctx context.Context, cfg Config, log zerolog.Logger) (Store, error) {
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		endpoint = "s3.amazonaws.com"
	}
	// minio-go expects a bare host:port; strip an accidental scheme.
	endpoint = strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")

	bucket := strings.TrimSpace(cfg.Bucket)
	if bucket == "" {
		return nil, errors.New("objectstore: bucket is required")
	}
	if strings.TrimSpace(cfg.AccessKey) == "" || strings.TrimSpace(cfg.SecretKey) == "" {
		return nil, errors.New("objectstore: access key and secret key are required")
	}

	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		region = defaultRegion
	}

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: region,
	})
	if err != nil {
		return nil, fmt.Errorf("objectstore: create minio client: %w", err)
	}

	exists, err := client.BucketExists(ctx, bucket)
	if err != nil {
		return nil, fmt.Errorf("objectstore: check bucket %q: %w", bucket, err)
	}
	if !exists {
		if !cfg.CreateBucket {
			return nil, fmt.Errorf("objectstore: bucket %q does not exist", bucket)
		}
		if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: region}); err != nil {
			// Tolerate a race where another process created it first.
			if ok, existsErr := client.BucketExists(ctx, bucket); existsErr != nil || !ok {
				return nil, fmt.Errorf("objectstore: create bucket %q: %w", bucket, err)
			}
		}
		log.Info().Str("bucket", bucket).Msg("objectstore: created bucket")
	}

	log.Info().
		Str("endpoint", endpoint).
		Str("bucket", bucket).
		Bool("ssl", cfg.UseSSL).
		Msg("objectstore: connected")

	return &minioStore{client: client, bucket: bucket}, nil
}

// NewWithClient wraps an already-constructed *minio.Client. Primarily useful
// for tests that point at a stub server.
func NewWithClient(client *minio.Client, bucket string) Store {
	return &minioStore{client: client, bucket: bucket}
}

func (s *minioStore) Bucket() string { return s.bucket }

func (s *minioStore) Put(ctx context.Context, key string, r io.Reader, opts PutOptions) (ObjectInfo, error) {
	size := opts.Size
	if size == 0 {
		// 0 is ambiguous between "empty" and "unset"; treat unset as stream.
		size = -1
	}
	info, err := s.client.PutObject(ctx, s.bucket, key, r, size, minio.PutObjectOptions{
		ContentType: opts.ContentType,
	})
	if err != nil {
		return ObjectInfo{}, fmt.Errorf("objectstore: put %q: %w", key, err)
	}
	return ObjectInfo{
		Key:         key,
		Size:        info.Size,
		ContentType: opts.ContentType,
		ETag:        info.ETag,
	}, nil
}

func (s *minioStore) Get(ctx context.Context, key string) (io.ReadCloser, ObjectInfo, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, ObjectInfo{}, fmt.Errorf("objectstore: get %q: %w", key, err)
	}
	// GetObject is lazy; Stat forces the request and surfaces a missing object.
	stat, err := obj.Stat()
	if err != nil {
		_ = obj.Close()
		if isNotFound(err) {
			return nil, ObjectInfo{}, fmt.Errorf("objectstore: get %q: %w", key, ErrNotFound)
		}
		return nil, ObjectInfo{}, fmt.Errorf("objectstore: get %q: %w", key, err)
	}
	return obj, objectInfoFromStat(key, stat), nil
}

func (s *minioStore) Stat(ctx context.Context, key string) (ObjectInfo, error) {
	stat, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		if isNotFound(err) {
			return ObjectInfo{}, fmt.Errorf("objectstore: stat %q: %w", key, ErrNotFound)
		}
		return ObjectInfo{}, fmt.Errorf("objectstore: stat %q: %w", key, err)
	}
	return objectInfoFromStat(key, stat), nil
}

func (s *minioStore) Exists(ctx context.Context, key string) (bool, error) {
	_, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("objectstore: exists %q: %w", key, err)
	}
	return true, nil
}

func (s *minioStore) PresignGet(ctx context.Context, key string, expiry time.Duration) (string, error) {
	u, err := s.client.PresignedGetObject(ctx, s.bucket, key, expiry, url.Values{})
	if err != nil {
		return "", fmt.Errorf("objectstore: presign get %q: %w", key, err)
	}
	return u.String(), nil
}

func objectInfoFromStat(key string, stat minio.ObjectInfo) ObjectInfo {
	return ObjectInfo{
		Key:          key,
		Size:         stat.Size,
		ContentType:  stat.ContentType,
		ETag:         stat.ETag,
		LastModified: stat.LastModified,
	}
}

// isNotFound reports whether err corresponds to a missing object/bucket.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	resp := minio.ToErrorResponse(err)
	switch resp.Code {
	case "NoSuchKey", "NoSuchBucket", "NotFound":
		return true
	}
	return resp.StatusCode == http.StatusNotFound
}
