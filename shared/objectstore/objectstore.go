// Package objectstore provides an S3/MinIO-compatible object-storage client
// for storing binary blobs (e.g. svc-02 attachment binaries that back
// attachment_library.storage_uri).
//
// The package exposes a small Store interface plus a MinIO/S3 implementation.
// Configuration is supplied via the local Config struct (or constructor
// params) so the package stays decoupled from shared/config; service-side
// wiring to shared/config happens at the call site.
package objectstore

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrNotFound is returned by Get/Stat when the requested object does not exist.
var ErrNotFound = errors.New("objectstore: object not found")

// ObjectInfo describes a stored object.
type ObjectInfo struct {
	Key          string
	Size         int64
	ContentType  string
	ETag         string
	LastModified time.Time
}

// PutOptions are optional parameters for a Put.
//
// Size may be -1 when unknown; implementations stream in that case.
type PutOptions struct {
	ContentType string
	Size        int64
}

// Store is the minimal object-storage contract the platform depends on.
//
// Implementations must be safe for concurrent use by multiple goroutines.
type Store interface {
	// Put writes the contents of r to key, returning info about the stored
	// object. When opts.Size is < 0 the size is unknown and the body is
	// streamed.
	Put(ctx context.Context, key string, r io.Reader, opts PutOptions) (ObjectInfo, error)

	// Get returns a reader for the object at key. The caller must close the
	// returned ReadCloser. It returns ErrNotFound if the object is absent.
	Get(ctx context.Context, key string) (io.ReadCloser, ObjectInfo, error)

	// Stat returns metadata for the object at key without fetching its body.
	// It returns ErrNotFound if the object is absent.
	Stat(ctx context.Context, key string) (ObjectInfo, error)

	// Exists reports whether an object exists at key.
	Exists(ctx context.Context, key string) (bool, error)

	// PresignGet returns a time-limited, pre-signed URL that grants read
	// access to key without credentials (e.g. a dashboard download link).
	PresignGet(ctx context.Context, key string, expiry time.Duration) (string, error)

	// Bucket returns the bucket this store writes to.
	Bucket() string
}
