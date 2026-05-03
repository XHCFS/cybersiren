package aggregator

import (
	"context"
	"errors"
	"fmt"

	valkeygo "github.com/valkey-io/valkey-go"
)

// StateStore captures the small slice of Valkey behaviour the aggregator
// needs. The production implementation is a thin wrapper over valkey-go
// (NewValkeyStore); tests use an in-memory fake (newFakeStore).
//
// Methods MUST be safe for concurrent use; the production wrapper is
// because valkey-go is, and the in-memory fake serialises with a mutex.
type StateStore interface {
	// HSetIfAbsent sets field=value only if the field does not already
	// exist (HSETNX). Returns true when the field was created.
	HSetIfAbsent(ctx context.Context, key, field, value string) (bool, error)
	// HSet writes one or more field/value pairs (HSET).
	HSet(ctx context.Context, key string, pairs ...string) error
	// HGet returns the field value or "" + ok=false on miss.
	HGet(ctx context.Context, key, field string) (value string, ok bool, err error)
	// HDel removes one or more fields.
	HDel(ctx context.Context, key string, fields ...string) error
	// HGetAll returns the full hash, never nil (empty map on miss).
	HGetAll(ctx context.Context, key string) (map[string]string, error)
	// Expire sets a TTL on the key in seconds.
	Expire(ctx context.Context, key string, seconds int) error
	// Del unconditionally removes the key.
	Del(ctx context.Context, key string) error
	// Scan walks keys matching pattern using Redis SCAN. fn is called
	// once per page; return false to stop iteration. The cursor / page
	// size are managed internally.
	Scan(ctx context.Context, pattern string, fn func(keys []string) bool) error
}

// ValkeyStore is the production StateStore backed by valkey-go.
type ValkeyStore struct {
	client valkeygo.Client
}

// NewValkeyStore wraps an existing valkey-go client.
func NewValkeyStore(client valkeygo.Client) *ValkeyStore {
	return &ValkeyStore{client: client}
}

func (s *ValkeyStore) HSetIfAbsent(ctx context.Context, key, field, value string) (bool, error) {
	cmd := s.client.B().Hsetnx().Key(key).Field(field).Value(value).Build()
	n, err := s.client.Do(ctx, cmd).AsInt64()
	if err != nil {
		return false, fmt.Errorf("hsetnx %s.%s: %w", key, field, err)
	}
	return n == 1, nil
}

func (s *ValkeyStore) HSet(ctx context.Context, key string, pairs ...string) error {
	if len(pairs) == 0 || len(pairs)%2 != 0 {
		return errors.New("HSet: pairs must be non-empty and even-length")
	}
	// Build dynamically — valkey-go's HSET FieldValue chain expects each
	// field/value via FieldValue(field, value).
	c := s.client.B().Hset().Key(key).FieldValue()
	for i := 0; i < len(pairs); i += 2 {
		c = c.FieldValue(pairs[i], pairs[i+1])
	}
	if err := s.client.Do(ctx, c.Build()).Error(); err != nil {
		return fmt.Errorf("hset %s: %w", key, err)
	}
	return nil
}

func (s *ValkeyStore) HGet(ctx context.Context, key, field string) (string, bool, error) {
	cmd := s.client.B().Hget().Key(key).Field(field).Build()
	v, err := s.client.Do(ctx, cmd).ToString()
	if err != nil {
		if valkeygo.IsValkeyNil(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("hget %s.%s: %w", key, field, err)
	}
	return v, true, nil
}

func (s *ValkeyStore) HDel(ctx context.Context, key string, fields ...string) error {
	if len(fields) == 0 {
		return nil
	}
	cmd := s.client.B().Hdel().Key(key).Field(fields...).Build()
	if err := s.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("hdel %s: %w", key, err)
	}
	return nil
}

func (s *ValkeyStore) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	m, err := s.client.Do(ctx, s.client.B().Hgetall().Key(key).Build()).AsStrMap()
	if err != nil {
		return nil, fmt.Errorf("hgetall %s: %w", key, err)
	}
	return m, nil
}

func (s *ValkeyStore) Expire(ctx context.Context, key string, seconds int) error {
	if err := s.client.Do(ctx, s.client.B().Expire().Key(key).Seconds(int64(seconds)).Build()).Error(); err != nil {
		return fmt.Errorf("expire %s: %w", key, err)
	}
	return nil
}

func (s *ValkeyStore) Del(ctx context.Context, key string) error {
	if err := s.client.Do(ctx, s.client.B().Del().Key(key).Build()).Error(); err != nil {
		return fmt.Errorf("del %s: %w", key, err)
	}
	return nil
}

// Scan walks keys matching pattern using SCAN with COUNT 200. The callback
// is invoked once per page; returning false stops iteration. Errors from
// SCAN are returned to the caller; the caller is expected to log and retry
// at the next sweep tick.
func (s *ValkeyStore) Scan(ctx context.Context, pattern string, fn func(keys []string) bool) error {
	var cursor uint64
	for {
		entry, err := s.client.Do(ctx,
			s.client.B().Scan().Cursor(cursor).Match(pattern).Count(200).Build(),
		).AsScanEntry()
		if err != nil {
			return fmt.Errorf("scan %q: %w", pattern, err)
		}
		if len(entry.Elements) > 0 {
			if !fn(entry.Elements) {
				return nil
			}
		}
		cursor = entry.Cursor
		if cursor == 0 {
			return nil
		}
	}
}
