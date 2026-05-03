package aggregator

import (
	"context"
	"strings"
	"sync"
)

// fakeStore is a tiny in-memory implementation of StateStore used in
// tests. It mirrors the bits of Valkey semantics the aggregator relies
// on (HSETNX returning 1 only on first insert, HGETALL returning the
// full hash, SCAN walking by prefix). It is intentionally NOT a generic
// Redis emulator — only the operations we actually call are supported.
type fakeStore struct {
	mu     sync.Mutex
	hashes map[string]map[string]string

	// Optional injected errors so tests can simulate transient failure.
	errOnHSetNX func(key, field string) error
}

func newFakeStore() *fakeStore {
	return &fakeStore{hashes: map[string]map[string]string{}}
}

func (f *fakeStore) HSetIfAbsent(_ context.Context, key, field, value string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errOnHSetNX != nil {
		if err := f.errOnHSetNX(key, field); err != nil {
			return false, err
		}
	}
	h := f.hashes[key]
	if h == nil {
		h = map[string]string{}
		f.hashes[key] = h
	}
	if _, exists := h[field]; exists {
		return false, nil
	}
	h[field] = value
	return true, nil
}

func (f *fakeStore) HSet(_ context.Context, key string, pairs ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := f.hashes[key]
	if h == nil {
		h = map[string]string{}
		f.hashes[key] = h
	}
	for i := 0; i+1 < len(pairs); i += 2 {
		h[pairs[i]] = pairs[i+1]
	}
	return nil
}

func (f *fakeStore) HGet(_ context.Context, key, field string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.hashes[key]
	if !ok {
		return "", false, nil
	}
	v, ok := h[field]
	return v, ok, nil
}

func (f *fakeStore) HDel(_ context.Context, key string, fields ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.hashes[key]
	if !ok {
		return nil
	}
	for _, fld := range fields {
		delete(h, fld)
	}
	return nil
}

func (f *fakeStore) HGetAll(_ context.Context, key string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.hashes[key]
	if !ok {
		return map[string]string{}, nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = v
	}
	return out, nil
}

func (f *fakeStore) Expire(_ context.Context, _ string, _ int) error { return nil }

func (f *fakeStore) Del(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.hashes, key)
	return nil
}

func (f *fakeStore) Scan(_ context.Context, pattern string, fn func(keys []string) bool) error {
	f.mu.Lock()
	prefix := strings.TrimSuffix(pattern, "*")
	keys := make([]string, 0, len(f.hashes))
	for k := range f.hashes {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	f.mu.Unlock()

	if len(keys) == 0 {
		return nil
	}
	fn(keys)
	return nil
}

// recorderPublisher captures every Publish call for assertions.
type recorderPublisher struct {
	mu       sync.Mutex
	messages [][]byte
	keys     [][]byte
	failNext int // when > 0, decrement and return errFakePublish
	errPub   error
}

type fakeError struct{ msg string }

func (e *fakeError) Error() string { return e.msg }

var errFakePublish = &fakeError{msg: "fake publisher: forced failure"}

func (r *recorderPublisher) Publish(_ context.Context, key, value []byte, _ int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failNext > 0 {
		r.failNext--
		if r.errPub == nil {
			return errFakePublish
		}
		return r.errPub
	}
	r.keys = append(r.keys, append([]byte(nil), key...))
	r.messages = append(r.messages, append([]byte(nil), value...))
	return nil
}

func (r *recorderPublisher) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.messages)
}
