package gmail

import (
	"context"
	"errors"
	"fmt"
	"sync"

	valkeygo "github.com/valkey-io/valkey-go"
)

// historyKey is the Valkey key holding the Gmail delta-sync cursor for an org.
func historyKey(orgID int64) string {
	return fmt.Sprintf("gmail:history_id:%d", orgID)
}

// ValkeyHistoryStore persists the Gmail historyId cursor in Valkey so the
// delta-sync watermark survives restarts. The cursor never expires (it is the
// only thing that lets history.list resume without re-walking the whole
// mailbox), so no TTL is set.
type ValkeyHistoryStore struct {
	client valkeygo.Client
}

// NewValkeyHistoryStore builds a ValkeyHistoryStore.
func NewValkeyHistoryStore(client valkeygo.Client) *ValkeyHistoryStore {
	return &ValkeyHistoryStore{client: client}
}

// Get returns the stored cursor, or "" when none is set.
func (s *ValkeyHistoryStore) Get(ctx context.Context, orgID int64) (string, error) {
	v, err := s.client.Do(ctx, s.client.B().Get().Key(historyKey(orgID)).Build()).ToString()
	if err != nil {
		if valkeygo.IsValkeyNil(err) {
			return "", nil
		}
		return "", fmt.Errorf("gmail history get: %w", err)
	}
	return v, nil
}

// Set persists historyID as the new cursor.
func (s *ValkeyHistoryStore) Set(ctx context.Context, orgID int64, historyID string) error {
	if err := s.client.Do(ctx,
		s.client.B().Set().Key(historyKey(orgID)).Value(historyID).Build(),
	).Error(); err != nil {
		return fmt.Errorf("gmail history set: %w", err)
	}
	return nil
}

// MemoryHistoryStore is an in-memory HistoryStore for the recorded-fixture
// tests (no Valkey in the gate). Safe for concurrent use.
type MemoryHistoryStore struct {
	mu sync.Mutex
	m  map[int64]string
}

// NewMemoryHistoryStore builds an empty MemoryHistoryStore.
func NewMemoryHistoryStore() *MemoryHistoryStore {
	return &MemoryHistoryStore{m: map[int64]string{}}
}

// Get returns the stored cursor, or "" when none is set.
func (s *MemoryHistoryStore) Get(_ context.Context, orgID int64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[orgID], nil
}

// Set persists historyID as the new cursor.
func (s *MemoryHistoryStore) Set(_ context.Context, orgID int64, historyID string) error {
	if historyID == "" {
		return errors.New("gmail history set: empty historyID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[orgID] = historyID
	return nil
}

// compile-time assertions.
var (
	_ HistoryStore = (*ValkeyHistoryStore)(nil)
	_ HistoryStore = (*MemoryHistoryStore)(nil)
)
