package main

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// scan is everything the dashboard knows about one email it is tracking. It is
// assembled from three sources over time: the submit (subject/from/source), the
// emails.scored message (per-module breakdown), and the emails.verdict message
// (final label). All fields are best-effort — the UI renders whatever is present.
type scan struct {
	EmailID     string
	Source      string // "upload" | "gmail"
	Subject     string
	From        string
	SubmittedAt time.Time

	Scored   *contracts.EmailsScored
	Header   *contracts.ScoresHeaderMessage // svc-04 emits the typed contract
	Attach   *contracts.ScoresAttachment    // svc-05 emits the typed contract
	ScoredAt time.Time
	// URL (svc-03) and NLP (svc-06) still emit the legacy ScoreEnvelope, so their
	// detail is decoded flexibly from es.ComponentDetails in view.go, not here.

	Verdict   *contracts.EmailsVerdict
	VerdictAt time.Time
}

// store is a bounded, in-memory cache of scans keyed by email_id, plus an
// ordered feed of the email_ids this dashboard submitted. There is no DB; when a
// persistence file is configured it is mirrored to a small gitignored JSON file
// so scans survive a restart (the Kafka consumers resume from their committed
// offset and would not replay them).
type store struct {
	mu    sync.RWMutex
	byID  map[string]*scan
	feed  []string // email_ids in submit order, newest last
	limit int
	file  string // JSON persistence path ("" = ephemeral / no persistence)
	dirty bool
	log   zerolog.Logger // flush diagnostics; defaults to a no-op logger
}

func newStore(limit int, file string) *store {
	if limit <= 0 {
		limit = 200
	}
	s := &store{byID: make(map[string]*scan), limit: limit, file: file, log: zerolog.Nop()}
	s.load()
	return s
}

// withLogger attaches a logger for flush diagnostics, returning the store for
// chaining. Optional: the store defaults to a no-op logger.
func (s *store) withLogger(log zerolog.Logger) *store {
	s.mu.Lock()
	s.log = log
	s.mu.Unlock()
	return s
}

// persistedStore is the on-disk shape of the store.
type persistedStore struct {
	ByID map[string]*scan `json:"by_id"`
	Feed []string         `json:"feed"`
}

// load reads the persistence file into the store, if configured and present.
func (s *store) load() {
	if s.file == "" {
		return
	}
	b, err := os.ReadFile(s.file)
	if err != nil {
		return
	}
	var p persistedStore
	if json.Unmarshal(b, &p) != nil {
		return
	}
	s.mu.Lock()
	if p.ByID != nil {
		s.byID = p.ByID
	}
	s.feed = p.Feed
	s.evictLocked()
	s.mu.Unlock()
}

// flush atomically writes the store to disk when there is unsaved state.
func (s *store) flush() {
	if s.file == "" {
		return
	}
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return
	}
	b, err := json.Marshal(persistedStore{ByID: s.byID, Feed: s.feed})
	s.mu.Unlock()
	if err != nil {
		// Marshalling a snapshot of the store should not fail in practice; leave
		// dirty set so the next tick retries.
		s.log.Error().Err(err).Msg("store: marshal snapshot failed")
		return
	}
	// Write to a temp file then rename so a reader never sees a half-written
	// snapshot. Only clear the dirty flag once the snapshot is durably in place;
	// on any failure we keep dirty=true so the next flush tick retries.
	tmp := s.file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		s.log.Error().Err(err).Str("file", tmp).Msg("store: write snapshot failed")
		return
	}
	if err := os.Rename(tmp, s.file); err != nil {
		s.log.Error().Err(err).Str("file", s.file).Msg("store: rename snapshot failed")
		return
	}
	s.mu.Lock()
	s.dirty = false
	s.mu.Unlock()
}

// runFlusher persists the store every couple seconds while dirty, with a final
// flush when ctx is cancelled (graceful shutdown), so scans survive a restart.
func (s *store) runFlusher(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.flush()
			return
		case <-t.C:
			s.flush()
		}
	}
}

// getOrCreate returns the scan for id, creating an empty one if absent. Caller
// must hold s.mu.
func (s *store) getOrCreate(id string) *scan {
	sc := s.byID[id]
	if sc == nil {
		sc = &scan{EmailID: id}
		s.byID[id] = sc
	}
	return sc
}

// recordSubmit registers an email this dashboard just forwarded to svc-01 and
// adds it to the feed.
func (s *store) recordSubmit(id, source, subject, from string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sc := s.getOrCreate(id)
	sc.Source = source
	sc.Subject = subject
	sc.From = from
	sc.SubmittedAt = time.Now().UTC()
	s.feed = append(s.feed, id)
	s.dirty = true
	s.evictLocked()
}

// applyScored folds an emails.scored message into the cache, decoding the
// verbatim component_details into typed per-module structs.
func (s *store) applyScored(es *contracts.EmailsScored) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sc := s.getOrCreate(es.Meta.EmailID)
	sc.Scored = es
	sc.ScoredAt = time.Now().UTC()
	sc.Header = decodeInto[contracts.ScoresHeaderMessage](es.ComponentDetails.Header)
	sc.Attach = decodeInto[contracts.ScoresAttachment](es.ComponentDetails.Attachment)
	s.dirty = true
	s.evictLocked()
}

// applyVerdict folds an emails.verdict message into the cache.
func (s *store) applyVerdict(ev *contracts.EmailsVerdict) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sc := s.getOrCreate(ev.Meta.EmailID)
	sc.Verdict = ev
	sc.VerdictAt = time.Now().UTC()
	s.dirty = true
	s.evictLocked()
}

// get returns a shallow copy of the scan for id, or nil if unknown.
func (s *store) get(id string) *scan {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sc := s.byID[id]
	if sc == nil {
		return nil
	}
	cp := *sc
	return &cp
}

// feedItems returns the most-recent submitted scans, newest first.
func (s *store) feedItems() []feedItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]feedItem, 0, len(s.feed))
	for i := len(s.feed) - 1; i >= 0; i-- {
		sc := s.byID[s.feed[i]]
		if sc == nil {
			continue
		}
		out = append(out, feedItem{
			EmailID:     sc.EmailID,
			Source:      sc.Source,
			Subject:     sc.Subject,
			From:        sc.From,
			SubmittedAt: sc.SubmittedAt,
			Status:      statusOf(sc),
			Label:       labelOf(sc),
			RiskScore:   riskOf(sc),
		})
	}
	return out
}

// evictLocked keeps the cache bounded. It drops the oldest feed entries and any
// cached scan no longer referenced by the feed. Caller must hold s.mu.
func (s *store) evictLocked() {
	for len(s.feed) > s.limit {
		s.feed = s.feed[1:]
	}
	if len(s.byID) <= s.limit*2 {
		return
	}
	keep := make(map[string]struct{}, len(s.feed))
	for _, id := range s.feed {
		keep[id] = struct{}{}
	}
	for id := range s.byID {
		if _, ok := keep[id]; !ok {
			delete(s.byID, id)
		}
	}
}

// decodeInto unmarshals a verbatim component_details blob into T, returning nil
// when the blob is empty (component absent) or malformed.
func decodeInto[T any](raw json.RawMessage) *T {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	return &v
}

// feedItem is the compact row shown in the recent-scans list.
type feedItem struct {
	EmailID     string    `json:"email_id"`
	Source      string    `json:"source"`
	Subject     string    `json:"subject"`
	From        string    `json:"from"`
	SubmittedAt time.Time `json:"submitted_at"`
	Status      string    `json:"status"`
	Label       string    `json:"label,omitempty"`
	RiskScore   *int      `json:"risk_score,omitempty"`
}

func statusOf(sc *scan) string {
	if sc.Verdict != nil {
		return "scored"
	}
	if sc.Scored != nil {
		return "scoring"
	}
	return "pending"
}

func labelOf(sc *scan) string {
	if sc.Verdict != nil {
		return sc.Verdict.VerdictLabel
	}
	return ""
}

func riskOf(sc *scan) *int {
	if sc.Verdict != nil {
		r := sc.Verdict.RiskScore
		return &r
	}
	return nil
}
