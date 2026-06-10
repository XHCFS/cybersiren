package processor

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-05-attachment-analysis/internal/scoring"
	"github.com/saif/cybersiren/services/svc-05-attachment-analysis/internal/store"
	"github.com/saif/cybersiren/services/svc-05-attachment-analysis/internal/vt"
	contractsk "github.com/saif/cybersiren/shared/contracts/kafka"
	sharedconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
)

// ── fakes ────────────────────────────────────────────────────────────────

type fakeStore struct {
	verdicts map[string]store.HashVerdict // keyed by sha256
	vtCache  map[int64]store.CachedVT     // keyed by library id

	flagged       []string // sha256s flagged malicious
	scoreUpdates  []store.EmailAttachmentScore
	updateAffects int64 // rows the score update reports affected (default 1)

	failHashLookup  bool
	failScoreUpdate bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		verdicts:      map[string]store.HashVerdict{},
		vtCache:       map[int64]store.CachedVT{},
		updateAffects: 1,
	}
}

func (f *fakeStore) GetHashVerdict(_ context.Context, _ int64, sha256 string) (store.HashVerdict, error) {
	if f.failHashLookup {
		return store.HashVerdict{}, errors.New("boom")
	}
	if v, ok := f.verdicts[sha256]; ok {
		return v, nil
	}
	return store.HashVerdict{Found: false}, nil
}

func (f *fakeStore) GetFreshVT(_ context.Context, _ int64, libraryID int64) (store.CachedVT, error) {
	if v, ok := f.vtCache[libraryID]; ok {
		return v, nil
	}
	return store.CachedVT{Found: false}, nil
}

func (f *fakeStore) CacheVT(_ context.Context, _, libraryID int64, _ time.Time, in store.VTCacheInput, _ time.Duration) error {
	f.vtCache[libraryID] = store.CachedVT{
		Found:          true,
		MaliciousVotes: in.MaliciousVotes,
		Raw:            in.Raw,
	}
	return nil
}

func (f *fakeStore) FlagMalicious(_ context.Context, _ int64, sha256 string, _ int, _ []string) error {
	f.flagged = append(f.flagged, sha256)
	return nil
}

func (f *fakeStore) UpdateEmailAttachmentScore(_ context.Context, in store.EmailAttachmentScore) (int64, error) {
	if f.failScoreUpdate {
		return 0, errors.New("update failed")
	}
	f.scoreUpdates = append(f.scoreUpdates, in)
	return f.updateAffects, nil
}

type fakeVT struct {
	enabled bool
	byHash  map[string]vt.Result
	calls   int
	err     error
}

func (f *fakeVT) Enabled() bool { return f.enabled }

func (f *fakeVT) Lookup(_ context.Context, sha256 string) (vt.Result, error) {
	f.calls++
	if f.err != nil {
		return vt.Result{Skipped: true}, f.err
	}
	if r, ok := f.byHash[sha256]; ok {
		return r, nil
	}
	return vt.Result{Skipped: true}, nil
}

type fakePublisher struct {
	published [][]byte
	err       error
}

func (f *fakePublisher) Publish(_ context.Context, _, value []byte, _ int) error {
	if f.err != nil {
		return f.err
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	f.published = append(f.published, cp)
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────

func newTestProcessor(st store.Store, v vtLookup, pub publisher) *Processor {
	return newTestProcessorWithMetrics(st, v, pub, nil)
}

func newTestProcessorWithMetrics(st store.Store, v vtLookup, pub publisher, m *Metrics) *Processor {
	return New(Config{
		Scoring: scoring.Config{
			EntropyThreshold:       7.5,
			HighEntropyScore:       20,
			ExtensionMismatchScore: 30,
			DangerousExtScore:      25,
			MacroOfficeScore:       20,
			DoubleExtScore:         35,
			MaliciousHashScore:     90,
		},
		VTCacheTTL:           24 * time.Hour,
		PublishRetryAttempts: 0,
	}, st, v, pub, m, zerolog.Nop())
}

func msgFor(m contractsk.AnalysisAttachments) sharedconsumer.Message {
	body, _ := json.Marshal(m)
	return sharedconsumer.Message{Value: body}
}

func decodePublished(t *testing.T, raw []byte) contractsk.ScoresAttachment {
	t.Helper()
	var out contractsk.ScoresAttachment
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal published scores.attachment: %v", err)
	}
	return out
}

// ── tests ────────────────────────────────────────────────────────────────

func TestDecodeMessage(t *testing.T) {
	good := contractsk.AnalysisAttachments{
		Meta:        contractsk.NewMetaWithFetched(7, 1, time.Now().UTC()),
		Attachments: []contractsk.Attachment{{SHA256: "a", Filename: "x.pdf"}},
	}
	body, _ := json.Marshal(good)
	parsed, err := decodeMessage(body)
	if err != nil {
		t.Fatalf("decode good: %v", err)
	}
	if parsed.Meta.EmailID != 7 || len(parsed.Attachments) != 1 {
		t.Fatalf("decoded mismatch: %+v", parsed)
	}
	if _, err := decodeMessage(nil); err == nil {
		t.Error("empty body should error")
	}
	if _, err := decodeMessage([]byte("nope")); err == nil {
		t.Error("garbage should error")
	}
	zero := contractsk.AnalysisAttachments{Meta: contractsk.NewMeta(0, 1)}
	zb, _ := json.Marshal(zero)
	if _, err := decodeMessage(zb); err == nil {
		t.Error("email_id=0 should error")
	}
}

func TestEncodeKey(t *testing.T) {
	for _, id := range []int64{1, 99, 1234567890} {
		if got := string(encodeKey(id)); got != strconv.FormatInt(id, 10) {
			t.Errorf("encodeKey(%d)=%q", id, got)
		}
	}
}

func TestHandle_MalformedSkipsAndCommits(t *testing.T) {
	pub := &fakePublisher{}
	p := newTestProcessor(newFakeStore(), &fakeVT{}, pub)
	// Non-nil error would NACK; malformed must return nil (commit) and not publish.
	if err := p.Handle(context.Background(), sharedconsumer.Message{Value: []byte("garbage")}); err != nil {
		t.Fatalf("malformed message should commit (nil err), got %v", err)
	}
	if len(pub.published) != 0 {
		t.Fatal("malformed message must not publish")
	}
}

func TestHandle_PerEmailMaxAndPersist(t *testing.T) {
	st := newFakeStore()
	// Two known library entries so the email_attachments update + VT path engage.
	st.verdicts["benignhash"] = store.HashVerdict{Found: true, ID: 11, IsMalicious: false}
	st.verdicts["exehash"] = store.HashVerdict{Found: true, ID: 22, IsMalicious: false}

	pub := &fakePublisher{}
	p := newTestProcessor(st, &fakeVT{enabled: false}, pub)

	fetchedAt := time.Now().UTC()
	in := contractsk.AnalysisAttachments{
		Meta: contractsk.NewMetaWithFetched(7, 1, fetchedAt),
		Attachments: []contractsk.Attachment{
			{SHA256: "benignhash", Filename: "report.pdf", ContentType: "application/pdf", Entropy: 3.0},
			{SHA256: "exehash", Filename: "invoice.pdf.exe", Entropy: 7.9}, // dangerous + double-ext + high-entropy = 25+35+20 = 80
		},
	}
	if err := p.Handle(context.Background(), msgFor(in)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(pub.published) != 1 {
		t.Fatalf("expected 1 published message, got %d", len(pub.published))
	}
	out := decodePublished(t, pub.published[0])
	if out.Component != contractsk.ComponentAttachment {
		t.Errorf("component = %q", out.Component)
	}
	if out.Score != 80 {
		t.Fatalf("per-email score = %d, want 80 (max of 0 and 80)", out.Score)
	}
	if out.AttachmentCount != 2 {
		t.Errorf("attachment_count = %d, want 2", out.AttachmentCount)
	}
	if len(out.AttachmentDetails) != 2 {
		t.Fatalf("expected 2 details, got %d", len(out.AttachmentDetails))
	}
	// Both known-library attachments must have triggered the email_attachments write-back.
	if len(st.scoreUpdates) != 2 {
		t.Fatalf("expected 2 risk_score updates, got %d", len(st.scoreUpdates))
	}
	for _, u := range st.scoreUpdates {
		if u.InternalID != 7 || u.OrgID != 1 {
			t.Errorf("update keyed wrong: %+v", u)
		}
		if len(u.AnalysisMetadata) == 0 {
			t.Error("analysis_metadata blob should be populated")
		}
	}
}

func TestHandle_MaliciousHashFlagsLibraryAndScores90(t *testing.T) {
	st := newFakeStore()
	st.verdicts["malhash"] = store.HashVerdict{Found: true, ID: 99, IsMalicious: true, RiskScore: 90}

	pub := &fakePublisher{}
	p := newTestProcessor(st, &fakeVT{enabled: false}, pub)

	in := contractsk.AnalysisAttachments{
		Meta:        contractsk.NewMetaWithFetched(5, 2, time.Now().UTC()),
		Attachments: []contractsk.Attachment{{SHA256: "malhash", Filename: "clean.pdf", ContentType: "application/pdf"}},
	}
	if err := p.Handle(context.Background(), msgFor(in)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	out := decodePublished(t, pub.published[0])
	if out.Score != 90 {
		t.Fatalf("malicious-hash email score = %d, want 90", out.Score)
	}
	if out.MaliciousCount != 1 {
		t.Fatalf("malicious_count = %d, want 1", out.MaliciousCount)
	}
	d := out.AttachmentDetails[0]
	if !d.IsMalicious {
		t.Error("detail.is_malicious should be true")
	}
	if d.TISource == nil || *d.TISource != "attachment_library" {
		t.Errorf("ti_source = %v, want attachment_library", d.TISource)
	}
	if len(st.flagged) != 1 || st.flagged[0] != "malhash" {
		t.Errorf("expected attachment_library flag for malhash, got %v", st.flagged)
	}
}

func TestHandle_VirusTotalMaliciousElevates(t *testing.T) {
	st := newFakeStore()
	st.verdicts["vth"] = store.HashVerdict{Found: true, ID: 33, IsMalicious: false}
	v := &fakeVT{
		enabled: true,
		byHash:  map[string]vt.Result{"vth": {MaliciousVotes: 5, Raw: []byte(`{"ok":true}`)}},
	}
	pub := &fakePublisher{}
	p := newTestProcessor(st, v, pub)

	in := contractsk.AnalysisAttachments{
		Meta:        contractsk.NewMetaWithFetched(8, 3, time.Now().UTC()),
		Attachments: []contractsk.Attachment{{SHA256: "vth", Filename: "doc.pdf", ContentType: "application/pdf"}},
	}
	if err := p.Handle(context.Background(), msgFor(in)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	out := decodePublished(t, pub.published[0])
	if out.Score != 90 {
		t.Fatalf("VT-malicious email score = %d, want 90", out.Score)
	}
	if v.calls != 1 {
		t.Fatalf("VT should have been queried once, got %d", v.calls)
	}
	// The fresh VT result must have been written to the 24h cache.
	if c, ok := st.vtCache[33]; !ok || !c.Found {
		t.Error("VT result should be cached after a fresh lookup")
	}
	if out.AttachmentDetails[0].TISource == nil || *out.AttachmentDetails[0].TISource != "virustotal" {
		t.Errorf("ti_source = %v, want virustotal", out.AttachmentDetails[0].TISource)
	}
}

func TestHandle_VirusTotalCacheHitSkipsAPI(t *testing.T) {
	st := newFakeStore()
	st.verdicts["ch"] = store.HashVerdict{Found: true, ID: 44, IsMalicious: false}
	st.vtCache[44] = store.CachedVT{Found: true, MaliciousVotes: 3}
	v := &fakeVT{enabled: true} // would skip if called
	pub := &fakePublisher{}
	p := newTestProcessor(st, v, pub)

	in := contractsk.AnalysisAttachments{
		Meta:        contractsk.NewMetaWithFetched(9, 4, time.Now().UTC()),
		Attachments: []contractsk.Attachment{{SHA256: "ch", Filename: "doc.pdf", ContentType: "application/pdf"}},
	}
	if err := p.Handle(context.Background(), msgFor(in)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if v.calls != 0 {
		t.Fatalf("cache hit must not call the VT API, got %d calls", v.calls)
	}
	out := decodePublished(t, pub.published[0])
	if out.Score != 90 {
		t.Fatalf("cached-VT-malicious score = %d, want 90", out.Score)
	}
}

func TestHandle_NoVTKeyNeverErrorsNorCalls(t *testing.T) {
	st := newFakeStore()
	st.verdicts["h"] = store.HashVerdict{Found: true, ID: 1, IsMalicious: false}
	v := &fakeVT{enabled: false}
	pub := &fakePublisher{}
	p := newTestProcessor(st, v, pub)

	in := contractsk.AnalysisAttachments{
		Meta:        contractsk.NewMetaWithFetched(1, 1, time.Now().UTC()),
		Attachments: []contractsk.Attachment{{SHA256: "h", Filename: "doc.pdf", ContentType: "application/pdf"}},
	}
	if err := p.Handle(context.Background(), msgFor(in)); err != nil {
		t.Fatalf("no-key path must never error: %v", err)
	}
	if v.calls != 0 {
		t.Fatalf("disabled VT must not be called, got %d", v.calls)
	}
}

func TestHandle_HashLookupErrorDegrades(t *testing.T) {
	st := newFakeStore()
	st.failHashLookup = true
	pub := &fakePublisher{}
	p := newTestProcessor(st, &fakeVT{}, pub)

	in := contractsk.AnalysisAttachments{
		Meta:        contractsk.NewMetaWithFetched(2, 1, time.Now().UTC()),
		Attachments: []contractsk.Attachment{{SHA256: "x", Filename: "invoice.pdf.exe", Entropy: 7.9}},
	}
	// A hash-lookup READ error must NOT NACK — heuristics still score and publish.
	if err := p.Handle(context.Background(), msgFor(in)); err != nil {
		t.Fatalf("hash-lookup error should degrade, not error: %v", err)
	}
	out := decodePublished(t, pub.published[0])
	if out.Score != 80 {
		t.Fatalf("heuristic-only score = %d, want 80", out.Score)
	}
}

func TestHandle_ScoreUpdateErrorNACKs(t *testing.T) {
	st := newFakeStore()
	st.verdicts["h"] = store.HashVerdict{Found: true, ID: 1, IsMalicious: false}
	st.failScoreUpdate = true
	pub := &fakePublisher{}
	p := newTestProcessor(st, &fakeVT{enabled: false}, pub)

	in := contractsk.AnalysisAttachments{
		Meta:        contractsk.NewMetaWithFetched(3, 1, time.Now().UTC()),
		Attachments: []contractsk.Attachment{{SHA256: "h", Filename: "doc.pdf", ContentType: "application/pdf"}},
	}
	// A DB-write failure MUST NACK (non-nil error) and not publish.
	if err := p.Handle(context.Background(), msgFor(in)); err == nil {
		t.Fatal("score-update failure should NACK")
	}
	if len(pub.published) != 0 {
		t.Fatal("a NACKed message must not publish")
	}
}

// TestHandle_WritebackMissCountsMetric locks the SVC-05 observability fix: when
// the email_attachments risk_score UPDATE matches 0 rows (the SVC-02 link is not
// yet persisted / two-id mismatch) the message still succeeds (the scores payload
// flows), but the gap is now counted on
// attachment_analysis_errors_total{stage="writeback_miss"} so a systematic miss
// is visible on dashboards instead of only by log-grep.
func TestHandle_WritebackMissCountsMetric(t *testing.T) {
	st := newFakeStore()
	st.verdicts["h"] = store.HashVerdict{Found: true, ID: 1, IsMalicious: false}
	st.updateAffects = 0 // simulate the SVC-02 link not yet persisted

	m := NewMetrics(nil)
	pub := &fakePublisher{}
	p := newTestProcessorWithMetrics(st, &fakeVT{enabled: false}, pub, m)

	in := contractsk.AnalysisAttachments{
		Meta:        contractsk.NewMetaWithFetched(12, 1, time.Now().UTC()),
		Attachments: []contractsk.Attachment{{SHA256: "h", Filename: "doc.pdf", ContentType: "application/pdf"}},
	}
	// A 0-row write-back is NOT a NACK: the scores.attachment payload must still flow.
	if err := p.Handle(context.Background(), msgFor(in)); err != nil {
		t.Fatalf("0-row write-back must not error: %v", err)
	}
	if len(pub.published) != 1 {
		t.Fatalf("expected the scores.attachment payload to still publish, got %d", len(pub.published))
	}
	if got := testutil.ToFloat64(m.ErrorsTotal.WithLabelValues("writeback_miss")); got != 1 {
		t.Fatalf("attachment_analysis_errors_total{stage=writeback_miss} = %v, want 1", got)
	}
	// A successful (1-row) write-back must NOT increment writeback_miss.
	st.updateAffects = 1
	if err := p.Handle(context.Background(), msgFor(in)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if got := testutil.ToFloat64(m.ErrorsTotal.WithLabelValues("writeback_miss")); got != 1 {
		t.Fatalf("writeback_miss must not increment on a matched write-back, got %v", got)
	}
}

func TestHandle_NoAttachmentsEmitsNeutral(t *testing.T) {
	pub := &fakePublisher{}
	p := newTestProcessor(newFakeStore(), &fakeVT{}, pub)

	in := contractsk.AnalysisAttachments{
		Meta:        contractsk.NewMetaWithFetched(4, 1, time.Now().UTC()),
		Attachments: nil,
	}
	if err := p.Handle(context.Background(), msgFor(in)); err != nil {
		t.Fatalf("empty-attachment email should still emit a score: %v", err)
	}
	out := decodePublished(t, pub.published[0])
	if out.Score != 0 || out.AttachmentCount != 0 {
		t.Fatalf("neutral score expected, got score=%d count=%d", out.Score, out.AttachmentCount)
	}
}

func TestHandle_PublishErrorNACKs(t *testing.T) {
	pub := &fakePublisher{err: errors.New("kafka down")}
	p := newTestProcessor(newFakeStore(), &fakeVT{}, pub)

	in := contractsk.AnalysisAttachments{
		Meta:        contractsk.NewMetaWithFetched(6, 1, time.Now().UTC()),
		Attachments: []contractsk.Attachment{{SHA256: "h", Filename: "x.pdf"}},
	}
	if err := p.Handle(context.Background(), msgFor(in)); err == nil {
		t.Fatal("publish failure should NACK")
	}
}

// TestInternalIDOf_PrefersInternalID locks the two-id key selection (G17): the
// email_attachments write-back must key on emails.internal_id (the DB BIGSERIAL
// svc-02 stamps onto analysis.attachments), falling back to the logical
// Meta.EmailID only while svc-02 has not yet populated it. Mirrors svc-03's
// url-pipeline prefer/fallback.
func TestInternalIDOf_PrefersInternalID(t *testing.T) {
	withID := contractsk.AnalysisAttachments{
		Meta:       contractsk.MessageMeta{EmailID: 1_700_000_000_000_000},
		InternalID: 42,
	}
	if got := internalIDOf(withID); got != 42 {
		t.Fatalf("internalIDOf with InternalID=42 = %d, want 42 (must prefer the surrogate)", got)
	}

	fallback := contractsk.AnalysisAttachments{
		Meta: contractsk.MessageMeta{EmailID: 99},
	}
	if got := internalIDOf(fallback); got != 99 {
		t.Fatalf("internalIDOf with InternalID=0 = %d, want 99 (must fall back to email_id)", got)
	}
}
