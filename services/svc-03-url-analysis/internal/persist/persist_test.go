package persist

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"

	db "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/shared/postgres/repository"
)

// fakeStore records every call so tests can assert exactly which writes fired
// and with what params. Per-method hooks let a test inject errors or prior-read
// hits. It is the in-memory stand-in for the org-scoped repository layer.
type fakeStore struct {
	resolveID    int64
	resolveErr   error
	resolveCalls []db.UpsertBareEnrichedThreatParams

	priorRow db.EnrichedThreat
	priorErr error // defaults to a miss when set to ErrNoPriorEnrichment
	priorSet bool  // when false, GetPriorEnrichedThreat returns a miss

	enrichErr   error
	enrichCalls []db.UpdateEnrichedThreatEnrichmentParams

	emailURLs    []db.ListEmailURLsRow
	emailURLErr  error
	listURLCalls int

	tiErr   error
	tiCalls []db.InsertEmailURLTIMatchParams

	resultErr   error
	resultCalls []db.UpsertEnrichmentResultParams

	enqueueID    int64
	enqueueErr   error
	enqueueCalls []db.EnqueueEnrichmentJobParams

	completeErr   error
	completeCalls []int64

	// orgIDs records the org id every method was called with (RLS GUC proxy).
	orgIDs []int64
}

func (f *fakeStore) ResolveThreatID(_ context.Context, orgID int64, p db.UpsertBareEnrichedThreatParams) (int64, error) {
	f.orgIDs = append(f.orgIDs, orgID)
	f.resolveCalls = append(f.resolveCalls, p)
	if f.resolveErr != nil {
		return 0, f.resolveErr
	}
	id := f.resolveID
	if id == 0 {
		id = 42
	}
	return id, nil
}

func (f *fakeStore) ApplyThreatEnrichment(_ context.Context, orgID int64, p db.UpdateEnrichedThreatEnrichmentParams) error {
	f.orgIDs = append(f.orgIDs, orgID)
	f.enrichCalls = append(f.enrichCalls, p)
	return f.enrichErr
}

func (f *fakeStore) GetPriorEnrichedThreat(_ context.Context, orgID int64, _ string, _ int64) (db.EnrichedThreat, error) {
	f.orgIDs = append(f.orgIDs, orgID)
	if f.priorErr != nil {
		return db.EnrichedThreat{}, f.priorErr
	}
	if !f.priorSet {
		return db.EnrichedThreat{}, repository.ErrNoPriorEnrichment
	}
	return f.priorRow, nil
}

func (f *fakeStore) ListEmailURLs(_ context.Context, orgID, _ int64, _ pgtype.Timestamptz) ([]db.ListEmailURLsRow, error) {
	f.orgIDs = append(f.orgIDs, orgID)
	f.listURLCalls++
	return f.emailURLs, f.emailURLErr
}

func (f *fakeStore) RecordTIMatch(_ context.Context, orgID int64, p db.InsertEmailURLTIMatchParams) error {
	f.orgIDs = append(f.orgIDs, orgID)
	f.tiCalls = append(f.tiCalls, p)
	return f.tiErr
}

func (f *fakeStore) UpsertResult(_ context.Context, orgID int64, p db.UpsertEnrichmentResultParams) (int64, error) {
	f.orgIDs = append(f.orgIDs, orgID)
	f.resultCalls = append(f.resultCalls, p)
	return 7, f.resultErr
}

func (f *fakeStore) EnqueueJob(_ context.Context, orgID int64, p db.EnqueueEnrichmentJobParams) (int64, error) {
	f.orgIDs = append(f.orgIDs, orgID)
	f.enqueueCalls = append(f.enqueueCalls, p)
	if f.enqueueErr != nil {
		return 0, f.enqueueErr
	}
	id := f.enqueueID
	if id == 0 {
		id = 99
	}
	return id, nil
}

func (f *fakeStore) CompleteJob(_ context.Context, orgID, jobID int64) error {
	f.orgIDs = append(f.orgIDs, orgID)
	f.completeCalls = append(f.completeCalls, jobID)
	return f.completeErr
}

func newPersister(s EnrichmentStore) *Persister {
	return New(s, NewMetrics(nil), zerolog.Nop())
}

func sampleEmail() Email {
	return Email{
		OrgID:      55,
		InternalID: 1234,
		FetchedAt:  time.Unix(1_700_000_000, 0).UTC(),
		URLs: []URLResult{{
			RawURL:      "http://evil.example.com/login",
			Normalized:  "http://evil.example.com/login",
			Domain:      "evil.example.com",
			TLD:         "com",
			Apex:        "example.com",
			Score:       88,
			Label:       "phishing",
			TIMatch:     true,
			TIRiskScore: 90,
		}},
	}
}

func TestPersist_HappyPath_WritesAllFive(t *testing.T) {
	store := &fakeStore{resolveID: 42, enqueueID: 99}
	p := newPersister(store)

	if err := p.Persist(context.Background(), sampleEmail()); err != nil {
		t.Fatalf("Persist returned error: %v", err)
	}

	// (1) enriched_threats bare-upsert resolve + UPDATE.
	if len(store.resolveCalls) != 1 {
		t.Fatalf("ResolveThreatID calls = %d, want 1", len(store.resolveCalls))
	}
	if got := store.resolveCalls[0].Url; got != "http://evil.example.com/login" {
		t.Errorf("bare upsert url = %q", got)
	}
	if len(store.enrichCalls) != 1 {
		t.Fatalf("ApplyThreatEnrichment calls = %d, want 1", len(store.enrichCalls))
	}
	upd := store.enrichCalls[0]
	if upd.ID != 42 {
		t.Errorf("enrichment UPDATE threat id = %d, want 42", upd.ID)
	}
	if !upd.RiskScore.Valid || upd.RiskScore.Int32 != 88 {
		t.Errorf("enrichment risk_score = %+v, want 88", upd.RiskScore)
	}
	if !upd.ThreatType.Valid || upd.ThreatType.String != "phishing" {
		t.Errorf("enrichment threat_type = %+v, want phishing", upd.ThreatType)
	}
	if len(upd.Column30) == 0 {
		t.Error("enrichment analysis_metadata (Column30) is empty")
	}

	// (2) enrichment_results UPSERT.
	if len(store.resultCalls) != 1 {
		t.Fatalf("UpsertResult calls = %d, want 1", len(store.resultCalls))
	}
	res := store.resultCalls[0]
	if res.EntityType != db.EntityTypeEnumThreat || res.EntityID != 42 {
		t.Errorf("result entity = (%s,%d), want (threat,42)", res.EntityType, res.EntityID)
	}
	if res.Provider != enrichmentProvider {
		t.Errorf("result provider = %q, want %q", res.Provider, enrichmentProvider)
	}
	if !res.ExpiresAt.Valid {
		t.Error("result expires_at not set (TTL missing)")
	}

	// (3) enrichment_jobs enqueue + complete (lifecycle).
	if len(store.enqueueCalls) != 1 {
		t.Fatalf("EnqueueJob calls = %d, want 1", len(store.enqueueCalls))
	}
	job := store.enqueueCalls[0]
	if job.JobType != db.JobTypeUrlScan || job.EntityType != db.EntityTypeEnumThreat || job.EntityID != 42 {
		t.Errorf("job = %+v, want url_scan/threat/42", job)
	}
	if len(store.completeCalls) != 1 || store.completeCalls[0] != 99 {
		t.Errorf("CompleteJob calls = %v, want [99]", store.completeCalls)
	}

	// (5) prior-email read was attempted once for the URL.
	if store.listURLCalls != 1 {
		t.Errorf("ListEmailURLs calls = %d, want 1", store.listURLCalls)
	}
}

func TestPersist_RLS_EveryWriteCarriesOrgID(t *testing.T) {
	store := &fakeStore{}
	p := newPersister(store)
	if err := p.Persist(context.Background(), sampleEmail()); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if len(store.orgIDs) == 0 {
		t.Fatal("no store calls recorded")
	}
	for i, org := range store.orgIDs {
		if org != 55 {
			t.Errorf("call %d used org_id %d, want 55 (RLS GUC scoping)", i, org)
		}
	}
}

func TestPersist_RejectsMissingOrg(t *testing.T) {
	store := &fakeStore{}
	p := newPersister(store)
	e := sampleEmail()
	e.OrgID = 0
	err := p.Persist(context.Background(), e)
	if !errors.Is(err, repository.ErrNoOrgContext) {
		t.Fatalf("err = %v, want ErrNoOrgContext", err)
	}
	if len(store.resolveCalls) != 0 {
		t.Error("no write should fire without an org id")
	}
}

func TestPersist_PriorEnrichmentReuse_SetsFlagAndMetadata(t *testing.T) {
	store := &fakeStore{
		priorSet: true,
		priorRow: db.EnrichedThreat{ID: 7, RiskScore: pgtype.Int4{Int32: 80, Valid: true}},
	}
	p := newPersister(store)
	if err := p.Persist(context.Background(), sampleEmail()); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	// analysis_metadata should record the reuse.
	var meta map[string]any
	if err := json.Unmarshal(store.enrichCalls[0].Column30, &meta); err != nil {
		t.Fatalf("unmarshal analysis_metadata: %v", err)
	}
	if meta["prior_enrichment_reused"] != true {
		t.Errorf("prior_enrichment_reused = %v, want true", meta["prior_enrichment_reused"])
	}
}

func TestPersist_TIMatchAudit_WritesWhenResolvable(t *testing.T) {
	store := &fakeStore{
		resolveID: 42,
		emailURLs: []db.ListEmailURLsRow{
			{ID: 500, ThreatID: pgtype.Int8{Int64: 42, Valid: true}},
		},
	}
	p := newPersister(store)
	e := sampleEmail()
	e.URLs[0].TIIndicatorID = 9001 // indicator id available
	if err := p.Persist(context.Background(), e); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if len(store.tiCalls) != 1 {
		t.Fatalf("RecordTIMatch calls = %d, want 1", len(store.tiCalls))
	}
	ti := store.tiCalls[0]
	if ti.EmailUrlID != 500 || ti.TiIndicatorID != 9001 {
		t.Errorf("ti match = (eu=%d, ind=%d), want (500, 9001)", ti.EmailUrlID, ti.TiIndicatorID)
	}
	if ti.MatchType != "domain" {
		t.Errorf("ti match_type = %q, want domain", ti.MatchType)
	}
}

func TestPersist_TIMatchAudit_SkippedWithoutIndicatorID(t *testing.T) {
	store := &fakeStore{
		emailURLs: []db.ListEmailURLsRow{
			{ID: 500, ThreatID: pgtype.Int8{Int64: 42, Valid: true}},
		},
	}
	p := newPersister(store)
	// sampleEmail has TIMatch=true but TIIndicatorID=0 → no audit row.
	if err := p.Persist(context.Background(), sampleEmail()); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if len(store.tiCalls) != 0 {
		t.Errorf("RecordTIMatch fired %d times without an indicator id", len(store.tiCalls))
	}
}

func TestPersist_TIMatchAudit_SkippedWhenEmailURLUnresolved(t *testing.T) {
	// No email_urls persisted yet (SVC-02 P1.1 not wired) → fail-soft, the
	// threat-level writes still run, only the audit row is skipped.
	store := &fakeStore{resolveID: 42}
	p := newPersister(store)
	e := sampleEmail()
	e.URLs[0].TIIndicatorID = 9001
	if err := p.Persist(context.Background(), e); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if len(store.tiCalls) != 0 {
		t.Errorf("RecordTIMatch fired %d times with no resolvable email_url", len(store.tiCalls))
	}
	if len(store.enrichCalls) != 1 {
		t.Error("threat-level enrichment UPDATE should still run when audit is skipped")
	}
}

func TestPersist_BestEffort_OneURLFailureDoesNotAbortOthers(t *testing.T) {
	store := &fakeStore{resolveID: 42}
	e := sampleEmail()
	good := e.URLs[0]
	bad := good
	bad.RawURL = "http://broken.example.com/"
	bad.Domain = "broken.example.com"
	e.URLs = []URLResult{bad, good}

	// First Resolve succeeds (id 42); make the FIRST enrichment UPDATE fail so
	// URL #1 errors, then assert URL #2 still wrote. The failure is injected via
	// a wrapper store so the second URL exercises the real fake.
	wrapped := &failFirstEnrich{fakeStore: store}
	p := newPersister(wrapped)
	err := p.Persist(context.Background(), e)
	if err == nil {
		t.Fatal("expected first URL's error to surface")
	}
	// Both URLs attempted the resolve; the second completed its enrichment
	// (recorded on the underlying fake after the wrapper let it through).
	if len(store.resolveCalls) != 2 {
		t.Errorf("ResolveThreatID calls = %d, want 2 (both URLs attempted)", len(store.resolveCalls))
	}
	if len(store.enrichCalls) != 1 {
		t.Errorf("second URL enrichment calls = %d, want 1 (first failed in wrapper)", len(store.enrichCalls))
	}
}

// failFirstEnrich fails the first ApplyThreatEnrichment call, succeeds after.
type failFirstEnrich struct {
	*fakeStore
	n int
}

func (w *failFirstEnrich) ApplyThreatEnrichment(ctx context.Context, orgID int64, p db.UpdateEnrichedThreatEnrichmentParams) error {
	w.n++
	if w.n == 1 {
		return errors.New("boom")
	}
	return w.fakeStore.ApplyThreatEnrichment(ctx, orgID, p)
}

// buildEnrichmentUpdate must leave risk_score (and threat_type) NULL for a
// benign re-observation so the COALESCE UPDATE preserves any prior verdict,
// while still writing the score/type for a real phishing verdict. risk_score
// relies on pgconv.Int4OrNull to map Score=0 to NULL (the NYC-3 no-clobber fix).
func TestBuildEnrichmentUpdateBenignDoesNotClobber(t *testing.T) {
	p := &Persister{}

	benign := p.buildEnrichmentUpdate(7, &URLResult{Score: 0, Label: "legitimate"}, nil)
	if benign.RiskScore.Valid {
		t.Errorf("benign risk_score = %+v, want NULL", benign.RiskScore)
	}
	if benign.ThreatType.Valid {
		t.Errorf("benign threat_type = %+v, want NULL", benign.ThreatType)
	}

	phish := p.buildEnrichmentUpdate(7, &URLResult{Score: 90, Label: "phishing"}, nil)
	if !phish.RiskScore.Valid || phish.RiskScore.Int32 != 90 {
		t.Errorf("phishing risk_score = %+v, want 90", phish.RiskScore)
	}
	if !phish.ThreatType.Valid || phish.ThreatType.String != "phishing" {
		t.Errorf("phishing threat_type = %+v, want phishing", phish.ThreatType)
	}
}

func TestThreatTypeForLabel(t *testing.T) {
	cases := map[string]string{
		"phishing":   "phishing",
		"suspicious": "suspicious",
		"legitimate": "",
		"":           "",
	}
	for in, want := range cases {
		if got := threatTypeForLabel(in); got != want {
			t.Errorf("threatTypeForLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTIMatchType(t *testing.T) {
	if got := tiMatchType(&URLResult{TIThreatType: "url"}); got != "exact" {
		t.Errorf("url indicator → %q, want exact", got)
	}
	if got := tiMatchType(&URLResult{TIThreatType: "phishing"}); got != "domain" {
		t.Errorf("domain indicator → %q, want domain", got)
	}
}

func TestAnalysisMetadata_OmitsEmptyAndEncodesSignals(t *testing.T) {
	u := URLResult{
		RawURL:      "http://x.test/",
		Label:       "phishing",
		Score:       77,
		TIMatch:     true,
		TIRiskScore: 88,
		MLVerdict:   "phishing",
		MLDeployP:   0.91,
	}
	var meta map[string]any
	if err := json.Unmarshal(u.analysisMetadata(), &meta); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if meta["source"] != "svc-03-url-analysis" {
		t.Errorf("source = %v", meta["source"])
	}
	if meta["ml_verdict"] != "phishing" {
		t.Errorf("ml_verdict = %v", meta["ml_verdict"])
	}
	if _, ok := meta["guard_hit"]; ok {
		t.Error("empty guard_hit should be omitted")
	}
	if meta["ti_risk_score"] != float64(88) {
		t.Errorf("ti_risk_score = %v, want 88", meta["ti_risk_score"])
	}
}
