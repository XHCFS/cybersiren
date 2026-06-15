package engine

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/saif/cybersiren/services/svc-08-decision/internal/campaign"
	"github.com/saif/cybersiren/services/svc-08-decision/internal/metrics"
	"github.com/saif/cybersiren/services/svc-08-decision/internal/persist"
	"github.com/saif/cybersiren/services/svc-08-decision/internal/rules"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
)

type fakeRules struct {
	rules []rules.CachedRule
	err   error
}

func (f fakeRules) Get(_ context.Context, _ int64) ([]rules.CachedRule, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.rules, nil
}

type fakeSimhash struct{}

func (fakeSimhash) Compute(string) (uint64, bool) { return 0, false }
func (fakeSimhash) Lookup(context.Context, int64, uint64) (campaign.Match, bool, error) {
	return campaign.Match{}, false, nil
}
func (fakeSimhash) Store(context.Context, int64, int64, uint64, string) error { return nil }

type fakeWriter struct {
	out       persist.Output
	err       error
	lastInput persist.Input
	writes    int
}

func (f *fakeWriter) Write(_ context.Context, in persist.Input) (persist.Output, error) {
	f.lastInput = in
	f.writes++
	return f.out, f.err
}

func (f *fakeWriter) GetCampaignHistory(context.Context, int64, string) (*persist.CampaignHistory, error) {
	return nil, nil
}

type publishedRecord struct {
	key     []byte
	value   []byte
	retries int
}

type fakePublisher struct {
	records []publishedRecord
}

func (f *fakePublisher) Publish(_ context.Context, key, value []byte, retries int) error {
	f.records = append(f.records, publishedRecord{
		key:     append([]byte(nil), key...),
		value:   append([]byte(nil), value...),
		retries: retries,
	})
	return nil
}

// makeScoredMessage builds a minimal scored message carrying a single URL
// component (77) — a model-sourced email in the phishing band. It is just the
// general makeScoredMessageWith with that one component, kept as a named helper
// for the many tests that don't care about the component mix.
func makeScoredMessage(t *testing.T, internalID int64, emailID string) kafkaconsumer.Message {
	t.Helper()
	return makeScoredMessageWith(t, internalID, emailID, Components{URL: ptrInt(77)})
}

// makeScoredMessageWith builds an emails.scored carrying the given component
// scores so tests can drive a chosen blended/final risk band. A nil score is
// omitted (absent component).
func makeScoredMessageWith(t *testing.T, internalID int64, emailID string, c Components) kafkaconsumer.Message {
	t.Helper()
	fetched := time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC)
	body, err := json.Marshal(contracts.EmailsScored{
		Meta:            contracts.NewMetaWithFetched(emailID, 7, fetched),
		InternalID:      internalID,
		FetchedAt:       fetched,
		URLScore:        c.URL,
		HeaderScore:     c.Header,
		NLPScore:        c.NLP,
		AttachmentScore: c.Attachment,
	})
	require.NoError(t, err)
	return kafkaconsumer.Message{Value: body}
}

func TestDecodeScored_AllowsDistinctInternalAndMetaEmailID(t *testing.T) {
	t.Parallel()
	msg := makeScoredMessage(t, 2001, "e1001")
	got, err := decodeScored(msg.Value)
	require.NoError(t, err)
	require.Equal(t, int64(2001), got.InternalID)
	require.Equal(t, "e1001", got.Meta.EmailID)
}

// A scored message with internal_id<=0 is unaddressable poison (it should have
// been dropped at svc-07's producer). decodeScored must reject it with the
// errUnresolvedInternalID sentinel so Handle can log it loudly — yet still
// commit the offset (a NACK would wedge the partition forever). Finding #8.
func TestDecodeScored_RejectsUnresolvedInternalID(t *testing.T) {
	t.Parallel()
	_, err := decodeScored(makeScoredMessage(t, 0, "e0").Value)
	require.Error(t, err)
	require.ErrorIs(t, err, errUnresolvedInternalID)

	_, err = decodeScored(makeScoredMessage(t, -1, "eneg").Value)
	require.ErrorIs(t, err, errUnresolvedInternalID)
}

func TestHandle_UnresolvedInternalID_CommitsWithoutWritingVerdict(t *testing.T) {
	t.Parallel()
	writer := &fakeWriter{out: persist.Output{CampaignID: 17, VerdictID: 44, EmailCount: 1}}
	pub := &fakePublisher{}
	eng := New(
		Config{},
		fakeRules{},
		fakeSimhash{},
		writer,
		pub,
		nil,
		zerolog.Nop(),
	)

	// Poison: internal_id=0. Handle must commit the offset (nil) but write no
	// verdict and publish nothing — the silent-data-loss path is now loud-but-safe.
	err := eng.Handle(context.Background(), makeScoredMessage(t, 0, "e0"))
	require.NoError(t, err, "poison must commit the offset, not NACK")
	require.Equal(t, 0, writer.writes, "no verdict row may be written for an unaddressable message")
	require.Len(t, pub.records, 0, "nothing may be published for an unaddressable message")
}

func TestHandle_DegradesWhenRulesUnavailable(t *testing.T) {
	t.Parallel()
	writer := &fakeWriter{out: persist.Output{CampaignID: 17, VerdictID: 44, EmailCount: 1}}
	pub := &fakePublisher{}
	eng := New(
		Config{PublishRetryAttempts: 2},
		nil, // explicit: unavailable rules cache should degrade, not panic
		fakeSimhash{},
		writer,
		pub,
		nil,
		zerolog.Nop(),
	)

	err := eng.Handle(context.Background(), makeScoredMessage(t, 1001, "e1001"))
	require.NoError(t, err)
	require.Equal(t, 1, writer.writes)
	require.Equal(t, VerdictSourceRule, writer.lastInput.VerdictSource)
	require.Len(t, pub.records, 1)
	require.Equal(t, 2, pub.records[0].retries)
}

// TestHandle_MalwareBandConfidenceNotCollapsedByReconcile drives the MAIN
// (Handle) path with an ML-driven, attachment-absent component set that lands
// in the malware band (76–100) and reconciles to phishing(high). It asserts
// the persisted+published verdict label is phishing AND the confidence is the
// score's NATURAL malware-band value — not the collapsed 51–75-band value the
// confidence trap would produce. Guards the main-path verdictLabelAndConfidence call.
func TestHandle_MalwareBandConfidenceNotCollapsedByReconcile(t *testing.T) {
	t.Parallel()
	writer := &fakeWriter{out: persist.Output{CampaignID: 17, VerdictID: 44, EmailCount: 1}}
	pub := &fakePublisher{}
	eng := New(
		Config{},
		fakeRules{}, // available, fires nothing → main path, no rule adjustment
		fakeSimhash{},
		writer,
		pub,
		nil,
		zerolog.Nop(),
	)

	// Header=NLP=90, no attachment → blend 90, source=model, reconcile=phishing(high).
	comps := Components{Header: ptrInt(90), NLP: ptrInt(90)}
	msg := makeScoredMessageWith(t, 5001, "e5001", comps)

	err := eng.Handle(context.Background(), msg)
	require.NoError(t, err)
	require.Equal(t, 1, writer.writes)

	const finalScore = 90
	require.Equal(t, finalScore, writer.lastInput.RiskScore, "ML-only blend must land in malware band")
	require.Equal(t, string(LabelPhishing), writer.lastInput.Label, "URL/header/NLP-driven high score reconciles to phishing(high)")

	natural := Confidence(finalScore, LabelFor(finalScore), false, VerdictSourceModel)
	collapsed := Confidence(finalScore, LabelPhishing, false, VerdictSourceModel)
	// Pin the literal value, not just the wiring: malware band [76,100], score
	// 90 → min(90-76,100-90)/25 = 10/25 = 0.4 (model source, no partial penalty).
	require.InDelta(t, 0.4, natural, 1e-9, "natural malware-band confidence for score 90 (model)")
	require.InDelta(t, 0.0, collapsed, 1e-9, "phishing band [51,75] is below 90 → distance clamps to 0")
	require.NotEqual(t, natural, collapsed, "test precondition: the two bands must differ")
	require.Equal(t, natural, writer.lastInput.Confidence,
		"confidence must use the score's natural malware band, not the reconciled phishing band")
	require.NotEqual(t, collapsed, writer.lastInput.Confidence,
		"confidence trap: reconcile to phishing must NOT collapse confidence to the 51-75 band")

	// The published wire verdict must carry the same decoupled values.
	require.Len(t, pub.records, 1)
	var v contracts.EmailsVerdict
	require.NoError(t, json.Unmarshal(pub.records[0].value, &v))
	require.Equal(t, string(LabelPhishing), v.VerdictLabel)
	require.Equal(t, natural, v.Confidence)
}

// TestHandle_DegradedMalwareBandConfidenceNotCollapsed drives the DEGRADED
// (publishDegraded) path with a high-band score that carries a malware-grade
// attachment, so it reconciles to MALWARE. It pins the degraded path's
// reconcile + rule-scaled confidence. NOTE: because the reconciled label here
// equals LabelFor(90), this case alone does NOT exercise the confidence trap on
// the degraded path (threading the reconciled label would be a no-op) — the
// phishing branch is covered by TestHandle_DegradedPhishingHighConfidenceNotCollapsed.
func TestHandle_DegradedMalwareBandConfidenceNotCollapsed(t *testing.T) {
	t.Parallel()
	writer := &fakeWriter{out: persist.Output{CampaignID: 17, VerdictID: 44, EmailCount: 1}}
	pub := &fakePublisher{}
	eng := New(
		Config{},
		nil, // unavailable rules cache → degraded path
		fakeSimhash{},
		writer,
		pub,
		nil,
		zerolog.Nop(),
	)

	// Attachment=URL=90 → blend 90. A malware-grade attachment (≥76) is present,
	// so the top band reconciles to malware; the other components are not
	// compared, only checked for the attachment floor.
	comps := Components{Attachment: ptrInt(90), URL: ptrInt(90)}
	msg := makeScoredMessageWith(t, 6001, "e6001", comps)

	err := eng.Handle(context.Background(), msg)
	require.NoError(t, err)
	require.Equal(t, 1, writer.writes)
	require.Equal(t, VerdictSourceRule, writer.lastInput.VerdictSource, "degraded path is rule-sourced")

	const finalScore = 90
	require.Equal(t, finalScore, writer.lastInput.RiskScore)
	require.Equal(t, string(LabelMalware), writer.lastInput.Label, "attachment-dominant high score reconciles to malware")

	natural := Confidence(finalScore, LabelFor(finalScore), false, VerdictSourceRule)
	collapsed := Confidence(finalScore, LabelPhishing, false, VerdictSourceRule)
	// Literal value: malware band [76,100], score 90 → 10/25 = 0.4, scaled by
	// the rule-source 0.5 factor = 0.2.
	require.InDelta(t, 0.2, natural, 1e-9, "natural malware-band confidence ×0.5 rule scaling for score 90")
	require.NotEqual(t, natural, collapsed, "test precondition: the two bands must differ")
	require.Equal(t, natural, writer.lastInput.Confidence,
		"degraded path confidence must use the natural malware band (rule-scaled), not the phishing band")

	require.Len(t, pub.records, 1)
	var v contracts.EmailsVerdict
	require.NoError(t, json.Unmarshal(pub.records[0].value, &v))
	require.Equal(t, string(LabelMalware), v.VerdictLabel)
	require.Equal(t, natural, v.Confidence)
}

// TestHandle_DegradedPhishingHighConfidenceNotCollapsed drives the DEGRADED
// (publishDegraded) path with a high-band score and NO malware-grade attachment,
// so it reconciles to phishing(high). THIS is the case that exercises the
// confidence trap on the degraded path: the reconciled label (phishing) differs
// from LabelFor(90) (malware), so threading the reconciled label into Confidence
// would collapse the value to 0. The malware-case test above can't catch that
// regression (its reconciled label equals LabelFor). Guards engine.go's
// publishDegraded verdictLabelAndConfidence call.
func TestHandle_DegradedPhishingHighConfidenceNotCollapsed(t *testing.T) {
	t.Parallel()
	writer := &fakeWriter{out: persist.Output{CampaignID: 17, VerdictID: 44, EmailCount: 1}}
	pub := &fakePublisher{}
	eng := New(
		Config{},
		nil, // unavailable rules cache → degraded path
		fakeSimhash{},
		writer,
		pub,
		nil,
		zerolog.Nop(),
	)

	// Header=NLP=90, no attachment → blend 90, high band, no malware-grade
	// attachment → reconciles to phishing(high). Degraded path forces source=rule.
	comps := Components{Header: ptrInt(90), NLP: ptrInt(90)}
	msg := makeScoredMessageWith(t, 6002, "e6002", comps)

	err := eng.Handle(context.Background(), msg)
	require.NoError(t, err)
	require.Equal(t, 1, writer.writes)
	require.Equal(t, VerdictSourceRule, writer.lastInput.VerdictSource, "degraded path is rule-sourced")

	const finalScore = 90
	require.Equal(t, finalScore, writer.lastInput.RiskScore)
	require.Equal(t, string(LabelPhishing), writer.lastInput.Label,
		"high score with no malware-grade attachment reconciles to phishing(high)")

	natural := Confidence(finalScore, LabelFor(finalScore), false, VerdictSourceRule)
	collapsed := Confidence(finalScore, LabelPhishing, false, VerdictSourceRule)
	// Literal value: malware band [76,100], score 90 → 10/25 = 0.4, ×0.5 rule = 0.2.
	// The collapsed (buggy) value uses the reconciled phishing band [51,75], where
	// 90 is out of range → 0.
	require.InDelta(t, 0.2, natural, 1e-9, "natural malware-band confidence ×0.5 rule scaling")
	require.InDelta(t, 0.0, collapsed, 1e-9, "phishing-band distance for score 90 clamps to 0")
	require.NotEqual(t, natural, collapsed, "test precondition: the two bands must differ")
	require.Equal(t, natural, writer.lastInput.Confidence,
		"CONFIDENCE TRAP (degraded path): phishing-reconciled label must NOT collapse confidence")

	require.Len(t, pub.records, 1)
	var v contracts.EmailsVerdict
	require.NoError(t, json.Unmarshal(pub.records[0].value, &v))
	require.Equal(t, string(LabelPhishing), v.VerdictLabel)
	require.Equal(t, natural, v.Confidence)
}

func TestHandle_UsesStoredKafkaWireOnDedupeReplay(t *testing.T) {
	t.Parallel()
	stored := []byte(`{"verdict_label":"benign","risk_score":11}`)
	writer := &fakeWriter{out: persist.Output{
		DedupeSkip:       true,
		CampaignID:       17,
		VerdictID:        44,
		EmailCount:       3,
		KafkaVerdictWire: stored,
	}}
	pub := &fakePublisher{}
	eng := New(
		Config{},
		fakeRules{err: errors.New("cache unavailable")},
		fakeSimhash{},
		writer,
		pub,
		nil,
		zerolog.Nop(),
	)

	err := eng.Handle(context.Background(), makeScoredMessage(t, 3001, "e3001"))
	require.NoError(t, err)
	require.Len(t, pub.records, 1)
	require.JSONEq(t, string(stored), string(pub.records[0].value))
}

// TestHandle_FusionShadow drives an input where weighted_average (active, default)
// and noisy_or (shadow) land in different verdict bands — NLP=40,Header=40 blends
// to 40 (suspicious) under the weighted mean but 64 (phishing) under the OR. It
// asserts (a) shadow OFF records nothing, and (b) shadow ON records exactly one
// disagreement labelled by the two reconciled verdict labels.
func TestHandle_FusionShadow(t *testing.T) {
	t.Parallel()
	comps := Components{NLP: ptrInt(40), Header: ptrInt(40)}

	// (a) shadow disabled (default): the second blend never runs, nothing recorded.
	regOff := prometheus.NewRegistry()
	mOff := metrics.New(regOff)
	engOff := New(Config{}, fakeRules{}, fakeSimhash{},
		&fakeWriter{out: persist.Output{CampaignID: 1, VerdictID: 1, EmailCount: 1}},
		&fakePublisher{}, mOff, zerolog.Nop())
	require.NoError(t, engOff.Handle(context.Background(), makeScoredMessageWith(t, 7001, "e7001", comps)))
	require.Equal(t, 0, testutil.CollectAndCount(mOff.FusionShadowDisagree),
		"shadow disabled by default → no disagreement series")

	// (b) shadow enabled: weighted (active) = suspicious, noisy_or (shadow) = phishing.
	regOn := prometheus.NewRegistry()
	mOn := metrics.New(regOn)
	engOn := New(Config{FusionShadow: true}, fakeRules{}, fakeSimhash{},
		&fakeWriter{out: persist.Output{CampaignID: 1, VerdictID: 1, EmailCount: 1}},
		&fakePublisher{}, mOn, zerolog.Nop())
	require.NoError(t, engOn.Handle(context.Background(), makeScoredMessageWith(t, 7002, "e7002", comps)))
	require.InDelta(t, 1.0,
		testutil.ToFloat64(mOn.FusionShadowDisagree.WithLabelValues(string(LabelSuspicious), string(LabelPhishing))),
		1e-9, "shadow enabled → one disagreement: active suspicious vs shadow phishing")

	// (c) degraded path (rules cache unavailable) still records shadow disagreement,
	// so the calibration sample is not biased toward healthy traffic.
	regDeg := prometheus.NewRegistry()
	mDeg := metrics.New(regDeg)
	engDeg := New(Config{FusionShadow: true}, nil, fakeSimhash{}, // nil rules cache → degraded path
		&fakeWriter{out: persist.Output{CampaignID: 1, VerdictID: 1, EmailCount: 1}},
		&fakePublisher{}, mDeg, zerolog.Nop())
	require.NoError(t, engDeg.Handle(context.Background(), makeScoredMessageWith(t, 7003, "e7003", comps)))
	require.InDelta(t, 1.0,
		testutil.ToFloat64(mDeg.FusionShadowDisagree.WithLabelValues(string(LabelSuspicious), string(LabelPhishing))),
		1e-9, "degraded path with shadow on → disagreement still recorded")
}

// TestHandle_FusionShadow_RulesReEvaluated proves the shadow runs rules against
// its OWN pre-rule band, not the active path's adjustment. Input NLP=20,Header=20:
// weighted blends to 20 (benign, rule below keyed on band==suspicious does NOT fire
// → active stays benign), but noisy_or blends to 36 (suspicious, the rule FIRES
// +20 → 56 → phishing). If the shadow merely reused the active adjustment (0) it
// would record (benign, suspicious); recording (benign, phishing) proves the rule
// was re-evaluated against the shadow's higher band.
func TestHandle_FusionShadow_RulesReEvaluated(t *testing.T) {
	t.Parallel()
	rule := rules.CachedRule{
		ID:          1,
		Name:        "escalate-suspicious",
		ScoreImpact: 20,
		Logic:       json.RawMessage(`{"signal":"verdict.label","op":"eq","value":"suspicious"}`),
	}
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	eng := New(Config{FusionShadow: true}, fakeRules{rules: []rules.CachedRule{rule}}, fakeSimhash{},
		&fakeWriter{out: persist.Output{CampaignID: 1, VerdictID: 1, EmailCount: 1}},
		&fakePublisher{}, m, zerolog.Nop())

	comps := Components{NLP: ptrInt(20), Header: ptrInt(20)}
	require.NoError(t, eng.Handle(context.Background(), makeScoredMessageWith(t, 7004, "e7004", comps)))

	require.InDelta(t, 1.0,
		testutil.ToFloat64(m.FusionShadowDisagree.WithLabelValues(string(LabelBenign), string(LabelPhishing))),
		1e-9, "shadow must re-evaluate rules against its own band → (benign, phishing), not (benign, suspicious)")
	require.InDelta(t, 0.0,
		testutil.ToFloat64(m.FusionShadowDisagree.WithLabelValues(string(LabelBenign), string(LabelSuspicious))),
		1e-9, "the no-re-eval label pair must NOT be recorded")
}
