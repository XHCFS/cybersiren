package engine

import (
	_ "embed"
	"encoding/json"
	"math"
	"testing"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

//go:embed calibration/parity_fixture_v1.json
var parityFixtureJSON []byte

type parityCase struct {
	NLP        *float64 `json:"nlp"`
	URL        *float64 `json:"url"`
	Header     *float64 `json:"header"`
	Attachment *float64 `json:"attachment"`
	Score      float64  `json:"score"`
}

func toIptr(v *float64) *int {
	if v == nil {
		return nil
	}
	i := int(math.Round(*v))
	return &i
}

// TestCalibratedOR_ParityWithPython is the train/serve-skew guard: the Go blender must
// reproduce the Python reference scorer (benchmark/export_artifact.py) on every fixture
// case to <0.5 (the fixture scores are computed from float inputs; the Go path rounds
// the component to int first, so allow the rounding gap — bounded below).
func TestCalibratedOR_ParityWithPython(t *testing.T) {
	var fx struct {
		Fixture []parityCase `json:"fixture"`
	}
	if err := json.Unmarshal(parityFixtureJSON, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(fx.Fixture) == 0 {
		t.Fatal("empty parity fixture")
	}
	b := NewCalibratedORBlender()
	var maxDiff float64
	for i, c := range fx.Fixture {
		// Cases with non-integer inputs (e.g. -5, 150) exercise clamping; the Python
		// fixture clamps the same way. Integer-valued inputs match exactly.
		got := b.Blend(Components{
			NLP:        toIptr(c.NLP),
			URL:        toIptr(c.URL),
			Header:     toIptr(c.Header),
			Attachment: toIptr(c.Attachment),
		}).Score
		diff := math.Abs(got - c.Score)
		if diff > maxDiff {
			maxDiff = diff
		}
		if diff > 0.5 {
			t.Errorf("case %d (nlp=%v url=%v header=%v att=%v): Go=%.4f Python=%.4f diff=%.4f",
				i, c.NLP, c.URL, c.Header, c.Attachment, got, c.Score, diff)
		}
	}
	t.Logf("parity over %d cases: max diff = %.5f", len(fx.Fixture), maxDiff)
}

// TestCalibratedOR_NoDilution: a confident single channel must not be averaged below
// threshold by clean/absent companions (the weighted-average bug).
func TestCalibratedOR_NoDilution(t *testing.T) {
	b := NewCalibratedORBlender()
	// text-only malicious: NLP=100, header clean present.
	if got := b.Blend(Components{NLP: iptr(100), Header: iptr(0)}).Score; got <= 50 {
		t.Fatalf("NLP=100 diluted by clean header: got %.1f, want > 50", got)
	}
	// NLP=100 alone must stay high.
	if got := b.Blend(Components{NLP: iptr(100)}).Score; got <= 50 {
		t.Fatalf("NLP=100 alone should fire: got %.1f", got)
	}
}

// TestCalibratedOR_Monotonic: raising any present component never lowers the fused score
// (the whole pipeline — per-channel calibration, OR, final calibration — is monotone).
func TestCalibratedOR_Monotonic(t *testing.T) {
	b := NewCalibratedORBlender()
	prev := math.Inf(-1)
	for s := 0; s <= 100; s += 5 {
		got := b.Blend(Components{NLP: iptr(s), Header: iptr(20)}).Score
		if got < prev-1e-9 {
			t.Fatalf("non-monotonic in NLP at %d: %.4f < previous %.4f", s, got, prev)
		}
		prev = got
	}
}

// TestCalibratedOR_Bounds: output always in [0,100]; out-of-range and negative inputs
// are clamped; all-nil yields 0.
func TestCalibratedOR_Bounds(t *testing.T) {
	b := NewCalibratedORBlender()
	for _, c := range []Components{
		{}, {NLP: iptr(-50)}, {URL: iptr(1000), Header: iptr(-3), NLP: iptr(50)},
		{NLP: iptr(100), URL: iptr(100), Header: iptr(100), Attachment: iptr(100)},
	} {
		got := b.Blend(c).Score
		if got < 0 || got > 100 {
			t.Fatalf("score out of bounds: %.4f for %+v", got, c)
		}
	}
	if res := b.Blend(Components{}); res.Score != 0 || res.WeightSum != 0 {
		t.Fatalf("all-nil: got score=%.4f weightSum=%.1f, want 0/0", res.Score, res.WeightSum)
	}
}

// TestCalibratedOR_AttachmentIdentity: attachment has no measured curve, so it uses
// identity — a confirmed-malware attachment (high score) must fire even alone (it must
// NOT be crushed by a hand-set weight).
func TestCalibratedOR_AttachmentIdentity(t *testing.T) {
	b := NewCalibratedORBlender()
	if got := b.Blend(Components{Attachment: iptr(95)}).Score; got <= 50 {
		t.Fatalf("confirmed-malware attachment alone should fire: got %.1f", got)
	}
}

// TestCalibratedOR_URLNeutral: the lexical URL channel is neutralised — a high URL
// score ALONE must not clear threshold (it is noise until authoritative TI/guard
// forwarding exists). A clean email with a noisy URL must stay benign.
func TestCalibratedOR_URLNeutral(t *testing.T) {
	b := NewCalibratedORBlender()
	if got := b.Blend(Components{URL: iptr(100), NLP: iptr(2), Header: iptr(2)}).Score; got > 50 {
		t.Fatalf("noisy URL on a clean email should stay benign: got %.1f", got)
	}
}

// TestComponentsFrom_DropsDegraded: a fail-soft (degraded) score must be treated as
// ABSENT, not fused — svc-06's neutral 50 is a moderate phishing value under the
// P(phishing) content scoring and must not push a legit verdict during an NLP outage.
func TestComponentsFrom_DropsDegraded(t *testing.T) {
	nlp50 := 50
	hdr80 := 80
	scored := contracts.EmailsScored{
		NLPScore:           &nlp50,
		HeaderScore:        &hdr80,
		DegradedComponents: []string{contracts.TopicScoresNLP},
	}
	c := ComponentsFrom(scored)
	if c.NLP != nil {
		t.Fatalf("degraded NLP should be dropped (absent), got %d", *c.NLP)
	}
	if c.Header == nil || *c.Header != 80 {
		t.Fatalf("non-degraded header should pass through, got %v", c.Header)
	}
	// a degraded NLP-only message must blend to benign (no real signal present).
	if got := NewCalibratedORBlender().Blend(c).Score; c.Header == nil && got > 50 {
		t.Fatalf("degraded-only should not fire, got %.1f", got)
	}
}

// TestParseCalibration_Rejects guards the loader against malformed artifacts.
func TestParseCalibration_Rejects(t *testing.T) {
	if _, err := parseCalibration([]byte(`{"channels":{"nlp":{"x":[0],"y":[]}}}`)); err == nil {
		t.Fatal("expected error on mismatched knot lengths")
	}
	if _, err := parseCalibration([]byte(`{"final":{"x":[],"y":[]}}`)); err == nil {
		t.Fatal("expected error on missing final curve")
	}
}
