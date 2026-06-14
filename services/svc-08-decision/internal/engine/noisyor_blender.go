package engine

// Reliability-weighted noisy-OR blender.
//
// The v1 WeightedAverageBlender cannot, by construction, catch both a text-only
// threat and a header-only threat: a weighted average dilutes a confident channel
// with the clean ones (a strong NLP=100 averaged against a clean header=0 falls
// below threshold). See docs/design/svc-07-08-design-brief.md §3.4.
//
// This blender combines present components with a reliability-weighted noisy-OR:
//
//	risk = 100 · ( 1 − Π_present ( 1 − reliability_c · score_c/100 ) )
//
// Properties (why this is the reliable, generalizable choice):
//   - A clean channel contributes a factor ≈ 1, i.e. NOTHING — it never dilutes a
//     confident channel (no averaging-dilution).
//   - Each channel can independently raise the alarm (text-only BEC, header-only
//     spoof are both caught).
//   - Monotonic: a higher component score never lowers the risk.
//   - Per-channel RELIABILITY (set from each channel's measured precision)
//     down-weights an unreliable channel. The lexical URL score is unreliable
//     (legit links score high), so URL is heavily down-weighted: "URL alone"
//     defers to SVC-03 (allowlist + operational model) instead of false-positiving
//     on legitimate links. Raise URL reliability once SVC-03's full stack runs.
//
// It is pure arithmetic — no model artifact, no sidecar, no network call.

// Reliabilities are the per-channel trust weights for the noisy-OR fusion. Each is
// in [0, 1] and scales how much a component's 0–100 score may raise the fused risk.
type Reliabilities struct {
	URL        float64
	Header     float64
	NLP        float64
	Attachment float64
}

// DefaultReliabilities returns the trust weights derived from each channel's
// measured precision on the fusion benchmark (CS-E2E-Bench): NLP is the strongest
// signal, header moderate, attachment fairly specific when it fires, and the
// lexical-only URL score is deliberately down-weighted.
func DefaultReliabilities() Reliabilities {
	return Reliabilities{
		NLP:        1.00,
		Header:     0.78,
		Attachment: 0.60,
		URL:        0.22,
	}
}

// ReliabilityNoisyORBlender implements Blender with the reliability-weighted
// noisy-OR above.
type ReliabilityNoisyORBlender struct {
	R Reliabilities
}

// NewReliabilityNoisyORBlender constructs the blender. A reliability set that is
// non-positive across all channels is replaced with DefaultReliabilities so a
// misconfiguration can never produce an all-zero (always-benign) blender.
func NewReliabilityNoisyORBlender(r Reliabilities) *ReliabilityNoisyORBlender {
	if r.URL+r.Header+r.NLP+r.Attachment <= 0 {
		r = DefaultReliabilities()
	}
	return &ReliabilityNoisyORBlender{R: r}
}

// Blend implements Blender.
func (b *ReliabilityNoisyORBlender) Blend(c Components) BlendResult {
	contributions := make(map[string]float64, 4)
	pNot := 1.0
	var relSum float64

	// accumulate folds one present component into the noisy-OR product and records
	// its phishing-probability contribution (reliability × normalised score).
	accumulate := func(name string, score *int, rel float64) {
		if score == nil || rel <= 0 {
			return
		}
		s := float64(*score)
		if s < 0 {
			s = 0
		} else if s > 100 {
			s = 100
		}
		p := rel * (s / 100.0)
		if p > 0.999 { // guard against a single channel pinning the product to 1
			p = 0.999
		}
		pNot *= (1 - p)
		relSum += rel
		contributions[name] = p
	}

	accumulate("url", c.URL, b.R.URL)
	accumulate("header", c.Header, b.R.Header)
	accumulate("nlp", c.NLP, b.R.NLP)
	accumulate("attachment", c.Attachment, b.R.Attachment)

	if relSum <= 0 {
		return BlendResult{Score: 0, Contributions: contributions, WeightSum: 0}
	}

	score := (1 - pNot) * 100
	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}
	return BlendResult{
		Score:         score,
		Contributions: contributions,
		WeightSum:     relSum,
	}
}
