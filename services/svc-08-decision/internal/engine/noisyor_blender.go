package engine

import "math"

// Probabilistic-OR (noisy-OR) blender.
//
// The v1 WeightedAverageBlender *dilutes* a confident channel: a strong single
// signal is averaged down by the clean channels. This under-rates a CONFIRMED
// single-channel threat — a URL that SVC-03 pinned to 100 (TI/blocklist hit,
// brand-in-subdomain guard, or L2 fusion verdict) blended against clean text and
// header scores only `0.25·100/(0.25+0.30+0.35) ≈ 28–41` → "suspicious", not
// "malware". The same happens to a confirmed-malware attachment (SVC-05 pins it
// high). See docs/design/svc-07-08-design-brief.md §3.4.
//
// This blender combines present components with a probabilistic OR:
//
//	risk = 100 · ( 1 − Π_present ( 1 − reliability_c · score_c/100 ) )
//
// Key properties:
//   - OR-FLOOR: risk ≥ 100·maxₑ(reliability_c·score_c/100). With the default
//     reliabilities of 1.0 this is risk ≥ maxₑ score_c, so a channel SVC-03/05
//     pinned to 100 yields risk = 100 (malware band) regardless of the other
//     channels. Confirmed signals can never be diluted below their own score.
//   - NO DILUTION: a clean channel contributes a factor of ~1 (nothing); it never
//     lowers a confident channel.
//   - Monotone and bounded to [0,100].
//
// RELIABILITIES are per-channel trust weights in [0,1], default **1.0** for every
// channel. They default to full trust because each upstream score is already a
// FUSED / calibrated signal in its own service (the URL score is SVC-03's
// TI+guard+L2-fused verdict, not a raw lexical score; attachment is SVC-05's
// AV/TI-aware score). A reliability may be tuned *downward* by operators if a
// channel proves noisy in production, but no channel is shipped at a fabricated
// sub-1.0 default — earlier drafts down-weighted URL based on an offline
// lexical-only proxy, which incorrectly crushed the TI-confirmed production score.
//
// CAVEAT (why this is not yet the production default — see §3.4/§3.6): the OR
// assumes channels are conditionally independent. Real channels are correlated, so
// correlated evidence is combined optimistically and the score distribution sits
// 1–2 bands higher than the weighted mean. The §3.6 verdict bands and rule
// `score_impact` values were tuned to the weighted-mean distribution and must be
// recalibrated before this becomes the default. Until then it is opt-in
// (`CYBERSIREN_DECISION__FUSION_MODE=noisy_or`) and runs in shadow for comparison.
//
// It is pure arithmetic — no model artifact, no sidecar, no network call.

// Reliabilities are the per-channel trust weights for the probabilistic-OR fusion.
// Each is in [0, 1] and scales how much a component's 0–100 score may raise the
// fused risk.
type Reliabilities struct {
	URL        float64
	Header     float64
	NLP        float64
	Attachment float64
}

// DefaultReliabilities returns full trust (1.0) for every channel: each upstream
// score is already a fused/calibrated signal, so the blender does not second-guess
// it. Operators may lower a value if a channel proves noisy; none is shipped at a
// fabricated sub-1.0 default.
func DefaultReliabilities() Reliabilities {
	return Reliabilities{URL: 1.0, Header: 1.0, NLP: 1.0, Attachment: 1.0}
}

// ReliabilityNoisyORBlender implements Blender with the probabilistic OR above.
type ReliabilityNoisyORBlender struct {
	R Reliabilities
}

// NewReliabilityNoisyORBlender constructs the blender. Each reliability is
// clamped to its [0,1] contract (so an operator-supplied >1 value can never push
// a per-channel probability past 1), and a reliability set that is non-positive
// across all channels is replaced with DefaultReliabilities so a misconfiguration
// can never produce an all-zero (always-benign) blender.
func NewReliabilityNoisyORBlender(r Reliabilities) *ReliabilityNoisyORBlender {
	if r.URL+r.Header+r.NLP+r.Attachment <= 0 {
		r = DefaultReliabilities()
	}
	r.URL = clampUnit(r.URL)
	r.Header = clampUnit(r.Header)
	r.NLP = clampUnit(r.NLP)
	r.Attachment = clampUnit(r.Attachment)
	return &ReliabilityNoisyORBlender{R: r}
}

// clampUnit clamps a reliability to its [0,1] contract. NaN (which compares false
// to both bounds) maps to 0 so a non-finite value can never poison the OR product.
func clampUnit(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// Blend implements Blender.
func (b *ReliabilityNoisyORBlender) Blend(c Components) BlendResult {
	contributions := make(map[string]float64, 4)
	pNot := 1.0
	var relSum float64

	// accumulate folds one present component into the OR product and records its
	// phishing-probability contribution (reliability × normalised score).
	accumulate := func(name string, score *int, rel float64) {
		if score == nil || rel <= 0 {
			return
		}
		s := clampScore(float64(*score))
		// rel ∈ [0,1] (clamped in the constructor) and s/100 ∈ [0,1], so p ∈ [0,1].
		p := rel * (s / 100.0)
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

	score := clampScore((1 - pNot) * 100)
	// WeightSum carries Σ reliability over present components (analogous to the
	// weighted blender's Σ weight — used only for downstream introspection).
	return BlendResult{
		Score:         score,
		Contributions: contributions,
		WeightSum:     relSum,
	}
}
