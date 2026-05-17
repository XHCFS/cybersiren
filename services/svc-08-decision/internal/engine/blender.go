// Package engine is the core orchestration of SVC-08 Decision Engine.
// See docs/design/svc-07-08-design-brief.md §3 for the contract.
package engine

import "math"

// Components is the per-component score view passed to the Blender. A
// nil pointer means the component was not present in the upstream
// emails.scored message (partial analysis or no attachments).
type Components struct {
	URL        *int
	Header     *int
	NLP        *int
	Attachment *int
}

// HasAny reports whether any ML component score was populated. When
// false, the engine flags VerdictSource = "rule".
func (c Components) HasAny() bool {
	return c.URL != nil || c.Header != nil || c.NLP != nil || c.Attachment != nil
}

// HasAnyML reports whether at least one ML-derived component (URL,
// header, NLP) is present. Attachment alone is currently considered
// rule-driven heuristics, not ML.
func (c Components) HasAnyML() bool {
	return c.URL != nil || c.Header != nil || c.NLP != nil
}

// BlendWeights configures the relative contribution of each component.
// All weights must be non-negative; the actual sum is computed only
// over present components so a missing component never silently shifts
// the blended score downward.
type BlendWeights struct {
	URL        float64
	Header     float64
	NLP        float64
	Attachment float64
}

// DefaultWeights returns the v1 starting weights from the design brief
// (§3.4). They reflect a "URL is usually the strongest signal" prior.
func DefaultWeights() BlendWeights {
	return BlendWeights{
		URL:        0.35,
		Header:     0.30,
		NLP:        0.25,
		Attachment: 0.10,
	}
}

// BlendResult is the output of a Blender. Score is the weighted blend
// clamped to [0, 100]; Contributions records the per-component
// (weighted-fraction × score) breakdown for explainability and gets
// serialised into emails.analysis_metadata.
type BlendResult struct {
	Score         float64
	Contributions map[string]float64 // {"url": w*score/W, ...} for present components only
	WeightSum     float64            // Σ weight_c over present components (for downstream introspection)
}

// Blender combines per-component scores into a single risk_score.
// Only one implementation today (WeightedAverageBlender); the interface
// exists so a learnable meta-classifier can drop in later without
// touching the engine orchestration.
type Blender interface {
	Blend(c Components) BlendResult
}

// WeightedAverageBlender is the v1 explainable blender: weighted mean
// over present components, divided by the sum of weights of present
// components only. Missing components contribute nothing and do not
// shift the denominator.
type WeightedAverageBlender struct {
	W BlendWeights
}

// NewWeightedAverageBlender constructs a blender. Weights with sum ≤ 0
// are silently replaced with DefaultWeights so a misconfiguration never
// produces a divide-by-zero.
func NewWeightedAverageBlender(w BlendWeights) *WeightedAverageBlender {
	if w.URL+w.Header+w.NLP+w.Attachment <= 0 {
		w = DefaultWeights()
	}
	return &WeightedAverageBlender{W: w}
}

// Blend implements Blender.
func (b *WeightedAverageBlender) Blend(c Components) BlendResult {
	contributions := make(map[string]float64, 4)
	var weighted, weightSum float64

	if c.URL != nil {
		w := b.W.URL
		v := w * float64(*c.URL)
		weighted += v
		weightSum += w
		contributions["url"] = v
	}
	if c.Header != nil {
		w := b.W.Header
		v := w * float64(*c.Header)
		weighted += v
		weightSum += w
		contributions["header"] = v
	}
	if c.NLP != nil {
		w := b.W.NLP
		v := w * float64(*c.NLP)
		weighted += v
		weightSum += w
		contributions["nlp"] = v
	}
	if c.Attachment != nil {
		w := b.W.Attachment
		v := w * float64(*c.Attachment)
		weighted += v
		weightSum += w
		contributions["attachment"] = v
	}

	if weightSum <= 0 {
		return BlendResult{Score: 0, Contributions: contributions, WeightSum: 0}
	}

	score := weighted / weightSum
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	// Normalise contributions so they sum to the blended score: divide
	// each by weightSum so the sum-of-contributions equals the blended
	// score — preserving the explainability invariant in §3.4.
	for k, v := range contributions {
		contributions[k] = v / weightSum
	}
	return BlendResult{
		Score:         score,
		Contributions: contributions,
		WeightSum:     weightSum,
	}
}

// Round rounds a float to the nearest int with half-up tie-breaking.
// Exposed for callers that need to convert blended/nudged scores into
// the integer space the rest of the pipeline uses.
func Round(v float64) int {
	return int(math.Round(v))
}

// ClampInt clamps v to [lo, hi].
func ClampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
