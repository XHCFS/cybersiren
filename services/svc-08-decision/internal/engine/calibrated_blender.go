package engine

// Calibrated probabilistic-OR blender — the production fusion (design brief §3.4).
//
// Each present component's raw 0–100 score is mapped through a per-channel calibration
// curve to a phishing/maliciousness probability p_c = calib_c(score_c); the channels
// are combined with a probabilistic-OR and the fused raw score is passed through a
// final calibration curve so the output is a true P(malicious)·100:
//
//	raw  = 100 · ( 1 − Π_present (1 − clip(calib_c(score_c), 0, cap)) )
//	risk = 100 · final(raw)
//
// Why this, established on the consistent real-model base (benchmark/FINDINGS.md):
//   - No dilution. A clean channel calibrates low and contributes a factor ≈ 1, so a
//     single confident channel is never averaged below threshold (the weighted-average
//     bug that dropped recall@1%FPR to 58% — below NLP alone at 72%).
//   - Reliability is LEARNED, not hand-set. The curves come from each channel's measured
//     P(malicious|score); the noisy lexical-URL channel calibrates to ~0 automatically
//     (no magic 0.22). Raw OR without calibration scores 29% — calibration is essential.
//   - Calibrated output. The final curve makes risk a real probability, so the §3.6
//     verdict bands stay meaningful (ECE ≈ 0.005).
//
// Channels with no measured curve fall back to identity (p = score/100), preserving a
// confident signal (e.g. a confirmed-malware attachment) without inventing a weight.
//
// URL note: the lexical/L2 URL score is NOT trusted here (it is noise on offline data
// and unmeasurable without live enrichment). URL re-enters as an authoritative channel
// (TI / domain-guard → reliability ≈ 1.0) once SVC-03 forwards guard_hit/ti_matched.

// CalibratedORBlender implements Blender with the calibrated probabilistic-OR above.
type CalibratedORBlender struct {
	cal Calibration
}

// NewCalibratedORBlender builds the blender from the embedded calibration artifact.
func NewCalibratedORBlender() *CalibratedORBlender {
	return &CalibratedORBlender{cal: loadEmbeddedCalibration()}
}

// channelProb maps a present component score to its calibrated probability, clamped
// to [0, cap]. A channel absent from the artifact uses identity (score/100).
func (b *CalibratedORBlender) channelProb(name string, score int) float64 {
	s := float64(score)
	if s < 0 {
		s = 0
	} else if s > 100 {
		s = 100
	}
	var p float64
	if ch, ok := b.cal.Channels[name]; ok {
		p = ch.curve().predict(s)
	} else {
		p = s / 100.0 // identity fallback for an uncalibrated channel
	}
	if p < 0 {
		p = 0
	}
	if p > b.cal.Cap {
		p = b.cal.Cap
	}
	return p
}

// Blend implements Blender.
func (b *CalibratedORBlender) Blend(c Components) BlendResult {
	contributions := make(map[string]float64, 4)
	pNot := 1.0
	present := 0

	fold := func(name string, score *int) {
		if score == nil {
			return
		}
		p := b.channelProb(name, *score)
		contributions[name] = p
		pNot *= (1 - p)
		present++
	}
	fold("url", c.URL)
	fold("header", c.Header)
	fold("nlp", c.NLP)
	fold("attachment", c.Attachment)

	if present == 0 {
		return BlendResult{Score: 0, Contributions: contributions, WeightSum: 0}
	}

	raw := (1 - pNot) * 100
	score := b.cal.Final.predict(raw) * 100
	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}
	return BlendResult{
		Score:         score,
		Contributions: contributions,
		WeightSum:     float64(present),
	}
}
