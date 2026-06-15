package engine

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// fusionCalibrationJSON is the versioned per-channel calibration artifact produced
// by benchmark/export_artifact.py from the consistent real-model base. It maps each
// channel's raw 0–100 score to a calibrated P(malicious) and a final raw→P curve.
// See docs/design/svc-07-08-design-brief.md §3.4 and benchmark/FINDINGS.md.
//
//go:embed calibration/fusion_calibration_v1.json
var fusionCalibrationJSON []byte

// pieceWiseLinear is a monotone calibration curve stored as (x, y) knots. Predict
// does np.interp-style linear interpolation, clamping outside [x0, xN] to y0 / yN —
// byte-for-byte matching the Python reference (benchmark/export_artifact.py:interp).
type pieceWiseLinear struct {
	X []float64 `json:"x"`
	Y []float64 `json:"y"`
}

func (c pieceWiseLinear) predict(x float64) float64 {
	n := len(c.X)
	if n == 0 {
		return 0
	}
	if x <= c.X[0] {
		return c.Y[0]
	}
	if x >= c.X[n-1] {
		return c.Y[n-1]
	}
	for i := 1; i < n; i++ {
		if x <= c.X[i] {
			dx := c.X[i] - c.X[i-1]
			if dx == 0 {
				return c.Y[i]
			}
			t := (x - c.X[i-1]) / dx
			return c.Y[i-1] + t*(c.Y[i]-c.Y[i-1])
		}
	}
	return c.Y[n-1]
}

// channelCalibration is one channel's curve plus its kind (isotonic / neutral /
// identity) — kind is informational; predict() is the same interpolation for all.
type channelCalibration struct {
	Kind string    `json:"kind"`
	X    []float64 `json:"x"`
	Y    []float64 `json:"y"`
}

func (c channelCalibration) curve() pieceWiseLinear { return pieceWiseLinear{X: c.X, Y: c.Y} }

// Calibration is the parsed fusion-calibration artifact.
type Calibration struct {
	Version  string                        `json:"version"`
	Cap      float64                       `json:"cap"`
	Final    pieceWiseLinear               `json:"final"`
	Channels map[string]channelCalibration `json:"channels"`
}

// loadEmbeddedCalibration parses the embedded artifact. It panics on a malformed
// artifact because the binary cannot run a calibrated fusion without it — this is a
// build-time asset, so a parse failure is a programming error, not runtime input.
func loadEmbeddedCalibration() Calibration {
	c, err := parseCalibration(fusionCalibrationJSON)
	if err != nil {
		panic(fmt.Sprintf("svc-08: embedded fusion calibration is invalid: %v", err))
	}
	return c
}

func parseCalibration(b []byte) (Calibration, error) {
	var c Calibration
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("unmarshal calibration: %w", err)
	}
	if c.Cap <= 0 || c.Cap >= 1 {
		c.Cap = 0.999
	}
	if len(c.Final.X) == 0 {
		return c, fmt.Errorf("calibration: missing final curve")
	}
	for name, ch := range c.Channels {
		if len(ch.X) != len(ch.Y) || len(ch.X) == 0 {
			return c, fmt.Errorf("calibration: channel %q has malformed knots", name)
		}
	}
	return c, nil
}
