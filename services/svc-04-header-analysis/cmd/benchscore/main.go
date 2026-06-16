// Command realheader runs the REAL svc-04 header-analysis scoring code over the
// benchmark records (no Kafka/DB) and emits id,header_score so the fusion analysis
// uses true service output instead of a Python proxy.
//
//	stdin : benchmark/_header_inputs.jsonl   (one {id, present, msg} per line)
//	rules : benchmark/_header_rules.json     (the seeded svc-04 rules)
//	stdout: CSV  id,header_score   (header_score empty when the channel is absent)
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/header"
	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/rules"
	contractsk "github.com/saif/cybersiren/shared/contracts/kafka"
	dsl "github.com/saif/cybersiren/shared/rules/dsl"
)

type inputRec struct {
	ID      string                            `json:"id"`
	Present bool                              `json:"present"`
	Msg     contractsk.AnalysisHeadersMessage `json:"msg"`
}

func main() {
	rulesBytes, err := os.ReadFile("benchmark/_header_rules.json")
	if err != nil {
		panic(err)
	}
	var ruleset []dsl.CachedRule
	if err := json.Unmarshal(rulesBytes, &ruleset); err != nil {
		panic(err)
	}

	log := zerolog.New(os.Stderr).Level(zerolog.Disabled)
	rep := header.NewReputationExtractor(nil /*no TI*/, 2 /*typosquat max dist*/, log)
	eval := rules.NewEvaluator(log)
	const hopThresh, driftThresh = 15, 24.0

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	fmt.Fprintln(out, "id,header_score")

	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		var rec inputRec
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			panic(err)
		}
		if !rec.Present {
			fmt.Fprintf(out, "%s,\n", rec.ID)
			continue
		}
		msg := rec.Msg
		signals := header.HeaderSignals{
			Auth:       header.ExtractAuth(&msg),
			Reputation: rep.Extract(context.TODO(), &msg),
			Structural: header.ExtractStructural(&msg, header.StructuralExtractorConfig{
				HopCountThreshold:       hopThresh,
				TimeDriftHoursThreshold: driftThresh,
			}),
			Source: &msg,
		}
		snap := rules.SignalsToSnapshot(signals)
		res := eval.Evaluate(ruleset, snap)
		score := rules.FinalScore(res.AuthSubScore, res.ReputationSubScore, res.StructuralSubScore, "max")
		fmt.Fprintf(out, "%s,%d\n", rec.ID, score)
	}
	if err := sc.Err(); err != nil {
		panic(err)
	}
}
