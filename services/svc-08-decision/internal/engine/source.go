package engine

// VerdictSource string constants, mirroring the verdict_source enum in
// db/migrations/001_initial_schema.up.sql.
const (
	VerdictSourceModel = "model"
	VerdictSourceRule  = "rule"
)

// SourceFor selects between "model" and "rule" per design brief §3.7:
//
//   - "model" — at least one ML score (URL, header, NLP) was present.
//   - "rule"  — no ML scores at all; only the rule engine contributed.
//
// Attachment-only emails are still "rule"-sourced because attachment
// scoring is heuristic, not model-derived (svc-05's design).
func SourceFor(c Components) string {
	if c.HasAnyML() {
		return VerdictSourceModel
	}
	return VerdictSourceRule
}
