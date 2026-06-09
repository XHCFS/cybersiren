package persist

import "testing"

// pgInt4 must map a zero value to a NULL pgtype, like its sibling helpers, so
// the COALESCE-based enriched_threats UPDATE leaves risk_score untouched. A
// Score=0 benign re-observation must NOT clobber a prior (possibly malicious)
// risk_score. Regression guard for the convert.go fix.
func TestPgInt4ZeroIsNull(t *testing.T) {
	if got := pgInt4(0); got.Valid {
		t.Errorf("pgInt4(0) = %+v, want NULL (Valid=false)", got)
	}
	if got := pgInt4(88); !got.Valid || got.Int32 != 88 {
		t.Errorf("pgInt4(88) = %+v, want {88, Valid=true}", got)
	}
}

// buildEnrichmentUpdate must leave risk_score (and threat_type) NULL for a
// benign re-observation so the COALESCE UPDATE preserves any prior verdict,
// while still writing the score/type for a real phishing verdict.
func TestBuildEnrichmentUpdateBenignDoesNotClobber(t *testing.T) {
	p := &Persister{}

	benign := p.buildEnrichmentUpdate(7, &URLResult{Score: 0, Label: "legitimate"})
	if benign.RiskScore.Valid {
		t.Errorf("benign risk_score = %+v, want NULL", benign.RiskScore)
	}
	if benign.ThreatType.Valid {
		t.Errorf("benign threat_type = %+v, want NULL", benign.ThreatType)
	}

	phish := p.buildEnrichmentUpdate(7, &URLResult{Score: 90, Label: "phishing"})
	if !phish.RiskScore.Valid || phish.RiskScore.Int32 != 90 {
		t.Errorf("phishing risk_score = %+v, want 90", phish.RiskScore)
	}
	if !phish.ThreatType.Valid || phish.ThreatType.String != "phishing" {
		t.Errorf("phishing threat_type = %+v, want phishing", phish.ThreatType)
	}
}
