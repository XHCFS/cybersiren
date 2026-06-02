package feeds

import "testing"

const sampleBundle = `{
  "type": "bundle",
  "objects": [
    {"type":"identity","id":"identity--1","name":"ACME"},
    {"type":"indicator","id":"indicator--a","confidence":80,"labels":["malicious-activity"],
     "pattern":"[url:value = 'http://evil.example.com/x']"},
    {"type":"indicator","id":"indicator--b","confidence":50,
     "pattern":"[domain-name:value = 'bad.example.org']"},
    {"type":"indicator","id":"indicator--c",
     "pattern":"[ipv4-addr:value = '203.0.113.7']"},
    {"type":"indicator","id":"indicator--d",
     "pattern":"[file:hashes.'SHA-256' = 'abc123']"},
    {"type":"indicator","id":"indicator--e",
     "pattern":"[url:value = 'http://a.test'] OR [domain-name:value = 'b.test']"},
    {"type":"indicator","id":"indicator--f","pattern":"[mutex:name = 'x']"}
  ]
}`

func TestParseSTIXBundle(t *testing.T) {
	t.Parallel()
	got, err := ParseSTIXBundle([]byte(sampleBundle), 42)
	if err != nil {
		t.Fatalf("ParseSTIXBundle: %v", err)
	}
	// a(url) + b(domain) + c(ip) + d(hash) + e(url+domain) = 6; mutex unsupported.
	if len(got) != 6 {
		t.Fatalf("got %d indicators, want 6: %+v", len(got), got)
	}
	first := got[0]
	if first.FeedID != 42 || first.IndicatorType != "url" || first.IndicatorValue != "http://evil.example.com/x" {
		t.Errorf("first indicator = %+v", first)
	}
	if first.RiskScore != 80 || first.Confidence != 0.8 {
		t.Errorf("confidence mapping wrong: risk=%d conf=%v", first.RiskScore, first.Confidence)
	}

	types := map[string]int{}
	for _, ind := range got {
		types[ind.IndicatorType]++
	}
	if types["url"] != 2 || types["domain"] != 2 || types["ip"] != 1 || types["hash"] != 1 {
		t.Errorf("type distribution = %v, want url=2 domain=2 ip=1 hash=1", types)
	}
}

func TestParseSTIXBundleInvalid(t *testing.T) {
	t.Parallel()
	if _, err := ParseSTIXBundle([]byte("{not json"), 1); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	got, err := ParseSTIXBundle([]byte(`{"objects":[]}`), 1)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty bundle: got %d err %v, want 0/nil", len(got), err)
	}
}
