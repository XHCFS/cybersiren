package enricher

import "go.opentelemetry.io/otel"

// enricherTracer is the OTEL tracer used by every per-enricher span in this
// package (dns / whois / tls / http / geoip / shortener / enrich-orchestrator).
// The name shows up in Jaeger as the source instrumentation library.
var enricherTracer = otel.Tracer("svc-03-url-analysis/phishing-enricher")
