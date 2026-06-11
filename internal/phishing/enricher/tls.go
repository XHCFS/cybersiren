package enricher

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

// TLSResult holds the TLS certificate inspection result.
type TLSResult struct {
	Enabled   bool
	Issuer    string
	Subject   string
	ValidFrom string
	ValidTo   string
}

// GetTLSCert dials hostname:port and inspects the TLS certificate chain.
// Returns TLSResult with Enabled=false and zero strings on any failure.
func GetTLSCert(ctx context.Context, hostname string, port int) TLSResult {
	if port == 0 {
		port = 443
	}
	addr := fmt.Sprintf("%s:%d", hostname, port)

	ctx, span := enricherTracer.Start(ctx, "enricher.tls.GetTLSCert")
	defer span.End()
	span.SetAttributes(attribute.String("enricher.hostname", hostname), attribute.Int("enricher.port", port))

	dialCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	// SSRF guard: hostname comes from a URL in an incoming email. InsecureSkipVerify
	// is intentional (we want cert data even for expired/self-signed certs), but
	// without an IP filter that lets an attacker dial internal/cloud-metadata hosts
	// on :443 to blind-probe the network. Control rejects any non-public resolved IP
	// before the TCP connect (mirrors safeDialContext; defeats DNS rebinding).
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Control: blockNonPublicControl},
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional: we want cert data even for expired/self-signed
			ServerName:         hostname,
		},
	}

	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		span.RecordError(err)
		return TLSResult{}
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return TLSResult{}
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return TLSResult{}
	}
	span.SetAttributes(attribute.Bool("enricher.tls_enabled", true), attribute.Int("enricher.cert_chain_len", len(certs)))

	leaf := certs[0]

	issuer := ""
	if len(certs) > 1 {
		issuer = commonName(certs[1].Subject.Names)
	} else {
		issuer = commonName(leaf.Issuer.Names)
	}

	return TLSResult{
		Enabled:   true,
		Issuer:    issuer,
		Subject:   commonName(leaf.Subject.Names),
		ValidFrom: leaf.NotBefore.UTC().Format(time.RFC3339),
		ValidTo:   leaf.NotAfter.UTC().Format(time.RFC3339),
	}
}

func commonName(names []pkix.AttributeTypeAndValue) string {
	for _, n := range names {
		// OID 2.5.4.3 = CommonName
		if n.Type.String() == "2.5.4.3" {
			if s, ok := n.Value.(string); ok {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}
