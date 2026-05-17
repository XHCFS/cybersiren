package enricher

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"
	"time"
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

	dialCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional: we want cert data even for expired/self-signed
			ServerName:         hostname,
		},
	}

	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
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
