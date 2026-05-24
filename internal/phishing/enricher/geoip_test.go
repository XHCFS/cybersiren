package enricher

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func geoIPTestDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("GEOIP_DIR")
	if dir == "" {
		t.Skip("GEOIP_DIR not set — skipping GeoIP tests")
	}
	return dir
}

func TestGeoIPLookup_Google(t *testing.T) {
	dir := geoIPTestDir(t)
	g, err := NewGeoIPLookup(dir)
	require.NoError(t, err)
	defer g.Close()

	r := g.Lookup("8.8.8.8")
	require.Equal(t, 15169, r.ASN, "8.8.8.8 should be Google ASN 15169")
	// ASN 15169 is in the CDN set — geo fields must be empty.
	require.Empty(t, r.Country, "CDN ASN: country should be zeroed")
}

func TestGeoIPLookup_InvalidIP(t *testing.T) {
	dir := geoIPTestDir(t)
	g, err := NewGeoIPLookup(dir)
	require.NoError(t, err)
	defer g.Close()

	r := g.Lookup("not-an-ip")
	require.Equal(t, 0, r.ASN)
	require.Empty(t, r.Country)
}
