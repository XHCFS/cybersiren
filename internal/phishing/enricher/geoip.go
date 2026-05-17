package enricher

import (
	"fmt"
	"math"
	"net"
	"path/filepath"

	"github.com/oschwald/geoip2-golang"
	maxminddb "github.com/oschwald/maxminddb-golang"
)

// GeoIPResult holds the GeoIP enrichment for an IP address.
type GeoIPResult struct {
	Country     string
	CountryName string
	Region      string
	City        string
	Latitude    float64
	Longitude   float64
	ASN         int
	ASNName     string
	ISP         string
	CIDRBlock   string
}

// cdnASNs are major CDN/anycast ASNs whose geo data reflects PoP location, not origin.
var cdnASNs = map[uint]struct{}{
	13335:  {},
	209242: {},
	20940:  {},
	16625:  {},
	54113:  {},
	16509:  {},
	14618:  {},
	15169:  {},
	36492:  {},
	8075:   {},
	8068:   {},
	32934:  {},
	63949:  {},
	19551:  {},
	22822:  {},
	60068:  {},
}

// GeoIPLookup holds the open MaxMind database readers.
type GeoIPLookup struct {
	city  *geoip2.Reader
	asnDB *maxminddb.Reader
}

type asnRecord struct {
	ASN  uint   `maxminddb:"autonomous_system_number"`
	Name string `maxminddb:"autonomous_system_organization"`
}

// NewGeoIPLookup opens the MaxMind databases from dir.
func NewGeoIPLookup(dir string) (*GeoIPLookup, error) {
	city, err := geoip2.Open(filepath.Join(dir, "GeoLite2-City.mmdb"))
	if err != nil {
		return nil, fmt.Errorf("open GeoLite2-City.mmdb: %w", err)
	}
	asnDB, err := maxminddb.Open(filepath.Join(dir, "GeoLite2-ASN.mmdb"))
	if err != nil {
		_ = city.Close()
		return nil, fmt.Errorf("open GeoLite2-ASN.mmdb: %w", err)
	}
	return &GeoIPLookup{city: city, asnDB: asnDB}, nil
}

// Close releases the database readers.
func (g *GeoIPLookup) Close() {
	if g.city != nil {
		_ = g.city.Close()
	}
	if g.asnDB != nil {
		_ = g.asnDB.Close()
	}
}

// Lookup returns GeoIP data for ipStr. Returns zero-value struct on any failure.
func (g *GeoIPLookup) Lookup(ipStr string) GeoIPResult {
	result := GeoIPResult{Latitude: math.NaN(), Longitude: math.NaN()}
	if g == nil {
		return result
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return result
	}

	// ASN + CIDR block
	if g.asnDB != nil {
		var rec asnRecord
		network, ok, err := g.asnDB.LookupNetwork(ip, &rec)
		if err == nil && ok {
			result.ASN = int(rec.ASN)
			result.ASNName = rec.Name
			if network != nil {
				result.CIDRBlock = network.String()
			}
		}
	}

	_, isCDN := cdnASNs[uint(result.ASN)]

	// City-level geo (zeroed for CDN ASNs)
	if g.city != nil {
		cityRec, err := g.city.City(ip)
		if err == nil {
			if !isCDN {
				result.Country = cityRec.Country.IsoCode
				if name, ok := cityRec.Country.Names["en"]; ok {
					result.CountryName = name
				}
				if len(cityRec.Subdivisions) > 0 {
					if name, ok := cityRec.Subdivisions[0].Names["en"]; ok {
						result.Region = name
					}
				}
				if name, ok := cityRec.City.Names["en"]; ok {
					result.City = name
				}
				if cityRec.Location.Latitude != 0 || cityRec.Location.Longitude != 0 {
					result.Latitude = cityRec.Location.Latitude
					result.Longitude = cityRec.Location.Longitude
				}
			}
		}
	}

	return result
}
