package models

import (
	"encoding/json"
	"time"
)

// EnrichmentData is the in-memory aggregate of all enrichment signals
// collected for a URL during the pipeline run. Assembled by the enrichment
// service, then written into enriched_threats + enrichment_results.
type EnrichmentData struct {
	URL string `json:"url" validate:"required,url"`

	// Network / geo
	IPAddress   string  `json:"ip_address,omitempty"`
	ASN         int     `json:"asn,omitempty"`
	ASNName     string  `json:"asn_name,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	Country     string  `json:"country,omitempty"`
	CountryName string  `json:"country_name,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`

	// TLS
	SSLEnabled    bool      `json:"ssl_enabled"`
	CertIssuer    string    `json:"cert_issuer,omitempty"`
	CertSubject   string    `json:"cert_subject,omitempty"`
	CertValidFrom time.Time `json:"cert_valid_from,omitempty"`
	CertValidTo   time.Time `json:"cert_valid_to,omitempty"`
	CertSerial    string    `json:"cert_serial,omitempty"`

	// WHOIS
	// CreationDate is a date-only value (no time component). The DB column is DATE.
	// When mapping to db.EnrichedThreat, truncate to date: pgtype.Date{Time: t.Truncate(24*time.Hour), Valid: true}
	CreationDate time.Time `json:"creation_date,omitempty"`
	// ExpiryDate is a date-only value. See CreationDate.
	ExpiryDate time.Time `json:"expiry_date,omitempty"`
	// UpdatedDate is a date-only value. See CreationDate.
	UpdatedDate time.Time `json:"updated_date,omitempty"`
	Registrar   string    `json:"registrar,omitempty"`
	NameServers []string  `json:"name_servers,omitempty"`

	// Availability
	Online         bool `json:"online"`
	HTTPStatusCode int  `json:"http_status_code,omitempty"`

	// Page content
	PageTitle    string `json:"page_title,omitempty"`
	PageLanguage string `json:"page_language,omitempty"`

	// Raw provider responses keyed by provider name, e.g. "virustotal", "ipinfo"
	ProviderResults map[string]json.RawMessage `json:"provider_results,omitempty"`
}
