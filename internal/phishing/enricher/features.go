package enricher

import (
	"math"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/publicsuffix"
)

// FeatureVector is the exact 44-column feature vector expected by hgb_operational.joblib.
// Float64 fields use math.NaN() for unknown/missing values; ToJSON() serializes NaN as null.
type FeatureVector struct {
	// Identity
	URL      string
	Hostname string
	Domain   string
	TLD      string

	// Network
	IPAddress string
	CIDRBlock string
	ASN       float64
	ASNName   string
	ISP       string

	// Geographic (zeroed for CDN ASNs)
	Country     string
	CountryName string
	Region      string
	City        string
	Latitude    float64
	Longitude   float64

	// TLS
	SSLEnabled    string
	CertIssuer    string
	CertSubject   string
	CertValidFrom string
	CertValidTo   string

	// HTTP
	HTTPStatusCode float64
	PageTitle      string
	PageLanguage   string

	// WHOIS
	Registrar    string
	CreationDate string
	ExpiryDate   string
	UpdatedDate  string
	NameServers  string

	// Derived numeric features (NaN if inputs missing)
	DomainAgeDays         float64
	CertAgeDays           float64
	CertValiditySpanDays  float64
	TitleBrandMismatch    float64
	TitleHasLoginKw       float64
	SubdomainDepth        float64
	SubdomainBrandCount   float64
	ApexIsNumeric         float64
	FormActionMismatch    float64
	IPInURL               float64
	NonStdPort            float64
	URLDomainCharRatio    float64
	FaviconDomainMismatch float64
	PasswordFieldCount    float64
	HasHiddenRedirect     float64
	IsEphemeralPlatform   float64
}

// ToJSON returns a map suitable for JSON serialization.
// NaN float64 values become nil (JSON null) — NaN is invalid JSON.
func (f FeatureVector) ToJSON() map[string]interface{} {
	nan := func(v float64) interface{} {
		if math.IsNaN(v) {
			return nil
		}
		return v
	}
	return map[string]interface{}{
		"url":                    f.URL,
		"hostname":               f.Hostname,
		"domain":                 f.Domain,
		"tld":                    f.TLD,
		"ip_address":             f.IPAddress,
		"cidr_block":             f.CIDRBlock,
		"asn":                    nan(f.ASN),
		"asn_name":               f.ASNName,
		"isp":                    f.ISP,
		"country":                f.Country,
		"country_name":           f.CountryName,
		"region":                 f.Region,
		"city":                   f.City,
		"latitude":               nan(f.Latitude),
		"longitude":              nan(f.Longitude),
		"ssl_enabled":            f.SSLEnabled,
		"cert_issuer":            f.CertIssuer,
		"cert_subject":           f.CertSubject,
		"cert_valid_from":        f.CertValidFrom,
		"cert_valid_to":          f.CertValidTo,
		"http_status_code":       nan(f.HTTPStatusCode),
		"page_title":             f.PageTitle,
		"page_language":          f.PageLanguage,
		"registrar":              f.Registrar,
		"creation_date":          f.CreationDate,
		"expiry_date":            f.ExpiryDate,
		"updated_date":           f.UpdatedDate,
		"name_servers":           f.NameServers,
		"domain_age_days":        nan(f.DomainAgeDays),
		"cert_age_days":          nan(f.CertAgeDays),
		"cert_validity_span_days": nan(f.CertValiditySpanDays),
		"title_brand_mismatch":   nan(f.TitleBrandMismatch),
		"title_has_login_kw":     nan(f.TitleHasLoginKw),
		"subdomain_depth":        nan(f.SubdomainDepth),
		"subdomain_brand_count":  nan(f.SubdomainBrandCount),
		"apex_is_numeric":        nan(f.ApexIsNumeric),
		"form_action_mismatch":   nan(f.FormActionMismatch),
		"ip_in_url":              nan(f.IPInURL),
		"non_std_port":           nan(f.NonStdPort),
		"url_domain_char_ratio":  nan(f.URLDomainCharRatio),
		"favicon_domain_mismatch": nan(f.FaviconDomainMismatch),
		"password_field_count":   nan(f.PasswordFieldCount),
		"has_hidden_redirect":    nan(f.HasHiddenRedirect),
		"is_ephemeral_platform":  nan(f.IsEphemeralPlatform),
	}
}

// ComputeFeatures assembles the FeatureVector from an EnrichedURL.
func ComputeFeatures(eu EnrichedURL) FeatureVector {
	rawURL := eu.ResolvedURL
	if rawURL == "" {
		rawURL = eu.OriginalURL
	}

	parsed, _ := url.Parse(rawURL)
	hostname := ""
	if parsed != nil {
		hostname = strings.ToLower(parsed.Hostname())
	}

	geo := eu.Geo
	isCDN := false
	if eu.Geo.ASN != 0 {
		_, isCDN = cdnASNs[uint(eu.Geo.ASN)]
	}

	country, countryName, region, city := geo.Country, geo.CountryName, geo.Region, geo.City
	lat, lon := geo.Latitude, geo.Longitude
	if isCDN {
		country, countryName, region, city = "", "", "", ""
		lat, lon = math.NaN(), math.NaN()
	}

	asn := float64(geo.ASN)
	if geo.ASN == 0 {
		asn = math.NaN()
	}

	sslEnabled := ""
	if eu.TLS.Enabled {
		sslEnabled = "true"
	} else if eu.TLS.ValidFrom != "" || eu.TLS.ValidTo != "" {
		sslEnabled = "false"
	}

	httpStatus := float64(eu.HTTP.StatusCode)
	if eu.HTTP.StatusCode == 0 {
		httpStatus = math.NaN()
	}

	title := strings.TrimSpace(eu.HTTP.Title)
	tld := extractTLD(hostname)
	apex := apexDomain(hostname)
	domain := apex

	fv := FeatureVector{
		URL:      rawURL,
		Hostname: hostname,
		Domain:   domain,
		TLD:      tld,

		IPAddress: eu.IP,
		CIDRBlock: geo.CIDRBlock,
		ASN:       asn,
		ASNName:   geo.ASNName,
		ISP:       geo.ISP,

		Country:     country,
		CountryName: countryName,
		Region:      region,
		City:        city,
		Latitude:    lat,
		Longitude:   lon,

		SSLEnabled:    sslEnabled,
		CertIssuer:    eu.TLS.Issuer,
		CertSubject:   eu.TLS.Subject,
		CertValidFrom: eu.TLS.ValidFrom,
		CertValidTo:   eu.TLS.ValidTo,

		HTTPStatusCode: httpStatus,
		PageTitle:      title,
		PageLanguage:   eu.HTTP.Language,

		Registrar:    eu.WHOIS.Registrar,
		CreationDate: eu.WHOIS.RegistrationDate,
		ExpiryDate:   eu.WHOIS.ExpiryDate,
		UpdatedDate:  eu.WHOIS.UpdatedDate,
		NameServers:  eu.WHOIS.NameServers,

		DomainAgeDays:        daysSince(eu.WHOIS.RegistrationDate),
		CertAgeDays:          daysSince(eu.TLS.ValidFrom),
		CertValiditySpanDays: daysBetween(eu.TLS.ValidFrom, eu.TLS.ValidTo),

		SubdomainDepth:      subdomainDepth(hostname),
		SubdomainBrandCount: subdomainBrandCount(hostname),
		ApexIsNumeric:       apexIsNumeric(hostname),

		IPInURL:            ipInURL(rawURL),
		NonStdPort:         nonStdPort(rawURL),
		URLDomainCharRatio: urlDomainCharRatio(hostname),
		IsEphemeralPlatform: isEphemeralPlatform(hostname),
	}

	// HTML-derived fields must be null (NaN) when the HTTP fetch failed.
	// Sending 0 for a missing password_field_count or form_action_mismatch
	// tells the model "no password fields / no mismatch", which is a strong
	// benign signal — the opposite of "I don't know". StatusCode==0 means
	// FetchHTTP returned the zero-value HTTPResult (error path).
	if eu.HTTP.StatusCode != 0 {
		fv.TitleBrandMismatch = titleBrandMismatch(title, hostname)
		fv.TitleHasLoginKw = titleHasLoginKw(title)
		fv.FormActionMismatch = formActionMismatch(eu.HTTP.FormActionDomain, hostname)
		fv.FaviconDomainMismatch = faviconDomainMismatch(eu.HTTP.FaviconURL, hostname)
		fv.PasswordFieldCount = float64(eu.HTTP.PasswordFieldCount)
		fv.HasHiddenRedirect = boolToFloat(eu.HTTP.HasHiddenRedirect)
	} else {
		nan := math.NaN()
		fv.TitleBrandMismatch = nan
		fv.TitleHasLoginKw = nan
		fv.FormActionMismatch = nan
		fv.FaviconDomainMismatch = nan
		fv.PasswordFieldCount = nan
		fv.HasHiddenRedirect = nan
	}

	return fv
}

// ---- data tables (ported verbatim from operational.py) ----

var brandDomains = map[string][]string{
	"adobe":         {"adobe.com", "adobe.io", "adobe.net"},
	"airbnb":        {"airbnb.com"},
	"aliexpress":    {"aliexpress.com"},
	"amazon":        {"amazon.co.uk", "amazon.com", "amazon.dev"},
	"apple":         {"apple.com", "apple.news"},
	"atlassian":     {"atlassian.com", "atlassian.net"},
	"bankofamerica": {"bankofamerica.com"},
	"barclays":      {"barclays.co.uk", "barclays.com"},
	"binance":       {"binance.com"},
	"cashapp":       {"cash.app", "cashapp.com"},
	"chase":         {"chase.com", "jpmorgan.com"},
	"chatgpt":       {"chatgpt.com"},
	"cisco":         {"cisco.com"},
	"citibank":      {"citi.com", "citibank.com"},
	"coinbase":      {"coinbase.com"},
	"commbank":      {"commbank.com.au"},
	"dell":          {"dell.com"},
	"dhl":           {"dhl.co.uk", "dhl.com", "dhl.de"},
	"discord":       {"discord.com", "discord.gg", "discord.media", "discordapp.com"},
	"docusign":      {"docusign.com", "docusign.net"},
	"doordash":      {"doordash.com"},
	"dpd":           {"dpd.co.uk", "dpd.com"},
	"dropbox":       {"dropbox.com"},
	"ebay":          {"ebay.co.uk", "ebay.com", "ebay.de"},
	"epicgames":     {"epicgames.com"},
	"etsy":          {"etsy.com"},
	"evri":          {"evri.com"},
	"facebook":      {"facebook.com", "facebook.net"},
	"fedex":         {"fedex.com"},
	"google":        {"google.cn", "google.co.id", "google.co.uk", "google.com"},
	"grammarly":     {"grammarly.com", "grammarly.io", "grammarly.net"},
	"hsbc":          {"hsbc.co.uk", "hsbc.com"},
	"hubspot":       {"hubspot.com"},
	"hulu":          {"hulu.com"},
	"instagram":     {"instagram.com"},
	"kaspersky":     {"kaspersky.com"},
	"kraken":        {"kraken.com"},
	"ledger":        {"ledger.com"},
	"linkedin":      {"linkedin.com"},
	"lloyds":        {"lloyds.com", "lloydsbankinggroup.com"},
	"mcafee":        {"mcafee.com"},
	"metamask":      {"metamask.io"},
	"microsoft":     {"microsoft.com", "microsoft.us"},
	"mozilla":       {"mozilla.com", "mozilla.net", "mozilla.org"},
	"natwest":       {"natwest.com"},
	"netflix":       {"netflix.com", "netflix.net"},
	"norton":        {"norton.com"},
	"okta":          {"okta.com"},
	"opera":         {"opera.com"},
	"paypal":        {"paypal.com"},
	"pinterest":     {"pinterest.com", "pinterest.net"},
	"postnl":        {"postnl.nl"},
	"reddit":        {"reddit.com"},
	"roblox":        {"roblox.com"},
	"royalmail":     {"royalmail.com"},
	"salesforce":    {"salesforce.com"},
	"samsung":       {"samsung.com"},
	"santander":     {"santander.co.uk", "santander.com"},
	"shein":         {"shein.com"},
	"signal":        {"signal.me", "signal.org"},
	"slack":         {"slack.com"},
	"snapchat":      {"snapchat.com"},
	"spotify":       {"spotify.com"},
	"steam":         {"steamcommunity.com", "steampowered.com"},
	"stripe":        {"stripe.com", "stripe.network"},
	"telegram":      {"telegram.me", "telegram.org"},
	"temu":          {"temu.com"},
	"tiktok":        {"tiktok.com"},
	"twitch":        {"twitch.tv"},
	"twitter":       {"twitter.com", "x.com"},
	"uber":          {"uber.com"},
	"ups":           {"ups.com"},
	"usps":          {"usps.com"},
	"venmo":         {"venmo.com"},
	"webex":         {"webex.com"},
	"wellsfargo":    {"wellsfargo.com"},
	"whatsapp":      {"whatsapp.com", "whatsapp.net"},
	"youtube":       {"youtube.com"},
	"zelle":         {"zellepay.com"},
	"zoom":          {"zoom.us"},
	"tmobile":       {"t-mobile.com"},
	"att":           {"att.com"},
	"verizon":       {"verizon.com"},
	"vodafone":      {"vodafone.com", "vodafone.co.uk"},
	"o2":            {"o2.co.uk", "o2.com"},
	"uphold":        {"uphold.com"},
	"trust":         {"trustwallet.com"},
	"phantom":       {"phantom.app"},
	"exodus":        {"exodus.com", "exodus.io"},
	"robinhood":     {"robinhood.com"},
	"revolut":       {"revolut.com"},
	"hermes":        {"myhermes.co.uk"},
	"chronopost":    {"chronopost.fr"},
	"colissimo":     {"colissimo.fr"},
	"laposte":       {"laposte.fr"},
	"hmrc":          {"hmrc.gov.uk"},
	"ato":           {"ato.gov.au"},
	"primevideo":    {"primevideo.com"},
	"disneyplus":    {"disneyplus.com"},
	"epic":          {"epicgames.com"},
	"ea":            {"ea.com", "origin.com"},
}

var subdomainBrandKeywords = func() map[string]struct{} {
	m := make(map[string]struct{})
	for brand := range brandDomains {
		m[brand] = struct{}{}
	}
	for _, kw := range []string{
		"msn", "outlook", "office", "onedrive", "teams", "sharepoint",
		"skype", "bing", "hotmail", "live", "azure",
		"gmail", "goog",
		"icloud", "itunes",
		"aws", "kindle",
		"meta", "messenger",
		"symantec", "crypto", "wallet", "support", "helpdesk",
		"mobile", "wireless", "prepaid", "postpaid",
		"uphold", "phantom", "exodus", "trust", "defi", "nft", "airdrop",
		"parcel", "delivery", "tracking", "shipment",
		"secure", "verify", "update", "alert", "notice", "billing",
		"payment", "invoice", "refund", "confirm", "validate",
	} {
		m[kw] = struct{}{}
	}
	return m
}()

var ephemeralPlatformSuffixes = map[string]struct{}{
	"vercel.app":       {},
	"pages.dev":        {},
	"github.io":        {},
	"netlify.app":      {},
	"web.app":          {},
	"glitch.me":        {},
	"webflow.io":       {},
	"fly.dev":          {},
	"render.com":       {},
	"railway.app":      {},
	"surge.sh":         {},
	"usercontent.dev":  {},
	"myportfolio.com":  {},
	"company.site":     {},
	"squarespace.com":  {},
	"weebly.com":       {},
	"wixsite.com":      {},
	"cargo.site":       {},
	"notion.site":      {},
	"blogger.com":      {},
	"blogspot.com":     {},
}

var loginKeywords = map[string]struct{}{
	"login": {}, "log in": {}, "sign in": {}, "signin": {}, "sign-in": {},
	"verify": {}, "verification": {}, "account": {}, "password": {}, "secure": {},
	"security": {}, "authenticate": {}, "authentication": {}, "sicherheit": {},
	"iniciar sesión": {}, "iniciar sesion": {}, "connexion": {}, "anmelden": {},
	"mot de passe": {}, "identifiez": {},
}

// ---- helper functions (ported from operational.py) ----

var reHyphenUnderscore = regexp.MustCompile(`[-_]`)

func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

func daysSince(dateStr string) float64 {
	t := parseISO(dateStr)
	if t.IsZero() {
		return math.NaN()
	}
	return time.Since(t).Hours() / 24.0
}

func daysBetween(fromStr, toStr string) float64 {
	from := parseISO(fromStr)
	to := parseISO(toStr)
	if from.IsZero() || to.IsZero() {
		return math.NaN()
	}
	return to.Sub(from).Hours() / 24.0
}

func parseISO(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	s = strings.ReplaceAll(s, "Z", "+00:00")
	// Try RFC3339 first
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	// Try date-only
	if t, err := time.Parse("2006-01-02", s[:min(len(s), 10)]); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func apexDomain(hostname string) string {
	if hostname == "" {
		return ""
	}
	apex, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err == nil && apex != "" {
		return apex
	}
	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return hostname
}

func extractTLD(hostname string) string {
	if hostname == "" {
		return ""
	}
	tld, _ := publicsuffix.PublicSuffix(hostname)
	return tld
}

func titleBrandMismatch(title, hostname string) float64 {
	titleLower := strings.ToLower(title)
	hostLower := strings.ToLower(hostname)
	for brand, domains := range brandDomains {
		if !strings.Contains(titleLower, brand) {
			continue
		}
		for _, canon := range domains {
			if hostLower == canon || strings.HasSuffix(hostLower, "."+canon) {
				return 0.0
			}
		}
		return 1.0
	}
	return 0.0
}

func titleHasLoginKw(title string) float64 {
	lower := strings.ToLower(title)
	for kw := range loginKeywords {
		if strings.Contains(lower, kw) {
			return 1.0
		}
	}
	return 0.0
}

func subdomainDepth(hostname string) float64 {
	if hostname == "" {
		return 0.0
	}
	labels := strings.Split(hostname, ".")
	depth := len(labels) - 2
	if depth < 0 {
		depth = 0
	}
	return float64(depth)
}

func subdomainBrandCount(hostname string) float64 {
	if hostname == "" {
		return 0.0
	}
	labels := strings.Split(strings.ToLower(hostname), ".")
	if len(labels) <= 2 {
		return 0.0
	}
	subLabels := labels[:len(labels)-2]
	count := 0
	for _, lbl := range subLabels {
		if _, ok := subdomainBrandKeywords[lbl]; ok {
			count++
			continue
		}
		parts := reHyphenUnderscore.Split(lbl, -1)
		for _, p := range parts {
			if _, ok := subdomainBrandKeywords[p]; ok {
				count++
				break
			}
		}
	}
	return float64(count)
}

func apexIsNumeric(hostname string) float64 {
	if hostname == "" {
		return 0.0
	}
	labels := strings.Split(hostname, ".")
	if len(labels) < 2 {
		return 0.0
	}
	stem := labels[len(labels)-2]
	for _, c := range stem {
		if !unicode.IsDigit(c) {
			return 0.0
		}
	}
	return 1.0
}

func formActionMismatch(formActionDomain, servingHostname string) float64 {
	if formActionDomain == "" || servingHostname == "" {
		return 0.0
	}
	servingApex := apexDomain(servingHostname)
	actionApex := apexDomain(formActionDomain)
	if actionApex == servingApex {
		return 0.0
	}
	return 1.0
}

func ipInURL(rawURL string) float64 {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0.0
	}
	host := strings.Trim(u.Hostname(), "[]")
	if net.ParseIP(host) != nil {
		return 1.0
	}
	return 0.0
}

func nonStdPort(rawURL string) float64 {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0.0
	}
	port := u.Port()
	if port == "" {
		return 0.0
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return 0.0
	}
	return 1.0
}

func urlDomainCharRatio(hostname string) float64 {
	if hostname == "" {
		return 0.0
	}
	nonAlpha := 0
	for _, c := range hostname {
		if !unicode.IsLetter(c) && c != '.' {
			nonAlpha++
		}
	}
	return float64(nonAlpha) / float64(len([]rune(hostname)))
}

func faviconDomainMismatch(faviconURL, servingHostname string) float64 {
	if faviconURL == "" || servingHostname == "" {
		return 0.0
	}
	href := faviconURL
	if !strings.Contains(href, "://") {
		if strings.HasPrefix(href, "//") {
			href = "https:" + href
		} else {
			href = "https://" + href
		}
	}
	u, err := url.Parse(href)
	if err != nil || u.Hostname() == "" {
		return 0.0
	}
	servingApex := apexDomain(servingHostname)
	faviconApex := apexDomain(u.Hostname())
	if faviconApex == servingApex {
		return 0.0
	}
	return 1.0
}

func isEphemeralPlatform(hostname string) float64 {
	h := strings.ToLower(hostname)
	for suffix := range ephemeralPlatformSuffixes {
		if strings.HasSuffix(h, "."+suffix) {
			return 1.0
		}
	}
	return 0.0
}
