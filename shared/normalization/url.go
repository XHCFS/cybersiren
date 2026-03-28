package normalization

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

var (
	ErrEmptyURL    = errors.New("empty url")
	ErrInvalidURL  = errors.New("invalid url")
	ErrEmptyDomain = errors.New("empty domain")
)

func NormalizeURL(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", ErrEmptyURL
	}

	if !hasExplicitScheme(value) {
		value = "http://" + strings.TrimPrefix(value, "//")
	}

	u, err := url.Parse(value)
	if err != nil {
		return "", ErrInvalidURL
	}

	hostname := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if hostname == "" {
		return "", ErrInvalidURL
	}

	u.Scheme = strings.ToLower(strings.TrimSpace(u.Scheme))
	if port := strings.TrimSpace(u.Port()); port != "" {
		u.Host = net.JoinHostPort(hostname, port)
	} else {
		u.Host = hostname
	}

	if u.Path == "/" || u.Path == "" {
		u.Path = ""
	}

	return u.String(), nil
}

func ExtractDomain(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", ErrInvalidURL
	}

	hostname := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if hostname == "" {
		return "", ErrEmptyDomain
	}

	return hostname, nil
}

func NormalizeDomain(raw string) string {
	domain := strings.ToLower(strings.TrimSpace(raw))

	for strings.HasPrefix(domain, "*.") {
		domain = strings.TrimPrefix(domain, "*.")
	}

	for strings.HasSuffix(domain, ".") {
		domain = strings.TrimSuffix(domain, ".")
	}

	return domain
}

func IsURL(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return false
	}

	if strings.TrimSpace(u.Hostname()) == "" {
		return false
	}

	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	return scheme == "http" || scheme == "https"
}

func hasExplicitScheme(raw string) bool {
	idx := strings.Index(raw, "://")
	if idx <= 0 {
		return false
	}

	scheme := raw[:idx]
	for i, r := range scheme {
		if i == 0 {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
				return false
			}
			continue
		}

		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '+' || r == '-' || r == '.' {
			continue
		}

		return false
	}

	return true
}
