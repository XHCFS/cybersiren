package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// alphabet for the random suffix: URL-safe, unambiguous base62. Using a fixed
// alphabet (rather than base64) keeps keys copy-paste-safe (no +/= or padding)
// and free of characters that get mangled in URLs or shells.
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// keyPrefixLookupLen is how many leading characters of the full key are stored
// in api_keys.key_prefix for O(1) candidate lookup before the (expensive)
// bcrypt comparison. It deliberately includes the configured prefix plus a few
// random chars so it is reasonably selective without revealing the secret.
const keyPrefixLookupLen = 12

// GeneratedKey is the result of minting a new API key. Plaintext is shown to
// the user exactly once and never stored. Hash is what goes in
// api_keys.key_hash; Prefix is the api_keys.key_prefix lookup fragment.
type GeneratedKey struct {
	// Plaintext is the full secret ("<config-prefix><random>"). Return it to
	// the caller once, then discard — only Hash is persistable.
	Plaintext string
	// Hash is the bcrypt hash of Plaintext, suitable for api_keys.key_hash.
	Hash string
	// Prefix is the leading fragment of Plaintext stored in
	// api_keys.key_prefix for fast lookup of the candidate row.
	Prefix string
}

// KeyManager mints and validates API keys. It is configured from the API-key
// half of shared/config.AuthConfig (APIKeyPrefix, APIKeyPrefixLen, BcryptCost)
// and is safe for concurrent use.
type KeyManager struct {
	prefix     string // human prefix, e.g. "cs_"
	suffixLen  int    // number of random chars after the prefix
	bcryptCost int
}

// NewKeyManager builds a KeyManager. prefix is AuthConfig.APIKeyPrefix,
// suffixLen is AuthConfig.APIKeyPrefixLen (the random-suffix length), and
// bcryptCost is AuthConfig.BcryptCost. Invalid values are rejected so a
// misconfigured service fails fast at startup rather than minting weak keys.
func NewKeyManager(prefix string, suffixLen, bcryptCost int) (*KeyManager, error) {
	if suffixLen <= 0 {
		return nil, fmt.Errorf("auth: api key suffix length must be positive, got %d", suffixLen)
	}
	if bcryptCost < bcrypt.MinCost || bcryptCost > bcrypt.MaxCost {
		return nil, fmt.Errorf("auth: bcrypt cost must be between %d and %d, got %d",
			bcrypt.MinCost, bcrypt.MaxCost, bcryptCost)
	}
	// bcrypt silently truncates input past 72 bytes; reject configurations
	// that could produce keys where trailing random entropy is ignored.
	if len(prefix)+suffixLen > 72 {
		return nil, fmt.Errorf("auth: prefix(%d)+suffix(%d) exceeds bcrypt's 72-byte input limit",
			len(prefix), suffixLen)
	}
	return &KeyManager{prefix: prefix, suffixLen: suffixLen, bcryptCost: bcryptCost}, nil
}

// Generate mints a fresh API key: a cryptographically random suffix appended to
// the configured prefix, bcrypt-hashed for storage, with a lookup prefix
// extracted. The plaintext is returned only in the result and is the caller's
// responsibility to surface to the user exactly once.
func (k *KeyManager) Generate() (GeneratedKey, error) {
	suffix, err := randomString(k.suffixLen)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("auth: generate api key: %w", err)
	}
	plaintext := k.prefix + suffix
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), k.bcryptCost)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("auth: hash api key: %w", err)
	}
	return GeneratedKey{
		Plaintext: plaintext,
		Hash:      string(hash),
		Prefix:    LookupPrefix(plaintext),
	}, nil
}

// HashKey bcrypt-hashes an externally supplied key (e.g. one being imported).
// Most callers should use Generate instead.
func (k *KeyManager) HashKey(plaintext string) (string, error) {
	if plaintext == "" {
		return "", ErrEmptyCredential
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), k.bcryptCost)
	if err != nil {
		return "", fmt.Errorf("auth: hash api key: %w", err)
	}
	return string(hash), nil
}

// Validate checks a candidate plaintext key against a stored bcrypt hash in
// constant time (bcrypt's compare is itself constant-time for a given cost).
// It returns nil on match, ErrInvalidAPIKey on mismatch, and ErrEmptyCredential
// for an empty key. The (KeyManager) receiver is not strictly required for the
// comparison, but keeping it a method keeps the call site symmetric with
// Generate/HashKey.
func (k *KeyManager) Validate(plaintext, storedHash string) error {
	return ValidateKey(plaintext, storedHash)
}

// ValidateKey is the package-level form of (*KeyManager).Validate. It needs no
// configuration because the cost is encoded in storedHash itself.
func ValidateKey(plaintext, storedHash string) error {
	if plaintext == "" || storedHash == "" {
		return ErrEmptyCredential
	}
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(plaintext))
	if err != nil {
		// Wrap so callers can log the cause but match on the sentinel.
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrInvalidAPIKey
		}
		return fmt.Errorf("%w: %v", ErrInvalidAPIKey, err)
	}
	return nil
}

// LookupPrefix returns the api_keys.key_prefix fragment for a full plaintext
// key: its leading keyPrefixLookupLen characters (or the whole key if shorter).
// Indexing this column lets the caller fetch the single candidate row before
// running the expensive bcrypt comparison.
func LookupPrefix(plaintext string) string {
	if len(plaintext) <= keyPrefixLookupLen {
		return plaintext
	}
	return plaintext[:keyPrefixLookupLen]
}

// HasPrefix reports whether key carries the manager's configured prefix. It is
// a cheap structural gate callers may use to reject obviously-foreign tokens
// before any DB lookup.
func (k *KeyManager) HasPrefix(key string) bool {
	return strings.HasPrefix(key, k.prefix)
}

// randomString returns n characters drawn uniformly from alphabet using
// crypto/rand. Rejection sampling avoids the modulo bias that "b % len" would
// introduce for an alphabet whose length does not divide 256.
func randomString(n int) (string, error) {
	const max = 256 - (256 % len(alphabet)) // largest multiple of len(alphabet) <= 256
	out := make([]byte, 0, n)
	buf := make([]byte, n) // refill in batches; usually one read suffices
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if int(b) >= max {
				continue // reject biased tail
			}
			out = append(out, alphabet[int(b)%len(alphabet)])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
}
