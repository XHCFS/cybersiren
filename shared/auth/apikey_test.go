package auth

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// testCost keeps bcrypt cheap in unit tests; production reads BcryptCost (12)
// from config.
const testCost = bcrypt.MinCost

func newTestKeyManager(t *testing.T) *KeyManager {
	t.Helper()
	km, err := NewKeyManager("cs_", 24, testCost)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	return km
}

func TestNewKeyManagerValidation(t *testing.T) {
	cases := []struct {
		name      string
		prefix    string
		suffixLen int
		cost      int
		wantErr   bool
	}{
		{"ok", "cs_", 24, testCost, false},
		{"zero suffix", "cs_", 0, testCost, true},
		{"negative suffix", "cs_", -1, testCost, true},
		{"cost too low", "cs_", 24, bcrypt.MinCost - 1, true},
		{"cost too high", "cs_", 24, bcrypt.MaxCost + 1, true},
		{"exceeds bcrypt 72-byte limit", "cs_", 80, testCost, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewKeyManager(tc.prefix, tc.suffixLen, tc.cost)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestGenerateAndValidate(t *testing.T) {
	km := newTestKeyManager(t)

	gk, err := km.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.HasPrefix(gk.Plaintext, "cs_") {
		t.Errorf("plaintext %q missing configured prefix", gk.Plaintext)
	}
	if len(gk.Plaintext) != len("cs_")+24 {
		t.Errorf("plaintext length = %d, want %d", len(gk.Plaintext), len("cs_")+24)
	}
	if gk.Hash == gk.Plaintext {
		t.Error("hash must not equal plaintext")
	}
	if gk.Prefix != km.LookupPrefix(gk.Plaintext) {
		t.Errorf("Prefix = %q, want %q", gk.Prefix, km.LookupPrefix(gk.Plaintext))
	}

	// Correct key validates.
	if err := km.Validate(gk.Plaintext, gk.Hash); err != nil {
		t.Errorf("Validate(correct): %v", err)
	}
	// Wrong key is rejected.
	if err := km.Validate(gk.Plaintext+"x", gk.Hash); !errors.Is(err, ErrInvalidAPIKey) {
		t.Errorf("Validate(wrong): got %v, want ErrInvalidAPIKey", err)
	}
}

func TestGenerateUniqueness(t *testing.T) {
	km := newTestKeyManager(t)
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		gk, err := km.Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if seen[gk.Plaintext] {
			t.Fatalf("duplicate key generated: %q", gk.Plaintext)
		}
		seen[gk.Plaintext] = true
	}
}

func TestValidateEmpty(t *testing.T) {
	km := newTestKeyManager(t)
	if err := km.Validate("", "somehash"); !errors.Is(err, ErrEmptyCredential) {
		t.Errorf("empty key: got %v, want ErrEmptyCredential", err)
	}
	if err := km.Validate("cs_abc", ""); !errors.Is(err, ErrEmptyCredential) {
		t.Errorf("empty hash: got %v, want ErrEmptyCredential", err)
	}
}

func TestValidateGarbageHash(t *testing.T) {
	if err := ValidateKey("cs_abc", "not-a-bcrypt-hash"); !errors.Is(err, ErrInvalidAPIKey) {
		t.Errorf("garbage hash: got %v, want ErrInvalidAPIKey", err)
	}
}

func TestHashKey(t *testing.T) {
	km := newTestKeyManager(t)
	hash, err := km.HashKey("cs_externalkey")
	if err != nil {
		t.Fatalf("HashKey: %v", err)
	}
	if err := km.Validate("cs_externalkey", hash); err != nil {
		t.Errorf("Validate after HashKey: %v", err)
	}
	if _, err := km.HashKey(""); !errors.Is(err, ErrEmptyCredential) {
		t.Errorf("HashKey(empty): got %v, want ErrEmptyCredential", err)
	}
}

func TestLookupPrefix(t *testing.T) {
	km := newTestKeyManager(t) // prefix "cs_", suffixLen 24
	wantLen := len("cs_") + maxLookupSuffixChars
	long := "cs_abcdefghijklmnopqrstuvwxyz"
	if got := km.LookupPrefix(long); len(got) != wantLen {
		t.Errorf("LookupPrefix(long) len = %d, want %d", len(got), wantLen)
	}
	// An externally supplied key shorter than the lookup window is returned
	// verbatim (only reachable via HashKey, never via this manager's Generate).
	short := "cs_ab"
	if got := km.LookupPrefix(short); got != short {
		t.Errorf("LookupPrefix(short) = %q, want %q", got, short)
	}
}

// TestLookupPrefixNeverRevealsFullKey is the regression guard for the cleartext
// key_prefix leak: for every minted key the stored Prefix must be strictly
// shorter than the plaintext and must omit at least reservedSuffixChars of the
// random suffix. It exercises the smallest legal suffix and the package default.
func TestLookupPrefixNeverRevealsFullKey(t *testing.T) {
	cases := []struct {
		name      string
		prefix    string
		suffixLen int
	}{
		{"minimum legal suffix", "cs_", reservedSuffixChars + 1},
		{"default config suffix", "cs_", 32},
		{"empty prefix", "", reservedSuffixChars + 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			km, err := NewKeyManager(tc.prefix, tc.suffixLen, testCost)
			if err != nil {
				t.Fatalf("NewKeyManager: %v", err)
			}
			for i := 0; i < 25; i++ {
				gk, err := km.Generate()
				if err != nil {
					t.Fatalf("Generate: %v", err)
				}
				if gk.Prefix == gk.Plaintext {
					t.Fatalf("stored Prefix equals full plaintext %q — whole secret leaked", gk.Plaintext)
				}
				if len(gk.Prefix) >= len(gk.Plaintext) {
					t.Fatalf("Prefix len %d >= plaintext len %d", len(gk.Prefix), len(gk.Plaintext))
				}
				// At least reservedSuffixChars random characters must be omitted.
				if omitted := len(gk.Plaintext) - len(gk.Prefix); omitted < reservedSuffixChars {
					t.Fatalf("only %d random chars withheld from prefix, want >= %d",
						omitted, reservedSuffixChars)
				}
				if !strings.HasPrefix(gk.Plaintext, gk.Prefix) {
					t.Fatalf("Prefix %q is not a prefix of plaintext %q", gk.Prefix, gk.Plaintext)
				}
			}
		})
	}
}

// TestNewKeyManagerRejectsShortSuffix asserts the fail-fast guard: a suffix that
// cannot keep reservedSuffixChars secret must be rejected at construction.
func TestNewKeyManagerRejectsShortSuffix(t *testing.T) {
	if _, err := NewKeyManager("cs_", reservedSuffixChars, testCost); err == nil {
		t.Fatalf("NewKeyManager accepted suffixLen=%d, want error", reservedSuffixChars)
	}
	if _, err := NewKeyManager("cs_", reservedSuffixChars+1, testCost); err != nil {
		t.Fatalf("NewKeyManager rejected minimum legal suffixLen=%d: %v", reservedSuffixChars+1, err)
	}
}

func TestHasPrefix(t *testing.T) {
	km := newTestKeyManager(t)
	if !km.HasPrefix("cs_anything") {
		t.Error("HasPrefix(cs_anything) = false, want true")
	}
	if km.HasPrefix("yk_anything") {
		t.Error("HasPrefix(yk_anything) = true, want false")
	}
}

// TestRandomStringDistribution is a light sanity check that randomString draws
// from the full alphabet and produces the requested length.
func TestRandomString(t *testing.T) {
	s, err := randomString(100)
	if err != nil {
		t.Fatalf("randomString: %v", err)
	}
	if len(s) != 100 {
		t.Fatalf("len = %d, want 100", len(s))
	}
	for _, c := range s {
		if !strings.ContainsRune(alphabet, c) {
			t.Fatalf("char %q not in alphabet", c)
		}
	}
}
