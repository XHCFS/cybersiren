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
	if gk.Prefix != LookupPrefix(gk.Plaintext) {
		t.Errorf("Prefix = %q, want %q", gk.Prefix, LookupPrefix(gk.Plaintext))
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
	long := "cs_abcdefghijklmnopqrstuvwxyz"
	if got := LookupPrefix(long); len(got) != keyPrefixLookupLen {
		t.Errorf("LookupPrefix(long) len = %d, want %d", len(got), keyPrefixLookupLen)
	}
	short := "cs_ab"
	if got := LookupPrefix(short); got != short {
		t.Errorf("LookupPrefix(short) = %q, want %q", got, short)
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
