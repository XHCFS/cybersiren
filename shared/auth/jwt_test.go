package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager("test-secret-which-is-long-enough", time.Hour)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func TestNewManager(t *testing.T) {
	if _, err := NewManager("", time.Hour); !errors.Is(err, ErrEmptySecret) {
		t.Errorf("empty secret: got %v, want ErrEmptySecret", err)
	}

	// Non-positive expiry must fall back to a default, not stay zero.
	m, err := NewManager("secret", 0)
	if err != nil {
		t.Fatalf("NewManager with zero expiry: %v", err)
	}
	if m.expiry != 24*time.Hour {
		t.Errorf("default expiry = %v, want 24h", m.expiry)
	}
}

func TestIssueVerifyRoundTrip(t *testing.T) {
	m := newTestManager(t)

	tok, err := m.Issue(42, 7, RoleAnalyst, "analyst@example.com")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	claims, err := m.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.UserID != 42 {
		t.Errorf("UserID = %d, want 42", claims.UserID)
	}
	if claims.OrgID != 7 {
		t.Errorf("OrgID = %d, want 7", claims.OrgID)
	}
	if claims.Role != RoleAnalyst {
		t.Errorf("Role = %q, want analyst", claims.Role)
	}
	if claims.Email != "analyst@example.com" {
		t.Errorf("Email = %q, want analyst@example.com", claims.Email)
	}
	if claims.Subject != "42" {
		t.Errorf("Subject = %q, want 42", claims.Subject)
	}
	if claims.Issuer != issuer {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, issuer)
	}
}

func TestIssueRejectsBadIdentity(t *testing.T) {
	m := newTestManager(t)
	cases := []struct {
		name           string
		uid, org       int64
		role           Role
	}{
		{"zero uid", 0, 1, RoleAdmin},
		{"negative org", 1, -1, RoleAdmin},
		{"unknown role", 1, 1, Role("superuser")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := m.Issue(tc.uid, tc.org, tc.role, "x@y.z"); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestVerifyEmpty(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Verify(""); !errors.Is(err, ErrEmptyCredential) {
		t.Errorf("empty token: got %v, want ErrEmptyCredential", err)
	}
}

func TestVerifyGarbage(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Verify("not.a.jwt"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("garbage token: got %v, want ErrInvalidToken", err)
	}
}

func TestVerifyWrongSecret(t *testing.T) {
	issuer := newTestManager(t)
	tok, err := issuer.Issue(1, 1, RoleViewer, "v@x.z")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	other, err := NewManager("a-completely-different-secret", time.Hour)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if _, err := other.Verify(tok); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("wrong secret: got %v, want ErrInvalidToken", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	m := newTestManager(t)
	// Force the clock into the past so the minted token is already expired.
	m.now = func() time.Time { return time.Now().Add(-2 * time.Hour) }
	tok, err := m.Issue(1, 1, RoleViewer, "v@x.z")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Verify with a normal clock.
	m.now = time.Now
	if _, err := m.Verify(tok); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expired token: got %v, want ErrInvalidToken", err)
	}
}

// TestVerifyRejectsAlgNone guards against the classic alg=none downgrade: a
// token signed with the "none" method must not be accepted even though its
// claims are otherwise well-formed.
func TestVerifyRejectsAlgNone(t *testing.T) {
	m := newTestManager(t)
	claims := Claims{
		UserID: 1, OrgID: 1, Role: RoleAdmin, Email: "a@b.c",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tok, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if _, err := m.Verify(tok); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("alg=none token: got %v, want ErrInvalidToken", err)
	}
}

// TestVerifyRejectsWrongIssuer ensures a token minted for a different issuer is
// rejected even when signed with the same secret.
func TestVerifyRejectsWrongIssuer(t *testing.T) {
	m := newTestManager(t)
	claims := Claims{
		UserID: 1, OrgID: 1, Role: RoleAdmin, Email: "a@b.c",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "someone-else",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := m.Verify(signed); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("wrong issuer: got %v, want ErrInvalidToken", err)
	}
}

func TestRoleValid(t *testing.T) {
	for _, r := range []Role{RoleAdmin, RoleAnalyst, RoleViewer} {
		if !r.Valid() {
			t.Errorf("%q should be valid", r)
		}
	}
	if Role("nope").Valid() {
		t.Error("unknown role should be invalid")
	}
}
