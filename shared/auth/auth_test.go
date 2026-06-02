package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/shared/config"
)

// fakeQuerier is an in-memory APIKeyQuerier for unit tests.
type fakeQuerier struct {
	row      dbsqlc.GetAPIKeyByHashRow
	getErr   error
	touched  []int64
	touchErr error
}

func (f *fakeQuerier) GetAPIKeyByHash(_ context.Context, _ string) (dbsqlc.GetAPIKeyByHashRow, error) {
	return f.row, f.getErr
}

func (f *fakeQuerier) TouchAPIKeyLastUsed(_ context.Context, id int64) error {
	f.touched = append(f.touched, id)
	return f.touchErr
}

func testCfg() config.AuthConfig {
	return config.AuthConfig{JWTSecret: "test-secret-not-for-prod", JWTExpiry: time.Hour}
}

func TestHashKeyDeterministicAndGenerate(t *testing.T) {
	t.Parallel()
	h1, h2 := HashKey("cs_abc"), HashKey("cs_abc")
	if h1 != h2 {
		t.Fatal("HashKey must be deterministic")
	}
	if h1 == HashKey("cs_abd") {
		t.Fatal("distinct keys must hash differently")
	}
	if len(h1) != 64 {
		t.Errorf("sha256 hex must be 64 chars, got %d", len(h1))
	}
	pt, prefix, hash, err := GenerateKey("cs_", 24)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(prefix) != 8 || pt[:3] != "cs_" {
		t.Errorf("plaintext=%q prefix=%q, want cs_ prefix and 8-char key_prefix", pt, prefix)
	}
	if hash != HashKey(pt) {
		t.Error("returned hash must equal HashKey(plaintext)")
	}
}

func TestLookupAPIKey(t *testing.T) {
	t.Parallel()
	valid := dbsqlc.GetAPIKeyByHashRow{ID: 7, OrgID: 3, UserID: pgtype.Int8{Int64: 9, Valid: true}, Scopes: []string{"ingest"}}

	t.Run("valid touches last_used and returns identity", func(t *testing.T) {
		t.Parallel()
		f := &fakeQuerier{row: valid}
		a := New(f, testCfg())
		res, err := a.LookupAPIKey(context.Background(), "cs_whatever")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if res.OrgID != 3 || res.UserID != 9 || res.KeyID != 7 {
			t.Errorf("res = %+v", res)
		}
		if len(f.touched) != 1 || f.touched[0] != 7 {
			t.Errorf("last_used_at not touched: %v", f.touched)
		}
	})

	t.Run("revoked rejected", func(t *testing.T) {
		t.Parallel()
		row := valid
		row.RevokedAt = pgtype.Timestamptz{Time: time.Now().Add(-time.Hour), Valid: true}
		a := New(&fakeQuerier{row: row}, testCfg())
		if _, err := a.LookupAPIKey(context.Background(), "k"); !errors.Is(err, ErrKeyRevoked) {
			t.Fatalf("err = %v, want ErrKeyRevoked", err)
		}
	})

	t.Run("expired rejected", func(t *testing.T) {
		t.Parallel()
		row := valid
		row.ExpiresAt = pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true}
		a := New(&fakeQuerier{row: row}, testCfg())
		if _, err := a.LookupAPIKey(context.Background(), "k"); !errors.Is(err, ErrKeyExpired) {
			t.Fatalf("err = %v, want ErrKeyExpired", err)
		}
	})

	t.Run("missing rejected", func(t *testing.T) {
		t.Parallel()
		a := New(&fakeQuerier{getErr: errors.New("no rows")}, testCfg())
		if _, err := a.LookupAPIKey(context.Background(), "k"); !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("err = %v, want ErrKeyNotFound", err)
		}
	})

	t.Run("empty key rejected without DB call", func(t *testing.T) {
		t.Parallel()
		f := &fakeQuerier{row: valid}
		a := New(f, testCfg())
		if _, err := a.LookupAPIKey(context.Background(), ""); !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("err = %v, want ErrKeyNotFound", err)
		}
		if len(f.touched) != 0 {
			t.Error("must not touch on empty key")
		}
	})
}

func TestHasScope(t *testing.T) {
	t.Parallel()
	if !HasScope([]string{"read", "ingest"}, "ingest") {
		t.Error("should grant present scope")
	}
	if !HasScope([]string{"*"}, "anything") {
		t.Error("wildcard should grant all")
	}
	if HasScope([]string{"read"}, "write") {
		t.Error("should not grant absent scope")
	}
}

func TestJWTRoundTrip(t *testing.T) {
	t.Parallel()
	a := New(nil, testCfg())
	tok, err := a.IssueJWT(42, 7, time.Hour)
	if err != nil {
		t.Fatalf("IssueJWT: %v", err)
	}
	claims, err := a.VerifyJWT(tok)
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}
	if claims.UserID != 42 || claims.OrgID != 7 {
		t.Errorf("claims = %+v, want uid 42 org 7", claims)
	}
}

func TestJWTExpiredRejected(t *testing.T) {
	t.Parallel()
	a := New(nil, testCfg())
	// Sign a token whose exp is already in the past (IssueJWT clamps ttl<=0 to
	// the default, so the expired token is minted directly).
	expired := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID: 1, OrgID: 1,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour))},
	})
	tok, err := expired.SignedString([]byte(testCfg().JWTSecret))
	if err != nil {
		t.Fatalf("sign expired: %v", err)
	}
	if _, err := a.VerifyJWT(tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestJWTAlgConfusionRejected(t *testing.T) {
	t.Parallel()
	a := New(nil, testCfg())
	// A token signed with "none" must be rejected (only HS256 is accepted).
	none := jwt.NewWithClaims(jwt.SigningMethodNone, Claims{UserID: 1, OrgID: 1})
	tok, err := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if _, err := a.VerifyJWT(tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestJWTWrongSecretRejected(t *testing.T) {
	t.Parallel()
	signer := New(nil, testCfg())
	tok, _ := signer.IssueJWT(1, 1, time.Hour)
	other := New(nil, config.AuthConfig{JWTSecret: "different-secret", JWTExpiry: time.Hour})
	if _, err := other.VerifyJWT(tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestJWTNotConfigured(t *testing.T) {
	t.Parallel()
	a := New(nil, config.AuthConfig{})
	if _, err := a.IssueJWT(1, 1, time.Hour); !errors.Is(err, ErrJWTNotConfigured) {
		t.Fatalf("err = %v, want ErrJWTNotConfigured", err)
	}
}
