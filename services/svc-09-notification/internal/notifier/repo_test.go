package notifier

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestParseChannels(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"null column", "", nil},
		{"empty array", "[]", nil},
		{"webhook only", `["webhook"]`, []string{"webhook"}},
		{"email and webhook", `["email","webhook"]`, []string{"email", "webhook"}},
		{"mixed case trimmed", `[" Email ","WEBHOOK"]`, []string{"email", "webhook"}},
		{"slack passes through (ignored later)", `["slack"]`, []string{"slack"}},
		{"empty strings dropped", `["", "email"]`, []string{"email"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseChannels([]byte(tc.raw))
			if err != nil {
				t.Fatalf("parseChannels(%q) error: %v", tc.raw, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("parseChannels(%q) = %v, want %v", tc.raw, got, tc.want)
			}
			for _, w := range tc.want {
				if _, ok := got[w]; !ok {
					t.Errorf("parseChannels(%q) missing %q", tc.raw, w)
				}
			}
		})
	}
}

func TestParseChannelsInvalidJSON(t *testing.T) {
	t.Parallel()
	if _, err := parseChannels([]byte(`{"not":"an array"}`)); err == nil {
		t.Fatal("expected error on non-array JSON, got nil")
	}
}

func TestOrgPrefsHasChannel(t *testing.T) {
	t.Parallel()
	p := OrgPrefs{Channels: map[string]struct{}{ChannelWebhook: {}}}
	if !p.HasChannel(ChannelWebhook) {
		t.Error("expected webhook channel present")
	}
	if p.HasChannel(ChannelEmail) {
		t.Error("did not expect email channel")
	}
}

func TestPGOrgReaderNilPool(t *testing.T) {
	t.Parallel()
	r := NewPGOrgReader(nil)
	if _, err := r.Load(context.Background(), 1); err == nil {
		t.Fatal("expected error from nil-pool reader, got nil")
	}
}

// TestPGOrgReaderLoad_Live exercises the real sqlc reads against Postgres. It is
// a DB-integration test: it skips under -short (the batch self-check) and only
// connects when APP_DATABASE_URL is set, matching the repo's integration-test
// convention. The full suite runs it at the batch gate under `make test` with
// infra up.
func TestPGOrgReaderLoad_Live(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DB-integration test under -short")
	}
	dsn := os.Getenv("APP_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APP_DATABASE_URL to run the live org-reader test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	r := NewPGOrgReader(pool)
	// Org id 1 is the seeded demo org in the dev migrations; tolerate its
	// absence so the test is robust across seed states.
	prefs, err := r.Load(ctx, 1)
	if err == ErrOrgNotFound {
		t.Skip("seed org 1 not present; nothing to assert")
	}
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if prefs.OrgID != 1 {
		t.Errorf("OrgID = %d, want 1", prefs.OrgID)
	}
	if prefs.Threshold < 0 || prefs.Threshold > 100 {
		t.Errorf("Threshold = %d, want within [0,100]", prefs.Threshold)
	}
}
