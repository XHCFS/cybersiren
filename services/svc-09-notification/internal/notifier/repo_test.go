package notifier

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

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
			got := parseChannels([]byte(tc.raw))
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

// TestParseChannelsUndecodableOptsOut covers the F3 poison-message fix: a
// notification_channels column that is valid JSONB but not a []string must NOT
// surface as an error (which Load would propagate and Handle would map to a
// NACK, wedging the partition forever on one bad org row). Instead the org is
// opted out — an empty channel set, no error — exactly like the NULL/empty
// case, so the offset commits.
func TestParseChannelsUndecodableOptsOut(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		`{"not":"an array"}`, // JSON object
		`{"email":true}`,     // object keyed by channel
		`"email"`,            // bare string, not an array
		`42`,                 // number
		`true`,               // bool
	} {
		got := parseChannels([]byte(raw))
		if len(got) != 0 {
			t.Errorf("parseChannels(%q) = %v, want empty set (opt-out)", raw, got)
		}
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

// TestPGOrgReaderLoad_MalformedChannels is the F3 fix end-to-end at the Load
// seam: an org whose notification_channels is valid JSONB but not a []string
// (here an object {"email":true}) must Load with NO error and an empty channel
// set. That is what lets Handle COMMIT the offset instead of NACKing forever on
// the poison row. DB-integration test: skips under -short and without
// APP_DATABASE_URL, runs at the batch gate with infra up. It seeds and removes
// its own throwaway org so it does not depend on or mutate seed data.
func TestPGOrgReaderLoad_MalformedChannels(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DB-integration test under -short")
	}
	dsn := os.Getenv("APP_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APP_DATABASE_URL to run the live malformed-channels test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	// Seed a throwaway org with a deliberately malformed notification_channels
	// (an object, not a string array). A unique slug avoids collisions with
	// other runs / seed data.
	slug := fmt.Sprintf("svc09-f3-%d", time.Now().UnixNano())
	var orgID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO organisations (name, slug, notification_channels)
		 VALUES ($1, $1, '{"email":true}'::jsonb)
		 RETURNING id`, slug,
	).Scan(&orgID); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organisations WHERE id = $1`, orgID)
	})

	prefs, err := NewPGOrgReader(pool).Load(ctx, orgID)
	if err != nil {
		t.Fatalf("Load with malformed notification_channels returned error %v; Handle would NACK and wedge the partition", err)
	}
	if len(prefs.Channels) != 0 {
		t.Errorf("Channels = %v, want empty set (org opted out on undecodable column)", prefs.Channels)
	}
	if prefs.OrgID != orgID {
		t.Errorf("OrgID = %d, want %d", prefs.OrgID, orgID)
	}
}
