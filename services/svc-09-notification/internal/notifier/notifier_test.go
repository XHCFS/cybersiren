package notifier

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/shared/config"
)

func TestShouldNotify(t *testing.T) {
	t.Parallel()
	cases := []struct {
		label           string
		risk, threshold int
		want            bool
	}{
		{"phishing", 0, 70, true},    // high-severity label always alerts
		{"malware", 10, 90, true},    // high-severity ignores threshold
		{"suspicious", 70, 70, true}, // meets threshold
		{"suspicious", 69, 70, false},
		{"benign", 100, 70, true}, // score overrides a benign label
		{"benign", 50, 70, false},
	}
	for _, c := range cases {
		if got := ShouldNotify(c.label, c.risk, c.threshold); got != c.want {
			t.Errorf("ShouldNotify(%q,%d,%d) = %v, want %v", c.label, c.risk, c.threshold, got, c.want)
		}
	}
}

func TestParseChannels(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []byte
		want []string
	}{
		{"nil → default", nil, []string{"webhook"}},
		{"empty array → default", []byte(`[]`), []string{"webhook"}},
		{"malformed → default", []byte(`{`), []string{"webhook"}},
		{"explicit", []byte(`["email","slack"]`), []string{"email", "slack"}},
	}
	for _, c := range cases {
		if got := parseChannels(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: parseChannels = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestConfigAndRecipientQueries DB-gates the two sqlc lookups. Skipped in
// -short / no-DB; runs in CI Integration.
func TestConfigAndRecipientQueries(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DB integration test in -short mode")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Skipf("config load failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, cfg.DB.DSN())
	if err != nil {
		t.Skipf("no DB pool: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("DB not reachable: %v", err)
	}

	uniq := time.Now().UnixNano()
	var orgID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO organisations (name, slug, notification_threshold, notification_channels)
		 VALUES ($1,$2,55,'["email","webhook"]'::jsonb) RETURNING id`,
		fmt.Sprintf("notif-test-%d", uniq), fmt.Sprintf("notif-test-%d", uniq)).Scan(&orgID); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	defer pool.Exec(context.Background(), `DELETE FROM organisations WHERE id=$1`, orgID) //nolint:errcheck

	if _, err := pool.Exec(ctx,
		`INSERT INTO users (org_id, email, role) VALUES ($1,$2,'admin'::user_role), ($1,$3,'viewer'::user_role)`,
		orgID, fmt.Sprintf("admin-%d@x.test", uniq), fmt.Sprintf("viewer-%d@x.test", uniq)); err != nil {
		t.Fatalf("seed users: %v", err)
	}

	q := dbsqlc.New(pool)
	cfgRow, err := q.GetOrgNotificationConfig(ctx, orgID)
	if err != nil {
		t.Fatalf("GetOrgNotificationConfig: %v", err)
	}
	if !cfgRow.NotificationThreshold.Valid || cfgRow.NotificationThreshold.Int32 != 55 {
		t.Errorf("threshold = %+v, want 55", cfgRow.NotificationThreshold)
	}
	if ch := parseChannels(cfgRow.NotificationChannels); !reflect.DeepEqual(ch, []string{"email", "webhook"}) {
		t.Errorf("channels = %v, want [email webhook]", ch)
	}

	admins, err := q.ListOrgAdminEmails(ctx, orgID)
	if err != nil {
		t.Fatalf("ListOrgAdminEmails: %v", err)
	}
	if len(admins) != 1 || admins[0] != fmt.Sprintf("admin-%d@x.test", uniq) {
		t.Errorf("admins = %v, want only the admin email", admins)
	}
}
