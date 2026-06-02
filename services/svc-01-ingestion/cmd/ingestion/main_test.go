package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/saif/cybersiren/shared/config"
)

func TestParseIngestJSON(t *testing.T) {
	t.Parallel()
	body := `{"message_id":"<a@x>","raw_message_b64":"Zm9v","source_adapter":"test"}`
	r := httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	req, err := parseIngest(r)
	if err != nil {
		t.Fatalf("parseIngest: %v", err)
	}
	if req.MessageID != "<a@x>" || req.RawMessageB64 != "Zm9v" || req.SourceAdapter != "test" {
		t.Errorf("parsed = %+v", req)
	}
}

func TestParseIngestMultipart(t *testing.T) {
	t.Parallel()
	raw := []byte("From: a@example.com\r\nSubject: hi\r\n\r\nbody")
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("email", "msg.eml")
	_, _ = fw.Write(raw)
	_ = mw.WriteField("message_id", "<m1@x>")
	_ = mw.WriteField("source_adapter", "upload")
	_ = mw.Close()

	r := httptest.NewRequest(http.MethodPost, "/ingest", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())

	req, err := parseIngest(r)
	if err != nil {
		t.Fatalf("parseIngest multipart: %v", err)
	}
	if req.MessageID != "<m1@x>" || req.SourceAdapter != "upload" {
		t.Errorf("form fields = %+v", req)
	}
	if got, _ := base64.StdEncoding.DecodeString(req.RawMessageB64); !bytes.Equal(got, raw) {
		t.Errorf("decoded upload = %q, want %q", got, raw)
	}
}

func TestParseIngestMultipartMissingFile(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("message_id", "<m@x>")
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/ingest", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())

	if _, err := parseIngest(r); err == nil {
		t.Fatal("expected error for missing email file field")
	}
}

// TestRegisterIdentityDedup verifies the DB dedup fallback: the first
// (org, message_id) is new, the second is a duplicate. Skipped in -short/no-DB;
// runs in CI Integration.
func TestRegisterIdentityDedup(t *testing.T) {
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
		`INSERT INTO organisations (name, slug) VALUES ($1,$2) RETURNING id`,
		fmt.Sprintf("dedup-test-%d", uniq), fmt.Sprintf("dedup-test-%d", uniq)).Scan(&orgID); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	defer pool.Exec(context.Background(), `DELETE FROM organisations WHERE id=$1`, orgID) //nolint:errcheck

	msgID := fmt.Sprintf("<dedup-%d@x>", uniq)
	now := time.Now().UTC()

	dup, err := registerIdentity(ctx, pool, orgID, msgID, uniq, now)
	if err != nil || dup {
		t.Fatalf("first call: dup=%v err=%v, want new", dup, err)
	}
	dup, err = registerIdentity(ctx, pool, orgID, msgID, uniq, now)
	if err != nil || !dup {
		t.Fatalf("second call: dup=%v err=%v, want duplicate", dup, err)
	}
}
