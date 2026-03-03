package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
)

// -- New() tests --------------------------------------------------------------

func TestNew_DefaultsToInfoOnInvalidLevel(t *testing.T) {
	logger := New("not-a-level", false)

	if logger.GetLevel() != zerolog.InfoLevel {
		t.Errorf("expected InfoLevel for invalid level string, got %v", logger.GetLevel())
	}
}

func TestNew_SetsRequestedLevel(t *testing.T) {
	tests := []struct {
		input string
		want  zerolog.Level
	}{
		{"debug", zerolog.DebugLevel},
		{"info", zerolog.InfoLevel},
		{"warn", zerolog.WarnLevel},
		{"error", zerolog.ErrorLevel},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			logger := New(tt.input, false)
			if logger.GetLevel() != tt.want {
				t.Errorf("New(%q, false) level = %v, want %v", tt.input, logger.GetLevel(), tt.want)
			}
		})
	}
}

func TestNew_JSONOutputContainsServiceField(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf).With().Str("service", "cybersiren").Timestamp().Logger()
	logger.Info().Msg("hello")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log JSON: %v\nraw: %s", err, buf.String())
	}

	if entry["service"] != "cybersiren" {
		t.Errorf("service field = %v, want %q", entry["service"], "cybersiren")
	}
	if entry["message"] == nil && entry["msg"] == nil {
		t.Error("expected a message field in log output")
	}
}

func TestNew_PrettyDoesNotPanic(t *testing.T) {
	logger := New("debug", true)
	logger.Info().Msg("pretty mode test")
}

// -- SetGlobal() tests --------------------------------------------------------

func TestSetGlobal_DoesNotPanic(t *testing.T) {
	logger := New("info", false)
	SetGlobal(logger)
}

// -- Context helper tests -----------------------------------------------------

func bufLogger() (zerolog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf).With().Timestamp().Logger()
	return logger, &buf
}

func logAndParse(t *testing.T, ctx context.Context, buf *bytes.Buffer) map[string]interface{} {
	t.Helper()
	zerolog.Ctx(ctx).Info().Msg("test")
	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v\nraw: %s", err, buf.String())
	}
	return entry
}

func TestWithRequestID(t *testing.T) {
	logger, buf := bufLogger()
	ctx := logger.WithContext(context.Background())
	ctx = WithRequestID(ctx, "req-abc-123")
	entry := logAndParse(t, ctx, buf)
	if entry["request_id"] != "req-abc-123" {
		t.Errorf("request_id = %v, want %q", entry["request_id"], "req-abc-123")
	}
}

func TestWithOrgID(t *testing.T) {
	logger, buf := bufLogger()
	ctx := logger.WithContext(context.Background())
	ctx = WithOrgID(ctx, 42)
	entry := logAndParse(t, ctx, buf)
	if v, ok := entry["org_id"].(float64); !ok || int64(v) != 42 {
		t.Errorf("org_id = %v, want 42", entry["org_id"])
	}
}

func TestWithEmailID(t *testing.T) {
	logger, buf := bufLogger()
	ctx := logger.WithContext(context.Background())
	ctx = WithEmailID(ctx, 99)
	entry := logAndParse(t, ctx, buf)
	if v, ok := entry["email_id"].(float64); !ok || int64(v) != 99 {
		t.Errorf("email_id = %v, want 99", entry["email_id"])
	}
}

func TestWithJobID(t *testing.T) {
	logger, buf := bufLogger()
	ctx := logger.WithContext(context.Background())
	ctx = WithJobID(ctx, 7, "scan")
	entry := logAndParse(t, ctx, buf)
	if v, ok := entry["job_id"].(float64); !ok || int64(v) != 7 {
		t.Errorf("job_id = %v, want 7", entry["job_id"])
	}
	if entry["job_type"] != "scan" {
		t.Errorf("job_type = %v, want %q", entry["job_type"], "scan")
	}
}

func TestWithThreatID(t *testing.T) {
	logger, buf := bufLogger()
	ctx := logger.WithContext(context.Background())
	ctx = WithThreatID(ctx, 555)
	entry := logAndParse(t, ctx, buf)
	if v, ok := entry["threat_id"].(float64); !ok || int64(v) != 555 {
		t.Errorf("threat_id = %v, want 555", entry["threat_id"])
	}
}

func TestWithCampaignID(t *testing.T) {
	logger, buf := bufLogger()
	ctx := logger.WithContext(context.Background())
	ctx = WithCampaignID(ctx, 1001)
	entry := logAndParse(t, ctx, buf)
	if v, ok := entry["campaign_id"].(float64); !ok || int64(v) != 1001 {
		t.Errorf("campaign_id = %v, want 1001", entry["campaign_id"])
	}
}

func TestWithChainedContextFields(t *testing.T) {
	logger, buf := bufLogger()
	ctx := logger.WithContext(context.Background())
	ctx = WithRequestID(ctx, "req-xyz")
	ctx = WithOrgID(ctx, 10)
	ctx = WithEmailID(ctx, 20)
	entry := logAndParse(t, ctx, buf)
	if entry["request_id"] != "req-xyz" {
		t.Errorf("request_id = %v, want %q", entry["request_id"], "req-xyz")
	}
	if v, ok := entry["org_id"].(float64); !ok || int64(v) != 10 {
		t.Errorf("org_id = %v, want 10", entry["org_id"])
	}
	if v, ok := entry["email_id"].(float64); !ok || int64(v) != 20 {
		t.Errorf("email_id = %v, want 20", entry["email_id"])
	}
}

func TestLoggerFromContext_FallsBackToGlobal(t *testing.T) {
	ctx := context.Background()
	l := loggerFromContext(ctx)
	if l == nil {
		t.Fatal("loggerFromContext returned nil for empty context")
	}
	l.Info().Msg("fallback test")
}
