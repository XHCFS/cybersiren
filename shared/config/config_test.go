package config

import (
	"math"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// -- helpers ------------------------------------------------------------------

// validConfig returns a minimal Config that passes validate().
// Tests mutate specific fields to trigger individual validation errors.
func validConfig() *Config {
	return &Config{
		Env: "development",
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         8080,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		DB: DBConfig{
			Host:              "localhost",
			Port:              5432,
			Name:              "testdb",
			User:              "testuser",
			Password:          "testpass",
			SSLMode:           "disable",
			MaxConns:          20,
			MinConns:          2,
			MaxConnLifetime:   time.Hour,
			MaxConnIdleTime:   30 * time.Minute,
			HealthCheckPeriod: time.Minute,
		},
		Auth: AuthConfig{
			JWTSecret:       "a]long-secret-for-testing-32chars!",
			JWTExpiry:       24 * time.Hour,
			BcryptCost:      12,
			APIKeyPrefix:    "cs_",
			APIKeyPrefixLen: 32,
		},
		Log: LogConfig{
			Level:  "info",
			Pretty: false,
		},
		MetricsPort:             9090,
		FeedPhishTankAPIKey:     "test-phishtank-key",
		SyncIntervalSeconds:     3600,
		TIDomainCacheTTLSeconds: 7200,
		Enrichment: EnrichmentConfig{
			WorkerCount: 10,
			JobTimeout:  30 * time.Second,
			MaxRetries:  3,
			VirusTotal:  VirusTotalConfig{Timeout: 20 * time.Second},
			IPInfo:      IPInfoConfig{Timeout: 10 * time.Second},
			WHOIS:       WHOISConfig{Timeout: 15 * time.Second},
			URLScan:     URLScanConfig{Timeout: 30 * time.Second},
			Screenshot:  ScreenshotConfig{Timeout: 20 * time.Second},
		},
		Embedding: EmbeddingConfig{
			Provider:  "openai",
			Model:     "text-embedding-3-small",
			Dimension: 1536,
			BaseURL:   "https://api.openai.com/v1",
		},
	}
}

// clearCybersirenEnv unsets CYBERSIREN_* env vars that CI may inject, so tests
// that rely on a clean environment (e.g. YAML-wins-over-env, missing-required)
// are not polluted by the integration job's database credentials.
func clearCybersirenEnv(t *testing.T) {
	t.Helper()
	keys := []string{
		"CYBERSIREN_DB__HOST", "CYBERSIREN_DB__PORT",
		"CYBERSIREN_DB__NAME", "CYBERSIREN_DB__USER",
		"CYBERSIREN_DB__PASSWORD", "CYBERSIREN_DB__SSLMODE",
		"CYBERSIREN_AUTH__JWT_SECRET", "CYBERSIREN_CONFIG_PATH",
	}
	for _, k := range keys {
		if orig, ok := os.LookupEnv(k); ok {
			os.Unsetenv(k)
			k := k
			orig := orig
			t.Cleanup(func() { os.Setenv(k, orig) })
		}
	}
}

// setRequiredEnv sets the minimum env vars needed for Load() to pass validation.
func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CYBERSIREN_DB__NAME", "testdb")
	t.Setenv("CYBERSIREN_DB__USER", "testuser")
	t.Setenv("CYBERSIREN_DB__PASSWORD", "testpassword")
	t.Setenv("CYBERSIREN_AUTH__JWT_SECRET", "test-secret-which-is-long-enough")
	t.Setenv("CYBERSIREN_CONFIG_PATH", "./nonexistent-config.yaml")
}

// -- DSN tests ----------------------------------------------------------------

func TestDSN_BasicOutput(t *testing.T) {
	db := DBConfig{
		Host:     "localhost",
		Port:     5432,
		Name:     "mydb",
		User:     "admin",
		Password: "secret",
		SSLMode:  "disable",
	}

	got := db.DSN()
	want := "postgres://admin:secret@localhost:5432/mydb?sslmode=disable"
	if got != want {
		t.Errorf("DSN() = %q, want %q", got, want)
	}
}

func TestDSN_SpecialCharactersInPassword(t *testing.T) {
	db := DBConfig{
		Host:     "db.example.com",
		Port:     5432,
		Name:     "prod",
		User:     "app",
		Password: "p@ss:word/with#special&chars=yes",
		SSLMode:  "require",
	}

	got := db.DSN()

	// Verify the DSN can be parsed back and credentials round-trip correctly.
	parsed, err := parsePostgresDSN(got)
	if err != nil {
		t.Fatalf("DSN() produced unparseable URL: %v\n  DSN: %s", err, got)
	}

	if parsed.user != "app" {
		t.Errorf("parsed user = %q, want %q", parsed.user, "app")
	}
	if parsed.password != "p@ss:word/with#special&chars=yes" {
		t.Errorf("parsed password = %q, want %q", parsed.password, "p@ss:word/with#special&chars=yes")
	}
	if parsed.host != "db.example.com:5432" {
		t.Errorf("parsed host = %q, want %q", parsed.host, "db.example.com:5432")
	}
	if parsed.dbname != "prod" {
		t.Errorf("parsed dbname = %q, want %q", parsed.dbname, "prod")
	}
	if parsed.sslmode != "require" {
		t.Errorf("parsed sslmode = %q, want %q", parsed.sslmode, "require")
	}
}

func TestDSN_NoSSLMode(t *testing.T) {
	db := DBConfig{
		Host:     "localhost",
		Port:     5432,
		Name:     "testdb",
		User:     "user",
		Password: "pass",
		SSLMode:  "",
	}

	got := db.DSN()
	// No query string at all when SSLMode is empty.
	if strings.Contains(got, "sslmode") {
		t.Errorf("DSN() should omit sslmode when empty, got %q", got)
	}
}

// parsedDSN holds fields extracted from a postgres:// URL for test assertions.
type parsedDSN struct {
	user, password, host, dbname, sslmode string
}

func parsePostgresDSN(raw string) (parsedDSN, error) {
	u, err := parseURL(raw)
	if err != nil {
		return parsedDSN{}, err
	}
	pass, _ := u.User.Password()
	return parsedDSN{
		user:     u.User.Username(),
		password: pass,
		host:     u.Host,
		dbname:   strings.TrimPrefix(u.Path, "/"),
		sslmode:  u.Query().Get("sslmode"),
	}, nil
}

// parseURL wraps url.Parse — trivial, but keeps test helpers self-contained.
func parseURL(raw string) (*url.URL, error) {
	return url.Parse(raw)
}

// -- validate() tests ---------------------------------------------------------

func TestValidate_ValidConfig(t *testing.T) {
	cfg := validConfig()
	if err := validate(cfg); err != nil {
		t.Fatalf("expected valid config to pass validation, got: %v", err)
	}
}

func TestValidate_MissingRequiredValues(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"missing db.name", func(c *Config) { c.DB.Name = "" }, "db.name"},
		{"missing db.user", func(c *Config) { c.DB.User = "" }, "db.user"},
		{"missing db.password", func(c *Config) { c.DB.Password = "" }, "db.password"},
		{"missing jwt_secret", func(c *Config) { c.Auth.JWTSecret = "" }, "auth.jwt_secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(cfg)

			err := validate(cfg)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestValidate_AllMissingRequired(t *testing.T) {
	cfg := validConfig()
	cfg.DB.Name = ""
	cfg.DB.User = ""
	cfg.DB.Password = ""
	cfg.Auth.JWTSecret = ""

	err := validate(cfg)
	if err == nil {
		t.Fatal("expected error for all missing required, got nil")
	}
	// All four should be reported in a single error.
	for _, key := range []string{"db.name", "db.user", "db.password", "auth.jwt_secret"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error should mention %q, got: %v", key, err)
		}
	}
}

func TestValidate_InvalidValues(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		// env
		{"invalid env", func(c *Config) { c.Env = "invalid" }, "env must be one of"},
		// ssl_mode
		{"invalid ssl mode", func(c *Config) { c.DB.SSLMode = "bogus" }, "db.ssl_mode must be one of"},
		// embedding
		{"zero embedding dimension", func(c *Config) { c.Embedding.Dimension = 0 }, "embedding.dimension must be greater than 0"},
		{"negative embedding dimension", func(c *Config) { c.Embedding.Dimension = -1 }, "embedding.dimension must be greater than 0"},
		// auth
		{"jwt_secret too short", func(c *Config) { c.Auth.JWTSecret = "short-secret" }, "auth.jwt_secret must be at least"},
		{"api_key_prefix_len zero", func(c *Config) { c.Auth.APIKeyPrefixLen = 0 }, "auth.api_key_prefix_len must be greater than"},
		{"api_key_prefix_len at floor", func(c *Config) { c.Auth.APIKeyPrefixLen = 8 }, "auth.api_key_prefix_len must be greater than"},
		{"api_key prefix+len exceeds bcrypt limit", func(c *Config) { c.Auth.APIKeyPrefix = "cs_"; c.Auth.APIKeyPrefixLen = 70 }, "must not exceed"},
		{"bcrypt_cost too low", func(c *Config) { c.Auth.BcryptCost = 3 }, "auth.bcrypt_cost must be between 4 and 31"},
		{"bcrypt_cost too high", func(c *Config) { c.Auth.BcryptCost = 32 }, "auth.bcrypt_cost must be between 4 and 31"},
		// server
		{"server port 0", func(c *Config) { c.Server.Port = 0 }, "server.port must be between 1 and 65535"},
		{"server port too high", func(c *Config) { c.Server.Port = 70000 }, "server.port must be between 1 and 65535"},
		{"server read_timeout zero", func(c *Config) { c.Server.ReadTimeout = 0 }, "server.read_timeout must be greater than 0"},
		{"server write_timeout zero", func(c *Config) { c.Server.WriteTimeout = 0 }, "server.write_timeout must be greater than 0"},
		{"server idle_timeout zero", func(c *Config) { c.Server.IdleTimeout = 0 }, "server.idle_timeout must be greater than 0"},
		// db
		{"db port 0", func(c *Config) { c.DB.Port = 0 }, "db.port must be between 1 and 65535"},
		{"db max_conns 0", func(c *Config) { c.DB.MaxConns = 0 }, "db.max_conns must be greater than 0"},
		{"db min_conns negative", func(c *Config) { c.DB.MinConns = -1 }, "db.min_conns must be greater than or equal to 0"},
		{"db min > max conns", func(c *Config) { c.DB.MinConns = 30; c.DB.MaxConns = 5 }, "db.min_conns (30) cannot be greater than db.max_conns (5)"},
		{"db max_conn_lifetime zero", func(c *Config) { c.DB.MaxConnLifetime = 0 }, "db.max_conn_lifetime must be greater than 0"},
		{"db max_conn_idle_time zero", func(c *Config) { c.DB.MaxConnIdleTime = 0 }, "db.max_conn_idle_time must be greater than 0"},
		{"db health_check_period zero", func(c *Config) { c.DB.HealthCheckPeriod = 0 }, "db.health_check_period must be greater than 0"},
		// enrichment
		{"enrichment worker_count 0", func(c *Config) { c.Enrichment.WorkerCount = 0 }, "enrichment.worker_count must be greater than 0"},
		{"enrichment job_timeout 0", func(c *Config) { c.Enrichment.JobTimeout = 0 }, "enrichment.job_timeout must be greater than 0"},
		{"enrichment max_retries negative", func(c *Config) { c.Enrichment.MaxRetries = -1 }, "enrichment.max_retries must be greater than or equal to 0"},
		{"enrichment vt timeout 0", func(c *Config) { c.Enrichment.VirusTotal.Timeout = 0 }, "enrichment.virustotal.timeout must be greater than 0"},
		{"enrichment ipinfo timeout 0", func(c *Config) { c.Enrichment.IPInfo.Timeout = 0 }, "enrichment.ipinfo.timeout must be greater than 0"},
		{"enrichment whois timeout 0", func(c *Config) { c.Enrichment.WHOIS.Timeout = 0 }, "enrichment.whois.timeout must be greater than 0"},
		{"enrichment urlscan timeout 0", func(c *Config) { c.Enrichment.URLScan.Timeout = 0 }, "enrichment.urlscan.timeout must be greater than 0"},
		{"enrichment screenshot timeout 0", func(c *Config) { c.Enrichment.Screenshot.Timeout = 0 }, "enrichment.screenshot.timeout must be greater than 0"},
		// ti domain cache TTL — must be positive and have headroom over the sync interval.
		{"ti domain cache ttl 0", func(c *Config) { c.TIDomainCacheTTLSeconds = 0 }, "ti_domain_cache_ttl_seconds must be greater than 0"},
		{"ti domain cache ttl below interval", func(c *Config) { c.TIDomainCacheTTLSeconds = 1800 }, "ti_domain_cache_ttl_seconds (1800) should be >= sync_interval_seconds"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(cfg)

			err := validate(cfg)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

// -- Load() tests -------------------------------------------------------------

func TestLoad_Defaults(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	// Spot-check that defaults are applied when no YAML or extra env vars exist.
	if cfg.Env != "development" {
		t.Errorf("default Env = %q, want %q", cfg.Env, "development")
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("default Server.Port = %d, want %d", cfg.Server.Port, 8080)
	}
	if cfg.Server.ReadTimeout != 15*time.Second {
		t.Errorf("default Server.ReadTimeout = %v, want %v", cfg.Server.ReadTimeout, 15*time.Second)
	}
	if cfg.DB.Host != "localhost" {
		t.Errorf("default DB.Host = %q, want %q", cfg.DB.Host, "localhost")
	}
	if cfg.DB.Port != 5432 {
		t.Errorf("default DB.Port = %d, want %d", cfg.DB.Port, 5432)
	}
	if cfg.DB.MaxConns != 20 {
		t.Errorf("default DB.MaxConns = %d, want %d", cfg.DB.MaxConns, 20)
	}
	if cfg.Auth.BcryptCost != 12 {
		t.Errorf("default Auth.BcryptCost = %d, want %d", cfg.Auth.BcryptCost, 12)
	}
	if cfg.Auth.APIKeyPrefix != "cs_" {
		t.Errorf("default Auth.APIKeyPrefix = %q, want %q", cfg.Auth.APIKeyPrefix, "cs_")
	}
	// The default random suffix must comfortably exceed the auth package's lookup
	// window so the stored key_prefix never reveals the full key.
	if cfg.Auth.APIKeyPrefixLen != 32 {
		t.Errorf("default Auth.APIKeyPrefixLen = %d, want %d", cfg.Auth.APIKeyPrefixLen, 32)
	}
	if cfg.Enrichment.WorkerCount != 10 {
		t.Errorf("default Enrichment.WorkerCount = %d, want %d", cfg.Enrichment.WorkerCount, 10)
	}
	if cfg.Embedding.Dimension != 1536 {
		t.Errorf("default Embedding.Dimension = %d, want %d", cfg.Embedding.Dimension, 1536)
	}
	// Domain cache TTL defaults to twice the sync interval so blocklisted domains
	// never expire from the cache in the window between two refreshes.
	if cfg.TIDomainCacheTTLSeconds != 7200 {
		t.Errorf("default TIDomainCacheTTLSeconds = %d, want %d", cfg.TIDomainCacheTTLSeconds, 7200)
	}
	if cfg.SyncIntervalSeconds != 3600 {
		t.Errorf("default SyncIntervalSeconds = %d, want %d", cfg.SyncIntervalSeconds, 3600)
	}
}

func TestLoad_EnvOverridesWithDoubleUnderscore(t *testing.T) {
	t.Setenv("CYBERSIREN_DB__NAME", "env_db")
	t.Setenv("CYBERSIREN_DB__USER", "env_user")
	t.Setenv("CYBERSIREN_DB__PASSWORD", "env_password")
	t.Setenv("CYBERSIREN_AUTH__JWT_SECRET", "supersecret-that-is-long-enough-now")
	t.Setenv("CYBERSIREN_CONFIG_PATH", "./nonexistent-config.yaml")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.DB.Name != "env_db" {
		t.Errorf("expected DB.Name from env to be %q, got %q", "env_db", cfg.DB.Name)
	}
	if cfg.DB.User != "env_user" {
		t.Errorf("expected DB.User from env to be %q, got %q", "env_user", cfg.DB.User)
	}
	if cfg.DB.Password != "env_password" {
		t.Errorf("expected DB.Password from env to be %q, got %q", "env_password", cfg.DB.Password)
	}
	if cfg.Auth.JWTSecret != "supersecret-that-is-long-enough-now" {
		t.Errorf("expected Auth.JWTSecret from env to be %q, got %q", "supersecret-that-is-long-enough-now", cfg.Auth.JWTSecret)
	}
}

func TestLoad_DeepNestedEnvOverride(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("CYBERSIREN_ENRICHMENT__VIRUSTOTAL__TIMEOUT", "99s")
	t.Setenv("CYBERSIREN_SERVER__PORT", "9090")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.Enrichment.VirusTotal.Timeout != 99*time.Second {
		t.Errorf("VirusTotal.Timeout = %v, want 99s", cfg.Enrichment.VirusTotal.Timeout)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("Server.Port = %d, want 9090", cfg.Server.Port)
	}
}

func TestLoad_TopLevelEnvOverride(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("CYBERSIREN_ENV", "production")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.Env != "production" {
		t.Errorf("Env = %q, want %q", cfg.Env, "production")
	}
}

func TestLoad_YAMLFile(t *testing.T) {
	clearCybersirenEnv(t)
	// Write a minimal YAML config to a temp file and verify it's loaded.
	yamlContent := `
env: staging
db:
  name: yaml_db
  user: yaml_user
  password: yaml_pass
  host: yaml-host
  port: 5433
  ssl_mode: require
  max_conns: 50
  min_conns: 5
  max_conn_lifetime: 2h
  max_conn_idle_time: 1h
  health_check_period: 5m
auth:
  jwt_secret: yaml-jwt-secret-long-enough-padded
  bcrypt_cost: 10
  api_key_prefix: "yk_"
  api_key_prefix_len: 12
`
	tmpFile := t.TempDir() + "/config.yaml"
	if err := writeFile(tmpFile, yamlContent); err != nil {
		t.Fatalf("writing temp YAML: %v", err)
	}
	t.Setenv("CYBERSIREN_CONFIG_PATH", tmpFile)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.Env != "staging" {
		t.Errorf("Env = %q, want %q", cfg.Env, "staging")
	}
	if cfg.DB.Name != "yaml_db" {
		t.Errorf("DB.Name = %q, want %q", cfg.DB.Name, "yaml_db")
	}
	if cfg.DB.Port != 5433 {
		t.Errorf("DB.Port = %d, want %d", cfg.DB.Port, 5433)
	}
	if cfg.Auth.APIKeyPrefix != "yk_" {
		t.Errorf("Auth.APIKeyPrefix = %q, want %q", cfg.Auth.APIKeyPrefix, "yk_")
	}
}

func TestLoad_EnvOverridesYAML(t *testing.T) {
	clearCybersirenEnv(t)
	yamlContent := `
env: staging
db:
  name: yaml_db
  user: yaml_user
  password: yaml_pass
  host: localhost
  port: 5432
  ssl_mode: disable
  max_conns: 20
  min_conns: 2
  max_conn_lifetime: 1h
  max_conn_idle_time: 30m
  health_check_period: 1m
auth:
  jwt_secret: yaml-jwt-secret-long-enough-padded
  bcrypt_cost: 10
  api_key_prefix: "yk_"
  api_key_prefix_len: 12
`
	tmpFile := t.TempDir() + "/config.yaml"
	if err := writeFile(tmpFile, yamlContent); err != nil {
		t.Fatalf("writing temp YAML: %v", err)
	}
	t.Setenv("CYBERSIREN_CONFIG_PATH", tmpFile)

	// Env should override YAML.
	t.Setenv("CYBERSIREN_DB__NAME", "env_override_db")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.DB.Name != "env_override_db" {
		t.Errorf("DB.Name = %q, want env override %q", cfg.DB.Name, "env_override_db")
	}
	// YAML value should still be used for fields not overridden.
	if cfg.DB.User != "yaml_user" {
		t.Errorf("DB.User = %q, want YAML value %q", cfg.DB.User, "yaml_user")
	}
}

func TestLoad_MissingRequiredFails(t *testing.T) {
	clearCybersirenEnv(t)
	t.Setenv("CYBERSIREN_CONFIG_PATH", "./nonexistent-config.yaml")
	// Don't set any required env vars — Load should return an error.
	_, err := Load()
	if err == nil {
		t.Fatal("expected Load() to fail when required values are missing")
	}
	if !strings.Contains(err.Error(), "missing required config values") {
		t.Errorf("unexpected error: %v", err)
	}
}

// writeFile is a small test helper.
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

// -- Attachment / Notification / Gmail defaults -------------------------------

func TestLoad_AttachmentNotificationGmailDefaults(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	// Attachment defaults (ARCH-SPEC §1-step3c).
	if cfg.Attachment.VTCacheTTL != 24*time.Hour {
		t.Errorf("Attachment.VTCacheTTL = %v, want 24h", cfg.Attachment.VTCacheTTL)
	}
	if cfg.Attachment.EntropyThreshold != 7.5 {
		t.Errorf("Attachment.EntropyThreshold = %v, want 7.5", cfg.Attachment.EntropyThreshold)
	}
	if cfg.Attachment.MaliciousHashScore != 90 {
		t.Errorf("Attachment.MaliciousHashScore = %d, want 90", cfg.Attachment.MaliciousHashScore)
	}
	if cfg.Attachment.DoubleExtScore != 35 {
		t.Errorf("Attachment.DoubleExtScore = %d, want 35", cfg.Attachment.DoubleExtScore)
	}
	if cfg.Attachment.ConsumeTopic != "analysis.attachments" {
		t.Errorf("Attachment.ConsumeTopic = %q, want %q", cfg.Attachment.ConsumeTopic, "analysis.attachments")
	}
	if cfg.Attachment.ProduceTopic != "scores.attachment" {
		t.Errorf("Attachment.ProduceTopic = %q, want %q", cfg.Attachment.ProduceTopic, "scores.attachment")
	}

	// Notification defaults — both channels off, sane transport defaults.
	if cfg.Notification.SMTP.Enabled {
		t.Errorf("Notification.SMTP.Enabled = true, want false by default")
	}
	if cfg.Notification.SMTP.Port != 587 {
		t.Errorf("Notification.SMTP.Port = %d, want 587", cfg.Notification.SMTP.Port)
	}
	if !cfg.Notification.SMTP.StartTLS {
		t.Errorf("Notification.SMTP.StartTLS = false, want true by default")
	}
	if cfg.Notification.SMTP.Timeout != 10*time.Second {
		t.Errorf("Notification.SMTP.Timeout = %v, want 10s", cfg.Notification.SMTP.Timeout)
	}
	if cfg.Notification.Webhook.Enabled {
		t.Errorf("Notification.Webhook.Enabled = true, want false by default")
	}
	if cfg.Notification.Webhook.MaxRetries != 3 {
		t.Errorf("Notification.Webhook.MaxRetries = %d, want 3", cfg.Notification.Webhook.MaxRetries)
	}

	// Gmail defaults — adapter off, gmail.readonly scope, 5m fallback poll.
	if cfg.Gmail.Enabled {
		t.Errorf("Gmail.Enabled = true, want false by default")
	}
	if cfg.Gmail.PollInterval != 5*time.Minute {
		t.Errorf("Gmail.PollInterval = %v, want 5m", cfg.Gmail.PollInterval)
	}
	if len(cfg.Gmail.Scopes) != 1 || cfg.Gmail.Scopes[0] != "https://www.googleapis.com/auth/gmail.readonly" {
		t.Errorf("Gmail.Scopes = %v, want [gmail.readonly]", cfg.Gmail.Scopes)
	}
	// Watched mailbox defaults to "me" (the authenticated user) per ARCH-SPEC §2.1.
	if cfg.Gmail.User != "me" {
		t.Errorf("Gmail.User = %q, want %q", cfg.Gmail.User, "me")
	}
	// watch() reacts to the INBOX label by default.
	if len(cfg.Gmail.LabelIDs) != 1 || cfg.Gmail.LabelIDs[0] != "INBOX" {
		t.Errorf("Gmail.LabelIDs = %v, want [INBOX]", cfg.Gmail.LabelIDs)
	}
	// Both delivery paths are enabled by default (push webhook + fallback poll).
	if !cfg.Gmail.PushEnabled {
		t.Errorf("Gmail.PushEnabled = false, want true by default")
	}
	if !cfg.Gmail.PollEnabled {
		t.Errorf("Gmail.PollEnabled = false, want true by default")
	}
	// Each Gmail API round-trip is bounded at 30s by default.
	if cfg.Gmail.HTTPTimeout != 30*time.Second {
		t.Errorf("Gmail.HTTPTimeout = %v, want 30s", cfg.Gmail.HTTPTimeout)
	}
}

func TestLoad_AttachmentNotificationGmailEnvOverride(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("CYBERSIREN_ATTACHMENT__VT_CACHE_TTL", "1h")
	t.Setenv("CYBERSIREN_ATTACHMENT__DOUBLE_EXT_SCORE", "40")
	t.Setenv("CYBERSIREN_NOTIFICATION__SMTP__ENABLED", "true")
	t.Setenv("CYBERSIREN_NOTIFICATION__SMTP__HOST", "smtp.example.com")
	t.Setenv("CYBERSIREN_NOTIFICATION__SMTP__FROM", "alerts@example.com")
	t.Setenv("CYBERSIREN_NOTIFICATION__WEBHOOK__URL", "https://hook.example.com/in")
	t.Setenv("CYBERSIREN_GMAIL__ENABLED", "true")
	t.Setenv("CYBERSIREN_GMAIL__CLIENT_ID", "client-123")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.Attachment.VTCacheTTL != time.Hour {
		t.Errorf("Attachment.VTCacheTTL = %v, want 1h", cfg.Attachment.VTCacheTTL)
	}
	if cfg.Attachment.DoubleExtScore != 40 {
		t.Errorf("Attachment.DoubleExtScore = %d, want 40", cfg.Attachment.DoubleExtScore)
	}
	if !cfg.Notification.SMTP.Enabled || cfg.Notification.SMTP.Host != "smtp.example.com" {
		t.Errorf("Notification.SMTP = %+v, want enabled host=smtp.example.com", cfg.Notification.SMTP)
	}
	if cfg.Notification.Webhook.URL != "https://hook.example.com/in" {
		t.Errorf("Notification.Webhook.URL = %q, want override", cfg.Notification.Webhook.URL)
	}
	if !cfg.Gmail.Enabled || cfg.Gmail.ClientID != "client-123" {
		t.Errorf("Gmail = %+v, want enabled client-123", cfg.Gmail)
	}
}

// -- AttachmentConfig.Validate ------------------------------------------------

func validAttachmentConfig() AttachmentConfig {
	return AttachmentConfig{
		VTCacheTTL:             24 * time.Hour,
		EntropyThreshold:       7.5,
		HighEntropyScore:       20,
		ExtensionMismatchScore: 30,
		DangerousExtScore:      25,
		MacroOfficeScore:       20,
		DoubleExtScore:         35,
		MaliciousHashScore:     90,
		ConsumeTopic:           "analysis.attachments",
		ProduceTopic:           "scores.attachment",
		ConsumerGroup:          "cg-attachment-analysis",
	}
}

func TestAttachmentConfig_Validate(t *testing.T) {
	if err := validAttachmentConfig().Validate(); err != nil {
		t.Fatalf("expected valid attachment config to pass, got: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*AttachmentConfig)
		wantErr string
	}{
		{"vt_cache_ttl zero", func(a *AttachmentConfig) { a.VTCacheTTL = 0 }, "attachment.vt_cache_ttl must be > 0"},
		{"entropy too low", func(a *AttachmentConfig) { a.EntropyThreshold = 0 }, "attachment.entropy_threshold"},
		{"entropy too high", func(a *AttachmentConfig) { a.EntropyThreshold = 9 }, "attachment.entropy_threshold"},
		{"score negative", func(a *AttachmentConfig) { a.HighEntropyScore = -1 }, "attachment.high_entropy_score"},
		{"score over 100", func(a *AttachmentConfig) { a.MaliciousHashScore = 101 }, "attachment.malicious_hash_score"},
		{"missing consume topic", func(a *AttachmentConfig) { a.ConsumeTopic = "" }, "attachment.consume_topic"},
		{"missing produce topic", func(a *AttachmentConfig) { a.ProduceTopic = "" }, "attachment.produce_topic"},
		{"missing consumer group", func(a *AttachmentConfig) { a.ConsumerGroup = "" }, "attachment.consumer_group"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := validAttachmentConfig()
			tt.mutate(&a)
			err := a.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

// -- NotificationConfig.Validate ----------------------------------------------

func TestNotificationConfig_Validate(t *testing.T) {
	// Both channels disabled → nothing to validate, passes.
	if err := (NotificationConfig{}).Validate(); err != nil {
		t.Fatalf("expected disabled channels to pass, got: %v", err)
	}

	// Valid enabled SMTP + webhook.
	valid := NotificationConfig{
		SMTP: SMTPConfig{
			Enabled: true,
			Host:    "smtp.example.com",
			Port:    587,
			From:    "alerts@example.com",
			Timeout: 10 * time.Second,
		},
		Webhook: WebhookConfig{
			Enabled:    true,
			URL:        "https://hook.example.com/in",
			Timeout:    10 * time.Second,
			MaxRetries: 3,
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid enabled channels to pass, got: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*NotificationConfig)
		wantErr string
	}{
		{"smtp missing host", func(n *NotificationConfig) { n.SMTP.Host = "" }, "notification.smtp.host"},
		{"smtp bad port", func(n *NotificationConfig) { n.SMTP.Port = 0 }, "notification.smtp.port"},
		{"smtp missing from", func(n *NotificationConfig) { n.SMTP.From = "" }, "notification.smtp.from"},
		{"smtp timeout zero", func(n *NotificationConfig) { n.SMTP.Timeout = 0 }, "notification.smtp.timeout"},
		{"webhook missing url", func(n *NotificationConfig) { n.Webhook.URL = "" }, "notification.webhook.url"},
		{"webhook bad url", func(n *NotificationConfig) { n.Webhook.URL = "not-a-url" }, "notification.webhook.url must be a valid"},
		{"webhook timeout zero", func(n *NotificationConfig) { n.Webhook.Timeout = 0 }, "notification.webhook.timeout"},
		{"webhook negative retries", func(n *NotificationConfig) { n.Webhook.MaxRetries = -1 }, "notification.webhook.max_retries"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := valid
			tt.mutate(&n)
			err := n.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestNotificationConfig_DisabledChannelSkipsValidation(t *testing.T) {
	// A disabled channel with otherwise-invalid fields must still pass —
	// only enabled channels are validated.
	n := NotificationConfig{
		SMTP:    SMTPConfig{Enabled: false, Host: "", Port: 0},
		Webhook: WebhookConfig{Enabled: false, URL: ""},
	}
	if err := n.Validate(); err != nil {
		t.Fatalf("expected disabled-but-empty channels to pass, got: %v", err)
	}
}

// -- GmailConfig.Validate -----------------------------------------------------

func TestGmailConfig_Validate(t *testing.T) {
	// Disabled adapter: Validate is opt-in and callers skip it when disabled,
	// but calling it directly on a disabled-empty config still reports the
	// missing creds — SVC-01 only calls it once the adapter is on.
	valid := GmailConfig{
		Enabled:      true,
		ClientID:     "client-123",
		ClientSecret: "secret-456",
		RefreshToken: "refresh-789",
		Scopes:       []string{"https://www.googleapis.com/auth/gmail.readonly"},
		OrgID:        7,
		PushEnabled:  true,
		PollEnabled:  true,
		WatchTopic:   "projects/demo/topics/gmail-push",
		PollInterval: 5 * time.Minute,
		HTTPTimeout:  30 * time.Second,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid gmail config to pass, got: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*GmailConfig)
		wantErr string
	}{
		{"missing client_id", func(g *GmailConfig) { g.ClientID = "" }, "gmail.client_id"},
		{"missing client_secret", func(g *GmailConfig) { g.ClientSecret = "" }, "gmail.client_secret"},
		{"missing refresh_token", func(g *GmailConfig) { g.RefreshToken = "" }, "gmail.refresh_token"},
		{"empty scopes", func(g *GmailConfig) { g.Scopes = nil }, "gmail.scopes"},
		{"missing org_id", func(g *GmailConfig) { g.OrgID = 0 }, "gmail.org_id"},
		{"poll_interval zero", func(g *GmailConfig) { g.PollInterval = 0 }, "gmail.poll_interval"},
		{"http_timeout zero", func(g *GmailConfig) { g.HTTPTimeout = 0 }, "gmail.http_timeout"},
		{"no delivery mode", func(g *GmailConfig) { g.PushEnabled = false; g.PollEnabled = false }, "push_enabled or poll_enabled"},
		{"push without topic", func(g *GmailConfig) { g.WatchTopic = "" }, "gmail.watch_topic"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := valid
			tt.mutate(&g)
			err := g.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestDecisionConfig_Validate(t *testing.T) {
	valid := DecisionConfig{
		FusionMode:   "noisy_or",
		FusionShadow: true,
		Reliability:  ReliabilityConfig{URL: 1.0, Header: 0.8, NLP: 1.0, Attachment: 0.0},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid decision config rejected: %v", err)
	}
	// empty fusion mode is allowed (engine defaults it to weighted_average).
	if err := (DecisionConfig{Reliability: ReliabilityConfig{URL: 1}}).Validate(); err != nil {
		t.Fatalf("empty fusion mode should be allowed: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*DecisionConfig)
		wantErr string
	}{
		{"bad mode", func(d *DecisionConfig) { d.FusionMode = "noisyor" }, "decision.fusion_mode"},
		{"reliability > 1", func(d *DecisionConfig) { d.Reliability.URL = 1.5 }, "decision.reliability.url"},
		{"reliability < 0", func(d *DecisionConfig) { d.Reliability.Header = -0.2 }, "decision.reliability.header"},
		{"reliability NaN", func(d *DecisionConfig) { d.Reliability.NLP = math.NaN() }, "decision.reliability.nlp"},
		{"reliability Inf", func(d *DecisionConfig) { d.Reliability.Attachment = math.Inf(1) }, "decision.reliability.attachment"},
		{"all-zero reliability", func(d *DecisionConfig) {
			d.Reliability = ReliabilityConfig{}
		}, "at least one channel must be > 0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := valid
			tt.mutate(&d)
			err := d.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestLoad_DecisionDefaultsAndEnvOverride(t *testing.T) {
	setRequiredEnv(t)
	// Nested koanf key: CYBERSIREN_DECISION__RELIABILITY__URL -> decision.reliability.url
	t.Setenv("CYBERSIREN_DECISION__FUSION_MODE", "noisy_or")
	t.Setenv("CYBERSIREN_DECISION__FUSION_SHADOW", "true")
	t.Setenv("CYBERSIREN_DECISION__RELIABILITY__URL", "0.5")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.Decision.FusionMode != "noisy_or" {
		t.Errorf("Decision.FusionMode = %q, want %q", cfg.Decision.FusionMode, "noisy_or")
	}
	if !cfg.Decision.FusionShadow {
		t.Errorf("Decision.FusionShadow = false, want true")
	}
	if cfg.Decision.Reliability.URL != 0.5 {
		t.Errorf("nested env override Decision.Reliability.URL = %v, want 0.5", cfg.Decision.Reliability.URL)
	}
	// Unset channels keep the 1.0 default.
	if cfg.Decision.Reliability.Header != 1.0 {
		t.Errorf("default Decision.Reliability.Header = %v, want 1.0", cfg.Decision.Reliability.Header)
	}
}

func TestLoad_DecisionDefaults(t *testing.T) {
	setRequiredEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Decision.FusionMode != "calibrated_or" {
		t.Errorf("default Decision.FusionMode = %q, want calibrated_or", cfg.Decision.FusionMode)
	}
	if cfg.Decision.FusionShadow {
		t.Errorf("default Decision.FusionShadow = true, want false")
	}
	r := cfg.Decision.Reliability
	if r.URL != 1.0 || r.Header != 1.0 || r.NLP != 1.0 || r.Attachment != 1.0 {
		t.Errorf("default reliabilities = %+v, want all 1.0", r)
	}
}
