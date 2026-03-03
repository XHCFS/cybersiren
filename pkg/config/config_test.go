package config

import (
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
			APIKeyPrefixLen: 8,
		},
		Log: LogConfig{
			Level:  "info",
			Pretty: false,
		},
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

// setRequiredEnv sets the minimum env vars needed for Load() to pass validation.
func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CYBERSIREN_DB__NAME", "testdb")
	t.Setenv("CYBERSIREN_DB__USER", "testuser")
	t.Setenv("CYBERSIREN_DB__PASSWORD", "testpassword")
	t.Setenv("CYBERSIREN_AUTH__JWT_SECRET", "testsecret")
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
		{"api_key_prefix_len zero", func(c *Config) { c.Auth.APIKeyPrefixLen = 0 }, "auth.api_key_prefix_len must be greater than 0"},
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
	if cfg.Enrichment.WorkerCount != 10 {
		t.Errorf("default Enrichment.WorkerCount = %d, want %d", cfg.Enrichment.WorkerCount, 10)
	}
	if cfg.Embedding.Dimension != 1536 {
		t.Errorf("default Embedding.Dimension = %d, want %d", cfg.Embedding.Dimension, 1536)
	}
}

func TestLoad_EnvOverridesWithDoubleUnderscore(t *testing.T) {
	t.Setenv("CYBERSIREN_DB__NAME", "env_db")
	t.Setenv("CYBERSIREN_DB__USER", "env_user")
	t.Setenv("CYBERSIREN_DB__PASSWORD", "env_password")
	t.Setenv("CYBERSIREN_AUTH__JWT_SECRET", "supersecret")
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
	if cfg.Auth.JWTSecret != "supersecret" {
		t.Errorf("expected Auth.JWTSecret from env to be %q, got %q", "supersecret", cfg.Auth.JWTSecret)
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
  jwt_secret: yaml-jwt-secret-long-enough
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
  jwt_secret: yaml-jwt-secret-long-enough
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
