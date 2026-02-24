package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidate_MissingRequiredValues(t *testing.T) {
	cfg := &Config{
		Env: "development",
		DB: DBConfig{
			Host:    "localhost",
			Port:    5432,
			SSLMode: "disable",
		},
		Auth: AuthConfig{
			JWTSecret:  "secret",
			JWTExpiry:  24 * time.Hour,
			BcryptCost: 12,
		},
		Embedding: EmbeddingConfig{
			Provider:  "openai",
			Model:     "text-embedding-3-small",
			Dimension: 1536,
			BaseURL:   "https://api.openai.com/v1",
		},
		Enrichment: EnrichmentConfig{
			WorkerCount: 1,
			JobTimeout:  time.Second,
			MaxRetries:  1,
			VirusTotal:  VirusTotalConfig{Timeout: time.Second},
			IPInfo:      IPInfoConfig{Timeout: time.Second},
			WHOIS:       WHOISConfig{Timeout: time.Second},
			URLScan:     URLScanConfig{Timeout: time.Second},
			Screenshot:  ScreenshotConfig{Timeout: time.Second},
		},
	}

	if err := validate(cfg); err == nil {
		t.Fatalf("expected error for missing required values, got nil")
	}
}

func TestValidate_InvalidValues(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "invalid env",
			mutate: func(c *Config) {
				c.Env = "invalid"
			},
			wantErr: "env must be one of",
		},
		{
			name: "invalid ssl mode",
			mutate: func(c *Config) {
				c.DB.SSLMode = "bogus"
			},
			wantErr: "db.ssl_mode must be one of",
		},
		{
			name: "non-positive embedding dimension",
			mutate: func(c *Config) {
				c.Embedding.Dimension = 0
			},
			wantErr: "embedding.dimension must be greater than 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Ensure required secrets are present so that Load() succeeds and
			// validate() failures are isolated to the field under test.
			t.Setenv("CYBERSIREN_DB__NAME", "testdb")
			t.Setenv("CYBERSIREN_DB__USER", "testuser")
			t.Setenv("CYBERSIREN_DB__PASSWORD", "testpassword")
			t.Setenv("CYBERSIREN_AUTH__JWT_SECRET", "testsecret")

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() failed: %v", err)
			}

			tt.mutate(cfg)

			err = validate(cfg)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestLoad_EnvOverridesWithDoubleUnderscore(t *testing.T) {
	t.Setenv("CYBERSIREN_DB__NAME", "env_db")
	t.Setenv("CYBERSIREN_DB__USER", "env_user")
	t.Setenv("CYBERSIREN_DB__PASSWORD", "env_password")
	t.Setenv("CYBERSIREN_AUTH__JWT_SECRET", "supersecret")

	// Ensure no external config file interferes with the test.
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


