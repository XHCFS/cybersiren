package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/knadh/koanf/v2"
	koanfyaml "github.com/knadh/koanf/parsers/yaml"
	enpv2 "github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
)

// Config is the root configuration object. All sub-configs are loaded
// from a YAML file and/or environment variables (env vars take precedence).
type Config struct {
	Env    string       `koanf:"env"` // "development" | "staging" | "production"
	Server ServerConfig `koanf:"server"`
	DB     DBConfig     `koanf:"db"`
	Auth   AuthConfig   `koanf:"auth"`
	Log    LogConfig    `koanf:"log"`

	Redis   RedisConfig   `koanf:"redis"`
	Worker  WorkerConfig  `koanf:"worker"`
	CORS    CORSConfig    `koanf:"cors"`
	ML      MLConfig      `koanf:"ml"`
	Enrichment EnrichmentConfig `koanf:"enrichment"`
	Storage    StorageConfig    `koanf:"storage"`
	Embedding  EmbeddingConfig  `koanf:"embedding"`
}

type ServerConfig struct {
	Host         string        `koanf:"host"`
	Port         int           `koanf:"port"`
	ReadTimeout  time.Duration `koanf:"read_timeout"`
	WriteTimeout time.Duration `koanf:"write_timeout"`
	IdleTimeout  time.Duration `koanf:"idle_timeout"`
}

type DBConfig struct {
	Host     string `koanf:"host"`
	Port     int    `koanf:"port"`
	Name     string `koanf:"name"`
	User     string `koanf:"user"`
	Password string `koanf:"password"`
	SSLMode  string `koanf:"ssl_mode"`

	MaxConns          int           `koanf:"max_conns"`
	MinConns          int           `koanf:"min_conns"`
	MaxConnLifetime   time.Duration `koanf:"max_conn_lifetime"`
	MaxConnIdleTime   time.Duration `koanf:"max_conn_idle_time"`
	HealthCheckPeriod time.Duration `koanf:"health_check_period"`
}

func (c DBConfig) DSN() string {
	// Build DSN using a URL-style connection string to avoid issues with
	// special characters in usernames or passwords.
	//
	// Example: postgres://user:pass@host:port/dbname?sslmode=disable
	user := url.QueryEscape(c.User)
	password := url.QueryEscape(c.Password)
	hostPort := fmt.Sprintf("%s:%d", c.Host, c.Port)

	dsn := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Host:   hostPort,
		Path:   c.Name,
	}

	qs := url.Values{}
	if c.SSLMode != "" {
		qs.Set("sslmode", c.SSLMode)
	}
	dsn.RawQuery = qs.Encode()

	return dsn.String()
}

type AuthConfig struct {
	JWTSecret       string        `koanf:"jwt_secret"`
	JWTExpiry       time.Duration `koanf:"jwt_expiry"`
	BcryptCost      int           `koanf:"bcrypt_cost"`
	APIKeyPrefix    string        `koanf:"api_key_prefix"`
	APIKeyPrefixLen int           `koanf:"api_key_prefix_len"` // Length of random suffix after prefix (e.g., "cs_" + 8 chars = "cs_abc12345")
}

type LogConfig struct {
	Level  string `koanf:"level"`
	Pretty bool   `koanf:"pretty"`
}

type RedisConfig struct {
	Addr     string `koanf:"addr"`
	DB       int    `koanf:"db"`
	Password string `koanf:"password"`
}

type WorkerConfig struct {
	Concurrency int    `koanf:"concurrency"`
	Queue       string `koanf:"queue"`
	MaxRetries  int    `koanf:"max_retries"`
}

type CORSConfig struct {
	AllowedOrigins   []string `koanf:"allowed_origins"`
	AllowedMethods   []string `koanf:"allowed_methods"`
	AllowedHeaders   []string `koanf:"allowed_headers"`
	ExposedHeaders   []string `koanf:"exposed_headers"`
	AllowCredentials bool     `koanf:"allow_credentials"`
}

type MLConfig struct {
	NLPServiceURL string `koanf:"nlp_service_url"`
	URLModelPath  string `koanf:"url_model_path"`
}

type EnrichmentConfig struct {
	WorkerCount int           `koanf:"worker_count"`
	JobTimeout  time.Duration `koanf:"job_timeout"`
	MaxRetries  int           `koanf:"max_retries"`

	VirusTotal VirusTotalConfig `koanf:"virustotal"`
	IPInfo     IPInfoConfig     `koanf:"ipinfo"`
	WHOIS      WHOISConfig      `koanf:"whois"`
	URLScan    URLScanConfig    `koanf:"urlscan"`
	Screenshot ScreenshotConfig `koanf:"screenshot"`
}

type VirusTotalConfig struct {
	APIKey  string        `koanf:"api_key"`
	Timeout time.Duration `koanf:"timeout"`
	BaseURL string        `koanf:"base_url"`
}

type IPInfoConfig struct {
	Token   string        `koanf:"token"`
	Timeout time.Duration `koanf:"timeout"`
	BaseURL string        `koanf:"base_url"`
}

type WHOISConfig struct {
	APIKey  string        `koanf:"api_key"`
	Timeout time.Duration `koanf:"timeout"`
	BaseURL string        `koanf:"base_url"`
}

type URLScanConfig struct {
	APIKey  string        `koanf:"api_key"`
	Timeout time.Duration `koanf:"timeout"`
	BaseURL string        `koanf:"base_url"`
}

type ScreenshotConfig struct {
	Endpoint string        `koanf:"endpoint"`
	Timeout  time.Duration `koanf:"timeout"`
}

type StorageConfig struct {
	Bucket    string `koanf:"bucket"`
	Region    string `koanf:"region"`
	AccessKey string `koanf:"access_key"`
	SecretKey string `koanf:"secret_key"`
	Endpoint  string `koanf:"endpoint"`
	UseSSL    bool   `koanf:"use_ssl"`
}

type EmbeddingConfig struct {
	Provider  string `koanf:"provider"`
	APIKey    string `koanf:"api_key"`
	Model     string `koanf:"model"`
	Dimension int    `koanf:"dimension"`
	BaseURL   string `koanf:"base_url"`
}

// Load reads configuration from:
//  1. config.yaml (or the path in CYBERSIREN_CONFIG_PATH)
//  2. Environment variables prefixed with CYBERSIREN_
//     (e.g. CYBERSIREN_DB_PASSWORD overrides db.password)
//
// Env vars always take precedence over the YAML file.
func Load() (*Config, error) {
	k := koanf.New(".")

	defaults := &Config{
		Env: "development",
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         8080,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		DB: DBConfig{
			Host:             "localhost",
			Port:             5432,
			SSLMode:          "disable",
			MaxConns:         20,
			MinConns:         2,
			MaxConnLifetime:  time.Hour,
			MaxConnIdleTime:  30 * time.Minute,
			HealthCheckPeriod: time.Minute,
		},
		Auth: AuthConfig{
			JWTExpiry:       24 * time.Hour,
			BcryptCost:      12,
			APIKeyPrefix:    "cs_",
			APIKeyPrefixLen: 8,
		},
		Log: LogConfig{
			Level:  "info",
			Pretty: false,
		},
		Redis: RedisConfig{
			Addr: "localhost:6379",
			DB:   0,
		},
		Worker: WorkerConfig{
			Concurrency: 10,
			Queue:       "default",
			MaxRetries:  3,
		},
		CORS: CORSConfig{
			AllowedOrigins:   []string{"*"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Authorization", "Content-Type"},
			ExposedHeaders:   []string{},
			AllowCredentials: true,
		},
		ML: MLConfig{
			NLPServiceURL: "http://localhost:8001",
			URLModelPath:  "./ml/url_model/model.bin",
		},
		Enrichment: EnrichmentConfig{
			WorkerCount: 10,
			JobTimeout:  30 * time.Second,
			MaxRetries:  3,
			VirusTotal: VirusTotalConfig{
				BaseURL: "https://www.virustotal.com/api/v3",
				Timeout: 20 * time.Second,
			},
			IPInfo: IPInfoConfig{
				BaseURL: "https://ipinfo.io",
				Timeout: 10 * time.Second,
			},
			WHOIS: WHOISConfig{
				BaseURL: "https://www.whoisxmlapi.com/whoisserver/WhoisService",
				Timeout: 15 * time.Second,
			},
			URLScan: URLScanConfig{
				BaseURL: "https://urlscan.io/api/v1",
				Timeout: 30 * time.Second,
			},
			Screenshot: ScreenshotConfig{
				Timeout: 20 * time.Second,
			},
		},
		Storage: StorageConfig{
			UseSSL: true,
		},
		Embedding: EmbeddingConfig{
			Provider:  "openai",
			Model:     "text-embedding-3-small",
			Dimension: 1536,
			BaseURL:   "https://api.openai.com/v1",
		},
	}

	if err := k.Load(structs.Provider(defaults, "koanf"), nil); err != nil {
		return nil, fmt.Errorf("loading defaults: %w", err)
	}

	configPath := os.Getenv("CYBERSIREN_CONFIG_PATH")
	if configPath == "" {
		configPath = "config.yaml"
	}

	if _, err := os.Stat(configPath); err == nil {
		if err := k.Load(file.Provider(configPath), koanfyaml.Parser()); err != nil {
			return nil, fmt.Errorf("reading config file %q: %w", configPath, err)
		}
	}

	if err := k.Load(enpv2.Provider(".", enpv2.Opt{
		Prefix: "CYBERSIREN_",
		TransformFunc: func(k, v string) (string, any) {
			s := strings.ToLower(k)
			s = strings.TrimPrefix(s, "cybersiren_")
			// Use double underscore as hierarchy delimiter and keep single underscores
			// inside field names (e.g. jwt_secret, ssl_mode).
			s = strings.ReplaceAll(s, "__", ".")
			return s, v
		},
	}), nil); err != nil {
		return nil, fmt.Errorf("loading env vars: %w", err)
	}

	cfg := &Config{}
	if err := k.Unmarshal("", cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

func validate(cfg *Config) error {
	var missing []string

	if cfg.DB.Name == "" {
		missing = append(missing, "db.name (CYBERSIREN_DB_NAME)")
	}
	if cfg.DB.User == "" {
		missing = append(missing, "db.user (CYBERSIREN_DB_USER)")
	}
	if cfg.DB.Password == "" {
		missing = append(missing, "db.password (CYBERSIREN_DB_PASSWORD)")
	}
	if cfg.Auth.JWTSecret == "" {
		missing = append(missing, "auth.jwt_secret (CYBERSIREN_AUTH_JWT_SECRET)")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required config values: %s", strings.Join(missing, ", "))
	}

	validEnvs := map[string]bool{"development": true, "staging": true, "production": true}
	if !validEnvs[cfg.Env] {
		return fmt.Errorf("env must be one of: development, staging, production, got %q", cfg.Env)
	}

	if cfg.Embedding.Dimension <= 0 {
		return fmt.Errorf("embedding.dimension must be greater than 0, got %d", cfg.Embedding.Dimension)
	}

	if cfg.Auth.APIKeyPrefixLen <= 0 {
		return fmt.Errorf("auth.api_key_prefix_len must be greater than 0, got %d", cfg.Auth.APIKeyPrefixLen)
	}

	if cfg.Auth.BcryptCost < 4 || cfg.Auth.BcryptCost > 31 {
		return fmt.Errorf("auth.bcrypt_cost must be between 4 and 31, got %d", cfg.Auth.BcryptCost)
	}

	if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535, got %d", cfg.Server.Port)
	}

	if cfg.Server.ReadTimeout <= 0 {
		return fmt.Errorf("server.read_timeout must be greater than 0, got %v", cfg.Server.ReadTimeout)
	}
	if cfg.Server.WriteTimeout <= 0 {
		return fmt.Errorf("server.write_timeout must be greater than 0, got %v", cfg.Server.WriteTimeout)
	}
	if cfg.Server.IdleTimeout <= 0 {
		return fmt.Errorf("server.idle_timeout must be greater than 0, got %v", cfg.Server.IdleTimeout)
	}

	if cfg.DB.Port < 1 || cfg.DB.Port > 65535 {
		return fmt.Errorf("db.port must be between 1 and 65535, got %d", cfg.DB.Port)
	}

	if cfg.DB.MaxConns <= 0 {
		return fmt.Errorf("db.max_conns must be greater than 0, got %d", cfg.DB.MaxConns)
	}
	if cfg.DB.MinConns < 0 {
		return fmt.Errorf("db.min_conns must be greater than or equal to 0, got %d", cfg.DB.MinConns)
	}
	if cfg.DB.MinConns > cfg.DB.MaxConns {
		return fmt.Errorf("db.min_conns (%d) cannot be greater than db.max_conns (%d)", cfg.DB.MinConns, cfg.DB.MaxConns)
	}
	if cfg.DB.MaxConnLifetime <= 0 {
		return fmt.Errorf("db.max_conn_lifetime must be greater than 0, got %v", cfg.DB.MaxConnLifetime)
	}
	if cfg.DB.MaxConnIdleTime <= 0 {
		return fmt.Errorf("db.max_conn_idle_time must be greater than 0, got %v", cfg.DB.MaxConnIdleTime)
	}
	if cfg.DB.HealthCheckPeriod <= 0 {
		return fmt.Errorf("db.health_check_period must be greater than 0, got %v", cfg.DB.HealthCheckPeriod)
	}

	if cfg.Enrichment.WorkerCount <= 0 {
		return fmt.Errorf("enrichment.worker_count must be greater than 0, got %d", cfg.Enrichment.WorkerCount)
	}
	if cfg.Enrichment.JobTimeout <= 0 {
		return fmt.Errorf("enrichment.job_timeout must be greater than 0, got %v", cfg.Enrichment.JobTimeout)
	}
	if cfg.Enrichment.MaxRetries < 0 {
		return fmt.Errorf("enrichment.max_retries must be greater than or equal to 0, got %d", cfg.Enrichment.MaxRetries)
	}

	if cfg.Enrichment.VirusTotal.Timeout <= 0 {
		return fmt.Errorf("enrichment.virustotal.timeout must be greater than 0, got %v", cfg.Enrichment.VirusTotal.Timeout)
	}
	if cfg.Enrichment.IPInfo.Timeout <= 0 {
		return fmt.Errorf("enrichment.ipinfo.timeout must be greater than 0, got %v", cfg.Enrichment.IPInfo.Timeout)
	}
	if cfg.Enrichment.WHOIS.Timeout <= 0 {
		return fmt.Errorf("enrichment.whois.timeout must be greater than 0, got %v", cfg.Enrichment.WHOIS.Timeout)
	}
	if cfg.Enrichment.URLScan.Timeout <= 0 {
		return fmt.Errorf("enrichment.urlscan.timeout must be greater than 0, got %v", cfg.Enrichment.URLScan.Timeout)
	}
	if cfg.Enrichment.Screenshot.Timeout <= 0 {
		return fmt.Errorf("enrichment.screenshot.timeout must be greater than 0, got %v", cfg.Enrichment.Screenshot.Timeout)
	}

	validSSLModes := map[string]bool{
		"disable":     true,
		"allow":       true,
		"prefer":      true,
		"require":     true,
		"verify-ca":   true,
		"verify-full": true,
	}
	if !validSSLModes[cfg.DB.SSLMode] {
		return fmt.Errorf("db.ssl_mode must be one of: disable, allow, prefer, require, verify-ca, verify-full, got %q", cfg.DB.SSLMode)
	}

	return nil
}
