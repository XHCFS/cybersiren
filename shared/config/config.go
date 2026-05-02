package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	koanfyaml "github.com/knadh/koanf/parsers/yaml"
	enpv2 "github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
)

// Config is the root configuration object. All sub-configs are loaded
// from a YAML file and/or environment variables (env vars take precedence).
type Config struct {
	Env    string       `koanf:"env"` // "development" | "staging" | "production"
	Server ServerConfig `koanf:"server"`
	DB     DBConfig     `koanf:"db"`
	Auth   AuthConfig   `koanf:"auth"`
	Log    LogConfig    `koanf:"log"`

	JaegerEndpoint          string `koanf:"jaeger_endpoint"`
	MetricsPort             int    `koanf:"metrics_port"`
	FeedPhishTankAPIKey     string `koanf:"feed_phishtank_api_key"`
	FeedThreatFoxAPIKey     string `koanf:"feed_threatfox_api_key"`
	FeedOpenPhishAPIKey     string `koanf:"feed_openphish_api_key"`
	FeedMalwareBazaarAPIKey string `koanf:"feed_malwarebazaar_api_key"`
	SyncIntervalSeconds     int    `koanf:"sync_interval_seconds"`
	TIHashCacheTTLSeconds   int    `koanf:"ti_hash_cache_ttl_seconds"`

	Valkey     ValkeyConfig     `koanf:"valkey"`
	Kafka      KafkaConfig      `koanf:"kafka"`
	Worker     WorkerConfig     `koanf:"worker"`
	CORS       CORSConfig       `koanf:"cors"`
	ML         MLConfig         `koanf:"ml"`
	Enrichment EnrichmentConfig `koanf:"enrichment"`
	Storage    StorageConfig    `koanf:"storage"`
	Embedding  EmbeddingConfig  `koanf:"embedding"`
	Header     HeaderConfig     `koanf:"header"`
}

// HeaderConfig holds configuration for SVC-04 Header Analysis Service.
//
// Thresholds are PRELIMINARY heuristics — they are exposed as configuration
// so they can be tuned without code changes. None of the values below have
// been calibrated against a labeled corpus; do not interpret them as
// validated detection thresholds. See ARCH-SPEC §1 step 3b.
type HeaderConfig struct {
	// RuleCacheTTLSeconds controls how long the in-process rule cache and
	// the Valkey rules_cache:{org_id} entry remain valid (default 60s).
	RuleCacheTTLSeconds int `koanf:"rule_cache_ttl_seconds"`

	// HopCountThreshold flags Received-chain depth above which the
	// "excessive_hop_count" structural signal fires (default 15).
	HopCountThreshold int `koanf:"hop_count_threshold"`

	// TimeDriftHoursThreshold flags absolute |sent_timestamp − latest
	// Received timestamp| above which "time_drift" structural signal
	// fires (default 24h). Stored as float to allow sub-hour tuning.
	TimeDriftHoursThreshold float64 `koanf:"time_drift_hours_threshold"`

	// TyposquatMaxDistance is the maximum Damerau-Levenshtein distance
	// between sender_domain and an embedded brand list entry that still
	// counts as a typosquat (default 2; distance 0 = exact match, ignored).
	TyposquatMaxDistance int `koanf:"typosquat_max_distance"`

	// ScoringBlend controls how sub-scores combine into the final score.
	// One of: "max", "average", "weighted". Default: "max".
	ScoringBlend string `koanf:"scoring_blend"`

	// AuthWeight, ReputationWeight, StructuralWeight are used when
	// ScoringBlend is "weighted". They are normalised internally.
	AuthWeight       float64 `koanf:"auth_weight"`
	ReputationWeight float64 `koanf:"reputation_weight"`
	StructuralWeight float64 `koanf:"structural_weight"`

	// ConsumeTopic / ProduceTopic / ConsumerGroup are exposed for tests
	// and for compose overrides. Defaults match ARCH-SPEC §3.
	ConsumeTopic  string `koanf:"consume_topic"`
	ProduceTopic  string `koanf:"produce_topic"`
	ConsumerGroup string `koanf:"consumer_group"`

	// PublishRetryAttempts caps the exponential-backoff retry count when
	// publishing scores.header (default 5).
	PublishRetryAttempts int `koanf:"publish_retry_attempts"`

	// DBWriteRetryAttempts caps the rule_hits transaction retry count
	// before the consumer refuses to commit the offset (default 3).
	DBWriteRetryAttempts int `koanf:"db_write_retry_attempts"`
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
	//
	// NOTE: Do NOT call url.QueryEscape on user/password here —
	// url.UserPassword already percent-encodes special characters.
	hostPort := fmt.Sprintf("%s:%d", c.Host, c.Port)

	dsn := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(c.User, c.Password),
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
	JWTSecret    string        `koanf:"jwt_secret"`
	JWTExpiry    time.Duration `koanf:"jwt_expiry"`
	BcryptCost   int           `koanf:"bcrypt_cost"`
	APIKeyPrefix string        `koanf:"api_key_prefix"`
	// Length of random suffix after prefix (e.g., "cs_" + 8 random chars).
	APIKeyPrefixLen int `koanf:"api_key_prefix_len"`
}

type LogConfig struct {
	Level  string `koanf:"level"`
	Pretty bool   `koanf:"pretty"`
}

type ValkeyConfig struct {
	Addr     string `koanf:"addr"`
	DB       int    `koanf:"db"`
	Password string `koanf:"password"`
}

// KafkaConfig holds the Kafka client connection settings shared across
// services. Brokers is a comma- or whitespace-separated list of host:port
// pairs; the Kafka client wrappers (shared/kafka/{producer,consumer}) parse
// it. Locally we point this at the Redpanda broker (Kafka API-compatible);
// in production it would point at an Apache Kafka cluster.
type KafkaConfig struct {
	Brokers             string `koanf:"brokers"`
	ClientID            string `koanf:"client_id"`
	ConsumerGroupPrefix string `koanf:"consumer_group_prefix"`
}

// Validate checks that the KafkaConfig has the minimum fields required by
// the producer/consumer wrappers. svc-04 (and any later services that need
// to fail fast on a misconfigured broker) call this from main().
func (k KafkaConfig) Validate() error {
	if strings.TrimSpace(k.Brokers) == "" {
		return errors.New("kafka.brokers is required (CYBERSIREN_KAFKA__BROKERS)")
	}
	return nil
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
	NLPServiceURL    string `koanf:"nlp_service_url"`
	URLModelPath     string `koanf:"url_model_path"`
	URLModelPoolSize int    `koanf:"url_model_pool_size"`
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
//  2. .env file (or the path in CYBERSIREN_ENV_FILE); does not overwrite already-set env vars
//  3. Environment variables prefixed with CYBERSIREN_
//     Double underscores delimit hierarchy levels:
//     e.g. CYBERSIREN_DB__PASSWORD overrides db.password
//
// Precedence (highest to lowest): process env > .env file > config.yaml > defaults.
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
			Host:              "localhost",
			Port:              5432,
			SSLMode:           "disable",
			MaxConns:          20,
			MinConns:          2,
			MaxConnLifetime:   time.Hour,
			MaxConnIdleTime:   30 * time.Minute,
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
		JaegerEndpoint:        "",
		MetricsPort:           9090,
		SyncIntervalSeconds:   3600,
		TIHashCacheTTLSeconds: 7200,
		Valkey: ValkeyConfig{
			Addr: "localhost:6379",
			DB:   0,
		},
		Kafka: KafkaConfig{
			Brokers:             "localhost:9092",
			ClientID:            "cybersiren",
			ConsumerGroupPrefix: "cybersiren",
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
			NLPServiceURL:    "http://localhost:8001",
			URLModelPath:     "./ml/inference_script.py",
			URLModelPoolSize: 3,
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
		Header: HeaderConfig{
			RuleCacheTTLSeconds:     60,
			HopCountThreshold:       15,
			TimeDriftHoursThreshold: 24,
			TyposquatMaxDistance:    2,
			ScoringBlend:            "max",
			AuthWeight:              1.0,
			ReputationWeight:        1.0,
			StructuralWeight:        1.0,
			ConsumeTopic:            "analysis.headers",
			ProduceTopic:            "scores.header",
			ConsumerGroup:           "cg-header-analysis",
			PublishRetryAttempts:    5,
			DBWriteRetryAttempts:    3,
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

	envFile := os.Getenv("CYBERSIREN_ENV_FILE")
	if envFile == "" {
		envFile = ".env"
	}
	// godotenv.Load does not overwrite env vars that are already set in the process,
	// so shell/container env always takes precedence over the .env file.
	if _, err := os.Stat(envFile); err == nil {
		if err := godotenv.Load(envFile); err != nil {
			return nil, fmt.Errorf("reading env file %q: %w", envFile, err)
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

func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}

	var missing []error

	if c.DB.Name == "" {
		missing = append(missing, errors.New("db.name (CYBERSIREN_DB__NAME)"))
	}
	if c.DB.User == "" {
		missing = append(missing, errors.New("db.user (CYBERSIREN_DB__USER)"))
	}
	if c.DB.Password == "" {
		missing = append(missing, errors.New("db.password (CYBERSIREN_DB__PASSWORD)"))
	}
	if c.Auth.JWTSecret == "" {
		missing = append(missing, errors.New("auth.jwt_secret (CYBERSIREN_AUTH__JWT_SECRET)"))
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required config values: %w", errors.Join(missing...))
	}

	validEnvs := map[string]bool{"development": true, "staging": true, "production": true}
	if !validEnvs[c.Env] {
		return fmt.Errorf("env must be one of: development, staging, production, got %q", c.Env)
	}

	if c.Embedding.Dimension <= 0 {
		return fmt.Errorf("embedding.dimension must be greater than 0, got %d", c.Embedding.Dimension)
	}

	if c.Auth.APIKeyPrefixLen <= 0 {
		return fmt.Errorf("auth.api_key_prefix_len must be greater than 0, got %d", c.Auth.APIKeyPrefixLen)
	}

	if c.Auth.BcryptCost < 4 || c.Auth.BcryptCost > 31 {
		return fmt.Errorf("auth.bcrypt_cost must be between 4 and 31, got %d", c.Auth.BcryptCost)
	}

	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535, got %d", c.Server.Port)
	}

	if c.Server.ReadTimeout <= 0 {
		return fmt.Errorf("server.read_timeout must be greater than 0, got %v", c.Server.ReadTimeout)
	}
	if c.Server.WriteTimeout <= 0 {
		return fmt.Errorf("server.write_timeout must be greater than 0, got %v", c.Server.WriteTimeout)
	}
	if c.Server.IdleTimeout <= 0 {
		return fmt.Errorf("server.idle_timeout must be greater than 0, got %v", c.Server.IdleTimeout)
	}

	if c.DB.Port < 1 || c.DB.Port > 65535 {
		return fmt.Errorf("db.port must be between 1 and 65535, got %d", c.DB.Port)
	}

	if c.DB.MaxConns <= 0 {
		return fmt.Errorf("db.max_conns must be greater than 0, got %d", c.DB.MaxConns)
	}
	if c.DB.MinConns < 0 {
		return fmt.Errorf("db.min_conns must be greater than or equal to 0, got %d", c.DB.MinConns)
	}
	if c.DB.MinConns > c.DB.MaxConns {
		return fmt.Errorf("db.min_conns (%d) cannot be greater than db.max_conns (%d)", c.DB.MinConns, c.DB.MaxConns)
	}
	if c.DB.MaxConnLifetime <= 0 {
		return fmt.Errorf("db.max_conn_lifetime must be greater than 0, got %v", c.DB.MaxConnLifetime)
	}
	if c.DB.MaxConnIdleTime <= 0 {
		return fmt.Errorf("db.max_conn_idle_time must be greater than 0, got %v", c.DB.MaxConnIdleTime)
	}
	if c.DB.HealthCheckPeriod <= 0 {
		return fmt.Errorf("db.health_check_period must be greater than 0, got %v", c.DB.HealthCheckPeriod)
	}

	if c.Enrichment.WorkerCount <= 0 {
		return fmt.Errorf("enrichment.worker_count must be greater than 0, got %d", c.Enrichment.WorkerCount)
	}
	if c.Enrichment.JobTimeout <= 0 {
		return fmt.Errorf("enrichment.job_timeout must be greater than 0, got %v", c.Enrichment.JobTimeout)
	}
	if c.Enrichment.MaxRetries < 0 {
		return fmt.Errorf("enrichment.max_retries must be greater than or equal to 0, got %d", c.Enrichment.MaxRetries)
	}

	if c.Enrichment.VirusTotal.Timeout <= 0 {
		return fmt.Errorf("enrichment.virustotal.timeout must be greater than 0, got %v", c.Enrichment.VirusTotal.Timeout)
	}
	if c.Enrichment.IPInfo.Timeout <= 0 {
		return fmt.Errorf("enrichment.ipinfo.timeout must be greater than 0, got %v", c.Enrichment.IPInfo.Timeout)
	}
	if c.Enrichment.WHOIS.Timeout <= 0 {
		return fmt.Errorf("enrichment.whois.timeout must be greater than 0, got %v", c.Enrichment.WHOIS.Timeout)
	}
	if c.Enrichment.URLScan.Timeout <= 0 {
		return fmt.Errorf("enrichment.urlscan.timeout must be greater than 0, got %v", c.Enrichment.URLScan.Timeout)
	}
	if c.Enrichment.Screenshot.Timeout <= 0 {
		return fmt.Errorf("enrichment.screenshot.timeout must be greater than 0, got %v", c.Enrichment.Screenshot.Timeout)
	}

	validSSLModes := map[string]bool{
		"disable":     true,
		"allow":       true,
		"prefer":      true,
		"require":     true,
		"verify-ca":   true,
		"verify-full": true,
	}
	if !validSSLModes[c.DB.SSLMode] {
		return fmt.Errorf("db.ssl_mode must be one of: disable, allow, prefer, require, verify-ca, verify-full, got %q", c.DB.SSLMode)
	}

	if c.SyncIntervalSeconds <= 30 {
		return fmt.Errorf("sync_interval_seconds must be greater than 30, got %d", c.SyncIntervalSeconds)
	}
	if c.TIHashCacheTTLSeconds <= 0 {
		return fmt.Errorf("ti_hash_cache_ttl_seconds must be greater than 0, got %d", c.TIHashCacheTTLSeconds)
	}
	if c.TIHashCacheTTLSeconds < c.SyncIntervalSeconds {
		return fmt.Errorf(
			"ti_hash_cache_ttl_seconds (%d) should be >= sync_interval_seconds (%d) to avoid cache expiry between syncs",
			c.TIHashCacheTTLSeconds, c.SyncIntervalSeconds,
		)
	}

	return nil
}

func validate(cfg *Config) error {
	return cfg.Validate()
}

// Validate sanity-checks SVC-04 Header Analysis configuration. It does NOT run
// during the global Config.Validate() pass so that other services can keep
// using the default zero values without surprise validation failures. SVC-04's
// main.go is expected to call this explicitly during startup.
func (h HeaderConfig) Validate() error {
	if h.RuleCacheTTLSeconds <= 0 {
		return fmt.Errorf("header.rule_cache_ttl_seconds must be > 0, got %d", h.RuleCacheTTLSeconds)
	}
	if h.HopCountThreshold < 1 {
		return fmt.Errorf("header.hop_count_threshold must be >= 1, got %d", h.HopCountThreshold)
	}
	if h.TimeDriftHoursThreshold <= 0 {
		return fmt.Errorf("header.time_drift_hours_threshold must be > 0, got %v", h.TimeDriftHoursThreshold)
	}
	if h.TyposquatMaxDistance < 0 {
		return fmt.Errorf("header.typosquat_max_distance must be >= 0, got %d", h.TyposquatMaxDistance)
	}
	switch h.ScoringBlend {
	case "max", "average", "weighted":
	default:
		return fmt.Errorf("header.scoring_blend must be one of: max, average, weighted; got %q", h.ScoringBlend)
	}
	if h.PublishRetryAttempts < 0 {
		return fmt.Errorf("header.publish_retry_attempts must be >= 0, got %d", h.PublishRetryAttempts)
	}
	if h.DBWriteRetryAttempts < 0 {
		return fmt.Errorf("header.db_write_retry_attempts must be >= 0, got %d", h.DBWriteRetryAttempts)
	}
	if strings.TrimSpace(h.ConsumeTopic) == "" {
		return errors.New("header.consume_topic is required")
	}
	if strings.TrimSpace(h.ProduceTopic) == "" {
		return errors.New("header.produce_topic is required")
	}
	if strings.TrimSpace(h.ConsumerGroup) == "" {
		return errors.New("header.consumer_group is required")
	}
	return nil
}

