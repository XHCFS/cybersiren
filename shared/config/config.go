package config

import (
	"errors"
	"fmt"
	"math"
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

	"github.com/saif/cybersiren/shared/auth"
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
	TIDomainCacheTTLSeconds int    `koanf:"ti_domain_cache_ttl_seconds"`

	Valkey     ValkeyConfig     `koanf:"valkey"`
	Kafka      KafkaConfig      `koanf:"kafka"`
	Worker     WorkerConfig     `koanf:"worker"`
	CORS       CORSConfig       `koanf:"cors"`
	ML         MLConfig         `koanf:"ml"`
	Enrichment EnrichmentConfig `koanf:"enrichment"`
	Storage    StorageConfig    `koanf:"storage"`
	Embedding  EmbeddingConfig  `koanf:"embedding"`
	Header     HeaderConfig     `koanf:"header"`
	Phishing   PhishingConfig   `koanf:"phishing"`

	Attachment   AttachmentConfig   `koanf:"attachment"`
	Notification NotificationConfig `koanf:"notification"`
	Gmail        GmailConfig        `koanf:"gmail"`
	Decision     DecisionConfig     `koanf:"decision"`
}

// DecisionConfig holds the score-fusion tunables for SVC-08 Decision Engine.
// Set via env (e.g. CYBERSIREN_DECISION__FUSION_MODE=noisy_or) or config.yaml
// (decision.fusion_mode). See docs/design/svc-07-08-design-brief.md §3.4/§3.6.
type DecisionConfig struct {
	// FusionMode selects the blender: "calibrated_or" (default; calibrated
	// probabilistic-OR — see §3.4), "weighted_average" (v1 rollback), or
	// "noisy_or" (hand-set probabilistic OR, rollback).
	FusionMode string `koanf:"fusion_mode"`
	// FusionShadow, when true, computes the non-active method per email and records
	// decision_fusion_shadow_disagree_total so a switch can be measured first.
	FusionShadow bool `koanf:"fusion_shadow"`
	// Reliability is the per-channel trust in [0,1] for the noisy-OR blender
	// (default 1.0). Lower a channel that proves noisy in production.
	Reliability ReliabilityConfig `koanf:"reliability"`
}

// ReliabilityConfig holds the per-channel noisy-OR reliabilities (each in [0,1]).
type ReliabilityConfig struct {
	URL        float64 `koanf:"url"`
	Header     float64 `koanf:"header"`
	NLP        float64 `koanf:"nlp"`
	Attachment float64 `koanf:"attachment"`
}

// Validate checks the decision-engine tunables. Opt-in (called by SVC-08 at
// startup, like HeaderConfig.Validate) so other services are unaffected.
func (d DecisionConfig) Validate() error {
	switch d.FusionMode {
	case "", "weighted_average", "noisy_or", "calibrated_or":
	default:
		return fmt.Errorf("decision.fusion_mode must be one of: calibrated_or, weighted_average, noisy_or; got %q", d.FusionMode)
	}
	channels := map[string]float64{
		"url": d.Reliability.URL, "header": d.Reliability.Header,
		"nlp": d.Reliability.NLP, "attachment": d.Reliability.Attachment,
	}
	var positive bool
	for name, r := range channels {
		if math.IsNaN(r) || math.IsInf(r, 0) || r < 0 || r > 1 {
			return fmt.Errorf("decision.reliability.%s must be a finite value in [0,1], got %v", name, r)
		}
		if r > 0 {
			positive = true
		}
	}
	if !positive {
		return errors.New("decision.reliability: at least one channel must be > 0 (all-zero disables scoring)")
	}
	return nil
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
	// Length of the random suffix appended after the prefix (e.g. "cs_" + 32
	// random chars). Must be large enough that the stored lookup prefix omits
	// several trailing random characters; auth.NewKeyManager rejects values that
	// are too small to keep that reserve secret.
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
			APIKeyPrefixLen: 32,
		},
		Log: LogConfig{
			Level:  "info",
			Pretty: false,
		},
		JaegerEndpoint:          "",
		MetricsPort:             9090,
		SyncIntervalSeconds:     3600,
		TIDomainCacheTTLSeconds: 7200,
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
			NLPServiceURL: "http://localhost:8001",
			URLModelPath:  "./ml/inference_script.py",
			// Sized to match svc-03's per-email URL concurrency (maxURLConcurrency=8)
			// so concurrent L1 predictions don't serialize on a smaller worker pool.
			URLModelPoolSize: 8,
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
		Phishing: PhishingConfig{
			SidecarURL: "http://127.0.0.1:8765",
			GeoIPDir:   "../../fusion_export/fusion_kit",
			// Matches internal/phishing.DefaultThreshold and the sidecar default.
			Threshold: 0.50,
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
		Attachment: AttachmentConfig{
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
		},
		Notification: NotificationConfig{
			SMTP: SMTPConfig{
				Enabled:  false,
				Port:     587,
				StartTLS: true,
				Timeout:  10 * time.Second,
			},
			Webhook: WebhookConfig{
				Enabled:    false,
				Timeout:    10 * time.Second,
				MaxRetries: 3,
			},
		},
		Gmail: GmailConfig{
			Enabled:      false,
			Scopes:       []string{"https://www.googleapis.com/auth/gmail.readonly"},
			User:         "me",
			LabelIDs:     []string{"INBOX"},
			PushEnabled:  true,
			PollEnabled:  true,
			PollInterval: 5 * time.Minute,
			HTTPTimeout:  30 * time.Second,
		},
		Decision: DecisionConfig{
			FusionMode:   "calibrated_or",
			FusionShadow: false,
			Reliability:  ReliabilityConfig{URL: 1.0, Header: 1.0, NLP: 1.0, Attachment: 1.0},
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

	// JWT secret is non-empty here (caught above); enforce the entropy floor so
	// a weak secret fails at boot, not when auth.NewManager is later constructed.
	if len(c.Auth.JWTSecret) < auth.MinJWTSecretLen {
		return fmt.Errorf("auth.jwt_secret must be at least %d bytes, got %d", auth.MinJWTSecretLen, len(c.Auth.JWTSecret))
	}

	// Mirror auth.NewKeyManager's bounds so a misconfigured prefix length fails
	// at boot rather than when a service first mints/looks up an API key. The
	// suffix must exceed MinAPIKeySuffixLen (so the stored lookup prefix can
	// never cover the whole key), and prefix+suffix must fit bcrypt's input limit.
	if c.Auth.APIKeyPrefixLen <= auth.MinAPIKeySuffixLen {
		return fmt.Errorf("auth.api_key_prefix_len must be greater than %d, got %d", auth.MinAPIKeySuffixLen, c.Auth.APIKeyPrefixLen)
	}
	if len(c.Auth.APIKeyPrefix)+c.Auth.APIKeyPrefixLen > auth.MaxAPIKeyInputLen {
		return fmt.Errorf("auth.api_key_prefix(%d)+api_key_prefix_len(%d) must not exceed %d (bcrypt input limit)",
			len(c.Auth.APIKeyPrefix), c.Auth.APIKeyPrefixLen, auth.MaxAPIKeyInputLen)
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
	if c.TIDomainCacheTTLSeconds <= 0 {
		return fmt.Errorf("ti_domain_cache_ttl_seconds must be greater than 0, got %d", c.TIDomainCacheTTLSeconds)
	}
	// The TI domain cache is rewritten at the end of each sync cycle, so its TTL
	// must outlive the interval (plus feed-fetch time) or blocklisted domains
	// expire from the cache between syncs and svc-03 lookups miss them.
	if c.TIDomainCacheTTLSeconds < c.SyncIntervalSeconds {
		return fmt.Errorf(
			"ti_domain_cache_ttl_seconds (%d) should be >= sync_interval_seconds (%d) to avoid cache expiry between syncs",
			c.TIDomainCacheTTLSeconds, c.SyncIntervalSeconds,
		)
	}

	return nil
}

func validate(cfg *Config) error {
	return cfg.Validate()
}

// PhishingConfig holds configuration for the Layer-2 ML phishing detector.
// Validation is opt-in — services that do not use the detector skip Validate().
type PhishingConfig struct {
	// SidecarURL is the base URL of the Python fusion-scorer sidecar.
	SidecarURL string `koanf:"sidecar_url"`
	// GeoIPDir is the directory containing GeoLite2-City.mmdb and GeoLite2-ASN.mmdb.
	GeoIPDir string `koanf:"geoip_dir"`
	// Threshold is the deploy_p cutoff above which a URL is classified as phishing (0–1).
	Threshold float64 `koanf:"threshold"`
}

// Validate sanity-checks PhishingConfig fields. Called explicitly by svc-03 during
// startup; not called in the global Config.Validate() pass.
func (p PhishingConfig) Validate() error {
	if strings.TrimSpace(p.SidecarURL) == "" {
		return errors.New("phishing.sidecar_url is required (CYBERSIREN_PHISHING__SIDECAR_URL)")
	}
	if p.Threshold <= 0 || p.Threshold >= 1 {
		return fmt.Errorf("phishing.threshold must be in (0, 1), got %v", p.Threshold)
	}
	return nil
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

// AttachmentConfig holds configuration for SVC-05 Attachment Analysis Service.
//
// The VirusTotal credential and HTTP client settings are reused from
// Enrichment.VirusTotal (the single source of truth for the VT key — see
// VirusTotalConfig); this section only carries the attachment-scoring knobs:
// the VT result cache TTL and the heuristic score impacts described in
// ARCH-SPEC §1-step3c. None of the heuristic weights have been calibrated
// against a labeled corpus; they are exposed so they can be tuned without a
// code change.
//
// Validation is opt-in — services that do not run attachment analysis skip
// Validate(); it is NOT run during the global Config.Validate() pass.
type AttachmentConfig struct {
	// VTCacheTTL is how long a VirusTotal hash result is cached in
	// enrichment_results (provider="virustotal"). ARCH-SPEC §1-step3c
	// specifies 24h.
	VTCacheTTL time.Duration `koanf:"vt_cache_ttl"`

	// EntropyThreshold is the Shannon-entropy value above which the
	// high-entropy heuristic fires (default 7.5; bytes have a max of 8.0).
	EntropyThreshold float64 `koanf:"entropy_threshold"`

	// Score impacts for each heuristic. The per-attachment score is the sum
	// of fired heuristics, clamped to 0–100; the per-email score is the max
	// across attachments. Defaults match ARCH-SPEC §1-step3c.
	HighEntropyScore       int `koanf:"high_entropy_score"`       // entropy > threshold (default 20)
	ExtensionMismatchScore int `koanf:"extension_mismatch_score"` // extension vs MIME mismatch (default 30)
	DangerousExtScore      int `koanf:"dangerous_ext_score"`      // .exe/.scr/.bat/… (default 25)
	MacroOfficeScore       int `koanf:"macro_office_score"`       // .docm/.xlsm/.pptm (default 20)
	DoubleExtScore         int `koanf:"double_ext_score"`         // .pdf.exe (default 35)
	MaliciousHashScore     int `koanf:"malicious_hash_score"`     // attachment_library hit (default 90)

	// ConsumeTopic / ProduceTopic / ConsumerGroup are exposed for tests and
	// compose overrides. Defaults match ARCH-SPEC §3.
	ConsumeTopic  string `koanf:"consume_topic"`
	ProduceTopic  string `koanf:"produce_topic"`
	ConsumerGroup string `koanf:"consumer_group"`
}

// Validate sanity-checks AttachmentConfig. Called explicitly by SVC-05 during
// startup; not part of the global Config.Validate() pass so other services can
// keep the default zero values without surprise failures.
func (a AttachmentConfig) Validate() error {
	if a.VTCacheTTL <= 0 {
		return fmt.Errorf("attachment.vt_cache_ttl must be > 0, got %v", a.VTCacheTTL)
	}
	if a.EntropyThreshold <= 0 || a.EntropyThreshold > 8 {
		return fmt.Errorf("attachment.entropy_threshold must be in (0, 8], got %v", a.EntropyThreshold)
	}
	for _, s := range []struct {
		name string
		val  int
	}{
		{"attachment.high_entropy_score", a.HighEntropyScore},
		{"attachment.extension_mismatch_score", a.ExtensionMismatchScore},
		{"attachment.dangerous_ext_score", a.DangerousExtScore},
		{"attachment.macro_office_score", a.MacroOfficeScore},
		{"attachment.double_ext_score", a.DoubleExtScore},
		{"attachment.malicious_hash_score", a.MaliciousHashScore},
	} {
		if s.val < 0 || s.val > 100 {
			return fmt.Errorf("%s must be in [0, 100], got %d", s.name, s.val)
		}
	}
	if strings.TrimSpace(a.ConsumeTopic) == "" {
		return errors.New("attachment.consume_topic is required")
	}
	if strings.TrimSpace(a.ProduceTopic) == "" {
		return errors.New("attachment.produce_topic is required")
	}
	if strings.TrimSpace(a.ConsumerGroup) == "" {
		return errors.New("attachment.consumer_group is required")
	}
	return nil
}

// NotificationConfig holds configuration for SVC-09 Notification Service: the
// SMTP email channel and the generic webhook POST channel (ARCH-SPEC §1-step6a).
// Slack/Teams are out of scope (P2). The per-org threshold and channel list
// live in the organisations table (migration 030), not here — this section is
// purely the transport credentials and client tuning.
//
// Validation is opt-in. SVC-09 calls Validate() at startup; only the channels
// it actually enables need to be fully configured (an org may run webhook-only
// or email-only), so Validate() checks a channel's fields only when that
// channel is enabled.
type NotificationConfig struct {
	SMTP    SMTPConfig    `koanf:"smtp"`
	Webhook WebhookConfig `koanf:"webhook"`
}

// Validate checks the enabled notification channels. Disabled channels are not
// validated so a deployment can run with only one transport configured.
func (n NotificationConfig) Validate() error {
	if n.SMTP.Enabled {
		if err := n.SMTP.Validate(); err != nil {
			return err
		}
	}
	if n.Webhook.Enabled {
		if err := n.Webhook.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// SMTPConfig holds the SMTP relay settings for the email-alert channel.
// Credentials must come from secrets, never committed YAML.
type SMTPConfig struct {
	// Enabled toggles the email channel. When false the rest is ignored.
	Enabled bool `koanf:"enabled"`

	Host string `koanf:"host"`
	Port int    `koanf:"port"`

	Username string `koanf:"username"`
	Password string `koanf:"password"`

	// From is the envelope/header From address used for outgoing alerts.
	From string `koanf:"from"`

	// StartTLS requests opportunistic TLS upgrade on a plaintext connection
	// (typical for port 587). When false on port 465 an implicit-TLS dial is
	// expected by the sender. Default true.
	StartTLS bool `koanf:"start_tls"`

	// Timeout bounds the connect+send round-trip per message (default 10s).
	Timeout time.Duration `koanf:"timeout"`
}

// Validate checks the SMTP fields. Only called when the channel is enabled.
func (s SMTPConfig) Validate() error {
	if strings.TrimSpace(s.Host) == "" {
		return errors.New("notification.smtp.host is required when the SMTP channel is enabled")
	}
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("notification.smtp.port must be between 1 and 65535, got %d", s.Port)
	}
	if strings.TrimSpace(s.From) == "" {
		return errors.New("notification.smtp.from is required when the SMTP channel is enabled")
	}
	if s.Timeout <= 0 {
		return fmt.Errorf("notification.smtp.timeout must be > 0, got %v", s.Timeout)
	}
	return nil
}

// WebhookConfig holds the generic outbound webhook (SIEM/SOAR) settings.
type WebhookConfig struct {
	// Enabled toggles the webhook channel. When false the rest is ignored.
	Enabled bool `koanf:"enabled"`

	// URL is the POST target for alert payloads.
	URL string `koanf:"url"`

	// Secret is an optional shared secret; when set the sender signs the body
	// (e.g. via an X-Signature HMAC header). Empty disables signing.
	Secret string `koanf:"secret"`

	// Timeout bounds each POST (default 10s).
	Timeout time.Duration `koanf:"timeout"`

	// MaxRetries caps the retry count for a failed delivery (default 3).
	MaxRetries int `koanf:"max_retries"`
}

// Validate checks the webhook fields. Only called when the channel is enabled.
func (w WebhookConfig) Validate() error {
	if strings.TrimSpace(w.URL) == "" {
		return errors.New("notification.webhook.url is required when the webhook channel is enabled")
	}
	u, err := url.Parse(w.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("notification.webhook.url must be a valid http(s) URL, got %q", w.URL)
	}
	if w.Timeout <= 0 {
		return fmt.Errorf("notification.webhook.timeout must be > 0, got %v", w.Timeout)
	}
	if w.MaxRetries < 0 {
		return fmt.Errorf("notification.webhook.max_retries must be >= 0, got %d", w.MaxRetries)
	}
	return nil
}

// GmailConfig holds the OAuth2 + Pub/Sub settings for the SVC-01 Gmail ingestion
// adapter (ARCH-SPEC §2.1: Gmail API v1, offline access, scope gmail.readonly,
// Google Pub/Sub push → poll messages.get, event-driven + 5-min fallback poll,
// watch() expires every 7 days — auto-renew). The adapter exchanges the offline
// RefreshToken for short-lived access tokens; the client id/secret/redirect
// identify the OAuth app.
//
// All three secret-bearing fields (ClientID, ClientSecret, RefreshToken) and the
// PushToken must come from secrets, never committed YAML. Validation is opt-in:
// only SVC-01 (when the Gmail adapter is enabled) calls Validate().
//
// Delivery model. The spec's primary trigger is a Pub/Sub PUSH notification: a
// watch() registration tells Gmail to publish a tiny {emailAddress, historyId}
// notification to a Pub/Sub topic, whose push subscription POSTs it to svc-01's
// /gmail/push endpoint; the adapter then fetches new messages via the Gmail
// history API. A fallback poll loop (history.list every PollInterval) catches
// anything missed while the webhook was unreachable. Either path feeds the SAME
// ingestion core, so dedup/quota/UUIDv7 apply uniformly.
type GmailConfig struct {
	// Enabled toggles the Gmail adapter. When false the rest is ignored so
	// that deployments running API-upload only are not forced to configure
	// OAuth.
	Enabled bool `koanf:"enabled"`

	ClientID     string `koanf:"client_id"`
	ClientSecret string `koanf:"client_secret"`

	// RedirectURL is the OAuth2 redirect/callback URI registered with the app.
	RedirectURL string `koanf:"redirect_url"`

	// RefreshToken is the long-lived offline token obtained during the consent
	// flow; the adapter mints access tokens from it.
	RefreshToken string `koanf:"refresh_token"`

	// Scopes the adapter requests. Defaults to gmail.readonly per ARCH-SPEC §2.1.
	Scopes []string `koanf:"scopes"`

	// User is the mailbox the adapter watches/polls. Gmail accepts "me" (the
	// authenticated user) or an email address. Default "me".
	User string `koanf:"user"`

	// OrgID is the tenant the watched mailbox belongs to. A Pub/Sub push
	// carries no API key, so the adapter binds ingested mail to this org (the
	// org still comes from configuration, NOT the request body — G10). The
	// quota/dedup/RLS path is identical to an API-key ingest.
	OrgID int64 `koanf:"org_id"`

	// WatchTopic is the FULLY-QUALIFIED Pub/Sub topic the watch() call targets,
	// e.g. projects/my-project/topics/gmail-push. Required for push.
	WatchTopic string `koanf:"watch_topic"`

	// LabelIDs filters which Gmail labels watch() reacts to (default ["INBOX"]).
	LabelIDs []string `koanf:"label_ids"`

	// PushEnabled enables the /gmail/push webhook handler + watch() registration.
	PushEnabled bool `koanf:"push_enabled"`

	// PushToken is a shared secret appended as ?token=... to the push
	// subscription endpoint URL; the handler rejects requests whose token does
	// not match. This is the lightweight verification of a push message when an
	// OIDC audience is not configured. Empty disables token verification (the
	// runbook recommends setting it).
	PushToken string `koanf:"push_token"`

	// PushAudience, when set, is the expected `aud` claim of the OIDC bearer
	// token Google signs the push request with (push subscriptions configured
	// with a service-account identity). Empty disables OIDC verification and
	// relies on PushToken instead.
	PushAudience string `koanf:"push_audience"`

	// PollEnabled enables the fallback history.list poll loop.
	PollEnabled bool `koanf:"poll_enabled"`

	// PollInterval is the fallback delta-poll cadence used when Pub/Sub push
	// is unavailable (default 5m, matching the spec's 5-min fallback).
	PollInterval time.Duration `koanf:"poll_interval"`

	// HTTPTimeout bounds each Gmail API round-trip (default 30s).
	HTTPTimeout time.Duration `koanf:"http_timeout"`

	// APIBaseURL / TokenURL are overridable so the recorded-fixture tests can
	// point the adapter at an httptest server. Empty falls back to the real
	// Google endpoints.
	APIBaseURL string `koanf:"api_base_url"`
	TokenURL   string `koanf:"token_url"`
}

// Validate checks the Gmail OAuth fields. Only called when the adapter is
// enabled (API-upload-only deployments skip it).
func (g GmailConfig) Validate() error {
	if strings.TrimSpace(g.ClientID) == "" {
		return errors.New("gmail.client_id is required when the Gmail adapter is enabled")
	}
	if strings.TrimSpace(g.ClientSecret) == "" {
		return errors.New("gmail.client_secret is required when the Gmail adapter is enabled")
	}
	if strings.TrimSpace(g.RefreshToken) == "" {
		return errors.New("gmail.refresh_token is required when the Gmail adapter is enabled")
	}
	if len(g.Scopes) == 0 {
		return errors.New("gmail.scopes must contain at least one scope when the Gmail adapter is enabled")
	}
	if g.OrgID <= 0 {
		return errors.New("gmail.org_id is required (the tenant the watched mailbox belongs to) when the Gmail adapter is enabled")
	}
	if g.PollInterval <= 0 {
		return fmt.Errorf("gmail.poll_interval must be > 0, got %v", g.PollInterval)
	}
	if g.HTTPTimeout <= 0 {
		return fmt.Errorf("gmail.http_timeout must be > 0, got %v", g.HTTPTimeout)
	}
	if !g.PushEnabled && !g.PollEnabled {
		return errors.New("gmail: at least one of push_enabled or poll_enabled must be true when the adapter is enabled")
	}
	if g.PushEnabled && strings.TrimSpace(g.WatchTopic) == "" {
		return errors.New("gmail.watch_topic is required when push is enabled (projects/<id>/topics/<name>)")
	}
	return nil
}
