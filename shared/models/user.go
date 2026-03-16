package models

import (
	"time"
)

// UserRole mirrors the user_role Postgres ENUM.
type UserRole string

const (
	UserRoleAdmin   UserRole = "admin"
	UserRoleAnalyst UserRole = "analyst"
	UserRoleViewer  UserRole = "viewer"
)

// APIKeyWithRawKey is returned once at creation time only.
// The RawKey is never stored — this is the caller's only chance to save it.
type APIKeyWithRawKey struct {
	ID        int64      `json:"id"`
	OrgID     int64      `json:"org_id"`
	UserID    *int64     `json:"user_id,omitempty"`
	Name      string     `json:"name"`
	KeyPrefix string     `json:"key_prefix"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	RawKey    string     `json:"raw_key"`
}

// JobStatus mirrors the job_status Postgres ENUM.
type JobStatus string

const (
	JobStatusPending    JobStatus = "pending"
	JobStatusInProgress JobStatus = "in_progress"
	JobStatusCompleted  JobStatus = "completed"
	JobStatusFailed     JobStatus = "failed"
	JobStatusSkipped    JobStatus = "skipped"
)

// JobType mirrors the job_type Postgres ENUM.
type JobType string

const (
	JobTypeWHOIS      JobType = "whois"
	JobTypeDNS        JobType = "dns"
	JobTypeASN        JobType = "asn"
	JobTypeIPGeo      JobType = "ip_geo"
	JobTypeSSLCert    JobType = "ssl_cert"
	JobTypeURLScan    JobType = "url_scan"
	JobTypeVirusTotal JobType = "virustotal"
	JobTypeFeedIngest JobType = "feed_ingest"
	JobTypeRuleEval   JobType = "rule_eval"
)
