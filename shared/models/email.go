package models

import (
	"encoding/json"
)

// ParsedEmail is the in-memory representation produced by the email parser.
// Pipeline-only — no db tags. The ingestion service maps this into an Email.
type ParsedEmail struct {
	RawHeaders map[string][]string `json:"raw_headers"`
	RawBody    string              `json:"raw_body"`

	MessageID    string `json:"message_id"`
	SenderName   string `json:"sender_name"`
	SenderEmail  string `json:"sender_email"`
	SenderDomain string `json:"sender_domain"`
	ReplyTo      string `json:"reply_to"`
	ReturnPath   string `json:"return_path"`

	AuthSPF        string `json:"auth_spf"`
	AuthDKIM       string `json:"auth_dkim"`
	AuthDMARC      string `json:"auth_dmarc"`
	AuthARC        string `json:"auth_arc"`
	OriginatingIP  string `json:"originating_ip"`
	XOriginatingIP string `json:"x_originating_ip"`
	MailerAgent    string `json:"mailer_agent"`

	InReplyTo      string   `json:"in_reply_to"`
	ReferencesList []string `json:"references_list"`

	Subject        string `json:"subject"`
	SentTimestamp  int64  `json:"sent_timestamp"`
	BodyPlain      string `json:"body_plain"`
	BodyHTML       string `json:"body_html"`
	ContentCharset string `json:"content_charset"`
	Precedence     string `json:"precedence"`
	ListID         string `json:"list_id"`

	URLs        []string           `json:"urls"`
	Attachments []ParsedAttachment `json:"attachments"`
	// VendorSecurityTags carries X-MS-Exchange-Organization-* and similar headers extracted
	// by the parser. Mapped to the vendor_security_tags JSONB column on Email.
	VendorSecurityTags json.RawMessage `json:"vendor_security_tags,omitempty"`
}

// ParsedAttachment holds attachment data extracted during parsing,
// before dedup and library lookup.
type ParsedAttachment struct {
	Filename    string  `json:"filename"`
	ContentType string  `json:"content_type"`
	ContentID   string  `json:"content_id"`
	Disposition string  `json:"disposition"`
	Data        []byte  `json:"-"` // raw bytes — never serialised
	SHA256      string  `json:"sha256"`
	MD5         string  `json:"md5"`
	SHA1        string  `json:"sha1"`
	SizeBytes   int64   `json:"size_bytes"`
	Entropy     float64 `json:"entropy"`
}
