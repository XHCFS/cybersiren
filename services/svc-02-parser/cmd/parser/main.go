// svc-02-parser is the Email Parser Service. It consumes emails.raw, decodes
// the base64 RFC-822 source, walks the MIME tree, and:
//
//   - extracts every URL (HTML href/src/action/meta-refresh + plain text) with
//     per-URL context, the sender identity + auth headers, the HTML and HTML-
//     stripped plain-text bodies, every attachment (hashed + entropy + magic-
//     byte type), and the recipient list;
//   - uploads each attachment binary to object storage (G6) and records its
//     storage_uri;
//   - persists the 6 SVC-02 write-groups (emails, enriched_threats, email_urls,
//     attachment_library, email_attachments, email_recipients) atomically under
//     one org GUC (ARCH-SPEC §14 step 2, G10 RLS);
//   - fans out to the 5 analysis.* topics, carrying BOTH ids (the logical
//     email_id and the DB-assigned internal_id + fetched_at — G5/G17 two-id
//     model) and shipping the body content on analysis.headers (D9).
//
// See docs/architecture/architecture-spec-detail.html §1 step 2 + §14 step 2.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	db "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/services/svc-02-parser/internal/email"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/normalization"
	"github.com/saif/cybersiren/shared/objectstore"
	"github.com/saif/cybersiren/shared/postgres/pgconv"
	"github.com/saif/cybersiren/shared/postgres/repository"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-02-parser"

func main() {
	app := &parserApp{}

	outputs := []string{
		contracts.TopicAnalysisURLs,
		contracts.TopicAnalysisHeaders,
		contracts.TopicAnalysisAttachments,
		contracts.TopicAnalysisText,
		contracts.TopicAnalysisPlans,
	}

	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsDB:        true,
		ProducerTopics: outputs,
		ConsumerTopics: []string{contracts.TopicEmailsRaw},
		GroupID:        contracts.GroupParser,
		OnReady:        app.onReady,
		Handler:        app.handle,
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

// parserApp holds the resources the handler needs beyond svckit.Deps: the
// object store (attachment binaries, G6), the email repository (the 6
// org-scoped write-groups), and the per-message metrics. They are constructed
// once in onReady.
type parserApp struct {
	store   objectstore.Store
	repo    *repository.EmailRepository
	metrics *parserMetrics
}

// onReady connects the object store and builds the email repository. The store
// is optional in dev — if it cannot be reached the service still parses and
// persists, just without storage_uri (logged as a warning).
func (a *parserApp) onReady(ctx context.Context, deps svckit.Deps) error {
	a.repo = repository.NewEmailRepository(deps.Pool)
	a.metrics = newParserMetrics(deps.Registry)

	store, err := objectstore.New(ctx, objectstore.Config{
		Endpoint:     deps.Cfg.Storage.Endpoint,
		Bucket:       deps.Cfg.Storage.Bucket,
		Region:       deps.Cfg.Storage.Region,
		AccessKey:    deps.Cfg.Storage.AccessKey,
		SecretKey:    deps.Cfg.Storage.SecretKey,
		UseSSL:       deps.Cfg.Storage.UseSSL,
		CreateBucket: true,
	}, deps.Log)
	if err != nil {
		// G6: attachment binaries MUST be retained, so object storage is REQUIRED.
		// Fail to start rather than silently persist blob-less attachment_library
		// rows (storage_uri NULL). Local dev: `make up-infra` runs MinIO and the
		// pipeline runner sets CYBERSIREN_STORAGE__*; compose wiring is Batch 7.
		if deps.Cfg.Storage.Endpoint == "" {
			return fmt.Errorf("object storage not configured (set CYBERSIREN_STORAGE__*); cannot retain attachment binaries (G6): %w", err)
		}
		return fmt.Errorf("object store configured (%s) but unavailable: %w", deps.Cfg.Storage.Endpoint, err)
	}
	a.store = store
	return nil
}

func (a *parserApp) handle(ctx context.Context, msg kafkaconsumer.Message, deps svckit.Deps) error {
	var raw contracts.EmailsRaw
	if err := json.Unmarshal(msg.Value, &raw); err != nil {
		// Permanent bad data: a payload that does not decode will never decode
		// on redelivery, so drop it and let the offset commit rather than block
		// the partition.
		a.metrics.dropped()
		deps.Log.Error().Err(err).
			Int("partition", msg.Partition).
			Int64("offset", msg.Offset).
			Int64("email_id", raw.Meta.EmailID).
			Msg("malformed emails.raw payload; skipping (offset will commit)")
		return nil
	}
	if raw.Meta.OrgID <= 0 {
		// Permanent bad data: RLS requires a real org on every write; a missing
		// org is unroutable and cannot be fixed by redelivery, so drop it.
		a.metrics.dropped()
		deps.Log.Error().Err(fmt.Errorf("emails.raw has no org_id")).
			Int("partition", msg.Partition).
			Int64("offset", msg.Offset).
			Int64("email_id", raw.Meta.EmailID).
			Msg("emails.raw missing org_id; skipping (offset will commit)")
		return nil
	}

	rawBytes, err := base64.StdEncoding.DecodeString(raw.RawMessageB64)
	if err != nil {
		// Permanent bad data: an undecodable base64 body will never decode on
		// redelivery, so drop it and let the offset commit.
		a.metrics.dropped()
		deps.Log.Error().Err(err).
			Int("partition", msg.Partition).
			Int64("offset", msg.Offset).
			Int64("email_id", raw.Meta.EmailID).
			Msg("undecodable raw_rfc822 base64; skipping (offset will commit)")
		return nil
	}

	parsed, err := email.Parse(rawBytes)
	if err != nil {
		// A non-RFC822 / malformed-MIME body must NOT be silently dropped: it may
		// still carry a phish URL or body text that has to reach a verdict. Build
		// a DEGRADED parse from the raw bytes (best-effort body + URL extraction)
		// and fall through to the normal persist+publish flow rather than losing
		// the email.
		a.metrics.degraded()
		deps.Log.Warn().Err(err).
			Int("partition", msg.Partition).
			Int64("offset", msg.Offset).
			Int64("email_id", raw.Meta.EmailID).
			Msg("unparsable rfc822 message; persisting a degraded parse (no headers, best-effort body)")
		parsed = degradedParse(rawBytes)
	}

	fetchedAt := raw.FetchedAt
	if fetchedAt.IsZero() {
		fetchedAt = time.Now().UTC()
	}

	// Derive the sender identity, auth results, and flattened headers JSON ONCE
	// and thread them through the builders so splitAddress/ParseAuthResults/
	// headerMapJSON each run a single time per email.
	hv := newHeaderView(parsed)

	// Upload each attachment binary to object storage (G6) and record the
	// storage_uri so attachment_library points at the persisted blob. A real
	// upload failure (store configured) is surfaced so handle() returns and Kafka
	// redelivers — G6 requires the binary be retained, not persisted blob-less.
	storageURIs, err := a.uploadAttachments(ctx, deps, parsed.Attachments)
	if err != nil {
		return fmt.Errorf("upload attachments: %w", err)
	}

	// Persist the 6 write-groups atomically under one org GUC, capturing the
	// DB-assigned (internal_id, fetched_at) composite key (G5/G17).
	key, err := a.repo.PersistParsed(ctx, raw.Meta.OrgID, buildPersist(raw, parsed, hv, fetchedAt, storageURIs))
	if err != nil {
		return fmt.Errorf("persist parsed email: %w", err)
	}

	if err := a.publishAll(ctx, deps, raw, parsed, hv, key, fetchedAt, storageURIs); err != nil {
		return err
	}

	a.metrics.processed()
	deps.Log.Info().
		Int64("email_id", raw.Meta.EmailID).
		Int64("internal_id", key.InternalID).
		Int("urls", len(parsed.URLs)).
		Int("attachments", len(parsed.Attachments)).
		Int("recipients", len(parsed.Recipients)).
		Bool("has_body", parsed.HasBody()).
		Msg("parsed, persisted, and fanned out")
	return nil
}

// uploadAttachments stores each attachment binary in object storage and returns
// the storage_uri per attachment index. When the store is absent (Batch-7 env
// gap) it returns empty URIs and a nil error so persistence proceeds without the
// pointer. When the store IS configured a Put failure is RETURNED (not swallowed)
// so handle() fails and Kafka redelivers the message — G6 requires the binary be
// retained rather than persisting an attachment_library row with no storage_uri.
func (a *parserApp) uploadAttachments(ctx context.Context, deps svckit.Deps, atts []email.Attachment) ([]string, error) {
	uris := make([]string, len(atts))
	if a.store == nil {
		return uris, nil
	}
	for i, att := range atts {
		key := attachmentObjectKey(att.SHA256)
		info, err := a.store.Put(ctx, key, bytes.NewReader(att.Data), objectstore.PutOptions{
			ContentType: att.ContentType,
			Size:        att.SizeBytes,
		})
		if err != nil {
			deps.Log.Warn().Err(err).Str("sha256", att.SHA256).Msg("attachment upload failed; will retry on redelivery")
			return nil, fmt.Errorf("put attachment %s: %w", att.SHA256, err)
		}
		uris[i] = fmt.Sprintf("s3://%s/%s", a.store.Bucket(), info.Key)
	}
	return uris, nil
}

// attachmentObjectKey is the content-addressed object key for an attachment:
// sha256-fanned (ab/cd/<sha256>) so the directory does not grow unbounded in
// one node. attachment_library is a global content-addressed table, so the key
// is org-agnostic — identical bytes map to one blob across tenants.
func attachmentObjectKey(sha256hex string) string {
	h := sha256hex
	if len(h) < 4 {
		// Defensive: a missing/short hash should still produce a stable key.
		sum := sha256.Sum256([]byte(sha256hex))
		h = hex.EncodeToString(sum[:])
	}
	return fmt.Sprintf("attachments/%s/%s/%s", h[0:2], h[2:4], h)
}

// degradedParse builds a best-effort *email.ParsedEmail from raw bytes that
// could not be parsed as RFC-822, so a malformed message still reaches a verdict
// instead of being dropped. It carries no headers (empty mail.Header) and no
// attachments/recipients; the body is the raw text (HTML-stripped when it looks
// like markup) and the URL list is whatever ExtractURLsFromText finds — a
// malformed phish link is still scored.
func degradedParse(rawBytes []byte) *email.ParsedEmail {
	raw := string(rawBytes)
	var urls []email.ExtractedURL
	bodyPlain := raw
	if strings.Contains(raw, "<") {
		// Looks like HTML: pull URLs out of href/src/action/meta-refresh BEFORE
		// stripping (HTMLToText drops attribute values, so extracting only from the
		// stripped text would lose every anchor link — the dominant phish case),
		// then render the markup to clean text for the NLP body.
		urls = email.ExtractURLsFromHTML(raw)
		bodyPlain = email.HTMLToText(raw)
	}
	bodyPlain = collapseSpaces(bodyPlain)
	urls = email.DedupeURLs(append(urls, email.ExtractURLsFromText(bodyPlain)...))
	return &email.ParsedEmail{
		Header:    mail.Header{},
		BodyPlain: bodyPlain,
		URLs:      urls,
	}
}

// collapseSpaces collapses runs of whitespace in s to single spaces and trims
// the ends, matching the clean plain-text shape the parser produces for a
// well-formed body.
func collapseSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// publishAll marshals and publishes the 5 analysis.* messages, keyed by the
// logical email_id partition key.
func (a *parserApp) publishAll(
	ctx context.Context,
	deps svckit.Deps,
	raw contracts.EmailsRaw,
	parsed *email.ParsedEmail,
	hv headerView,
	key repository.EmailKey,
	fetchedAt time.Time,
	storageURIs []string,
) error {
	emailID := raw.Meta.EmailID
	orgID := raw.Meta.OrgID
	meta := contracts.NewMetaWithFetched(emailID, orgID, fetchedAt)
	kafkaKey := []byte(strconv.FormatInt(emailID, 10))

	headersMsg := buildAnalysisHeaders(emailID, key.InternalID, orgID, fetchedAt, parsed, hv)

	out := []struct {
		topic   string
		payload any
	}{
		{contracts.TopicAnalysisURLs, buildAnalysisURLs(meta, key.InternalID, parsed)},
		{contracts.TopicAnalysisHeaders, headersMsg},
		{
			contracts.TopicAnalysisAttachments,
			contracts.AnalysisAttachments{Meta: meta, InternalID: key.InternalID, Attachments: toContractAttachments(parsed.Attachments)},
		},
		{contracts.TopicAnalysisText, buildAnalysisText(meta, parsed, hv)},
		{contracts.TopicAnalysisPlans, buildAnalysisPlan(meta, parsed)},
	}

	for _, o := range out {
		payload, err := json.Marshal(o.payload)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", o.topic, err)
		}
		prod, ok := deps.Producers[o.topic]
		if !ok {
			return fmt.Errorf("svc-02: producer %s not configured", o.topic)
		}
		if err := prod.Publish(ctx, kafkaKey, payload, 1); err != nil {
			return fmt.Errorf("publish %s: %w", o.topic, err)
		}
	}
	return nil
}

// buildPersist maps the parsed email onto the repository's 6-write-group input.
func buildPersist(
	raw contracts.EmailsRaw,
	parsed *email.ParsedEmail,
	hv headerView,
	fetchedAt time.Time,
	storageURIs []string,
) repository.PersistParsedFull {
	h := parsed.Header
	msgID := messageID(raw, h)

	emailParams := db.InsertEmailParams{
		FetchedAt:      pgconv.Timestamptz(fetchedAt),
		OrgID:          pgconv.Int8(raw.Meta.OrgID),
		MessageID:      pgconv.Text(msgID),
		SenderName:     pgconv.Text(hv.fromName),
		SenderEmail:    pgconv.Text(hv.fromAddr),
		SenderDomain:   pgconv.Text(hv.senderDomain),
		ReplyToEmail:   pgconv.Text(addressOnly(h.Get("Reply-To"))),
		ReturnPath:     pgconv.Text(addressOnly(h.Get("Return-Path"))),
		OriginatingIp:  originatingAddr(h),
		AuthSpf:        pgconv.Text(hv.auth["spf"]),
		AuthDkim:       pgconv.Text(hv.auth["dkim"]),
		AuthDmarc:      pgconv.Text(hv.auth["dmarc"]),
		AuthArc:        pgconv.Text(hv.auth["arc"]),
		XOriginatingIp: parseIP(h.Get("X-Originating-IP")),
		MailerAgent:    pgconv.Text(h.Get("X-Mailer")),
		InReplyTo:      pgconv.Text(h.Get("In-Reply-To")),
		ReferencesList: splitReferences(h.Get("References")),
		ContentCharset: pgconv.Text(charsetFrom(h.Get("Content-Type"))),
		Precedence:     pgconv.Text(h.Get("Precedence")),
		ListID:         pgconv.Text(h.Get("List-Id")),
		Subject:        pgconv.Text(parsed.Subject),
		SentTimestamp:  pgconv.Int8OrNull(sentTimestamp(h.Get("Date"))),
		HeadersJson:    hv.headersJSON,
		BodyPlain:      pgconv.Text(parsed.BodyPlain),
		BodyHtml:       pgconv.Text(parsed.BodyHTML),
	}

	urls := make([]repository.ParsedURL, 0, len(parsed.URLs))
	for _, u := range parsed.URLs {
		domain, _ := normalization.ExtractDomain(u.URL)
		urls = append(urls, repository.ParsedURL{
			URL:         u.URL,
			Domain:      pgconv.Text(domain),
			TLD:         pgconv.Text(normalization.TLDLabel(domain)),
			VisibleText: pgconv.Text(u.VisibleText),
		})
	}

	atts := make([]repository.ParsedAttachment, 0, len(parsed.Attachments))
	for i, att := range parsed.Attachments {
		atts = append(atts, repository.ParsedAttachment{
			Library: db.UpsertParsedAttachmentParams{
				Sha256:          att.SHA256,
				Md5:             pgconv.Text(att.MD5),
				Sha1:            pgconv.Text(att.SHA1),
				ActualExtension: pgconv.Text(att.ActualExtension()),
				SizeBytes:       pgconv.Int8(att.SizeBytes),
				Entropy:         pgconv.Float8(att.Entropy),
				StorageUri:      pgconv.Text(storageURIAt(storageURIs, i)),
			},
			Filename:    pgconv.Text(att.Filename),
			ContentType: pgconv.Text(att.ContentType),
			ContentID:   pgconv.Text(att.ContentID),
			Disposition: pgconv.Text(att.Disposition),
		})
	}

	recips := make([]repository.ChildRecipient, 0, len(parsed.Recipients))
	for _, rc := range parsed.Recipients {
		recips = append(recips, repository.ChildRecipient{
			Address:       rc.Address,
			DisplayName:   pgconv.Text(rc.DisplayName),
			RecipientType: rc.Type,
		})
	}

	return repository.PersistParsedFull{
		Email:       emailParams,
		MessageID:   msgID,
		URLs:        urls,
		Attachments: atts,
		Recipients:  recips,
	}
}

// buildAnalysisHeaders projects the parsed headers + body onto svc-04's
// AnalysisHeadersMessage, carrying BOTH ids (G5/G17) and the body content (D9 —
// the parser ships the body, svc-04 computes the structural flags).
func buildAnalysisHeaders(
	emailID, internalID, orgID int64,
	fetchedAt time.Time,
	parsed *email.ParsedEmail,
	hv headerView,
) contracts.AnalysisHeadersMessage {
	h := parsed.Header

	return contracts.AnalysisHeadersMessage{
		EmailID:          emailID,
		InternalID:       internalID,
		FetchedAt:        fetchedAt,
		OrgID:            orgID,
		SenderEmail:      hv.fromAddr,
		SenderDomain:     hv.senderDomain,
		SenderName:       hv.fromName,
		ReplyToEmail:     addressOnly(h.Get("Reply-To")),
		ReturnPath:       addressOnly(h.Get("Return-Path")),
		MailerAgent:      h.Get("X-Mailer"),
		OriginatingIP:    addrString(originatingAddr(h)),
		XOriginatingIP:   addrString(parseIP(h.Get("X-Originating-IP"))),
		AuthSPF:          hv.auth["spf"],
		AuthDKIM:         hv.auth["dkim"],
		AuthDMARC:        hv.auth["dmarc"],
		AuthARC:          hv.auth["arc"],
		InReplyTo:        h.Get("In-Reply-To"),
		ReferencesList:   splitReferences(h.Get("References")),
		SentTimestamp:    sentTimestamp(h.Get("Date")),
		ContentCharset:   charsetFrom(h.Get("Content-Type")),
		Precedence:       h.Get("Precedence"),
		ListID:           h.Get("List-Id"),
		HopCount:         hopCount(h),
		ReceivedChain:    receivedChain(h),
		HeadersJSON:      hv.headersJSON,
		BodyHTML:         parsed.BodyHTML,
		BodyPlain:        parsed.BodyPlain,
		BodyCharset:      parsed.BodyCharset,
		PlainSynthesised: parsed.PlainSynthesised,
	}
}

// buildAnalysisURLs projects the extracted URLs onto the analysis.urls contract,
// stamping the DB-assigned internal_id so svc-03 can look up email_urls by the
// real surrogate key (mirrors analysis.headers' InternalID — G5/G17 two-id
// model; Meta.EmailID stays the logical id).
func buildAnalysisURLs(meta contracts.MessageMeta, internalID int64, parsed *email.ParsedEmail) contracts.AnalysisURLs {
	return contracts.AnalysisURLs{
		Meta:       meta,
		InternalID: internalID,
		URLs:       toContractURLs(parsed.URLs),
	}
}

func buildAnalysisText(meta contracts.MessageMeta, parsed *email.ParsedEmail, hv headerView) contracts.AnalysisText {
	return contracts.AnalysisText{
		Meta:         meta,
		Subject:      parsed.Subject,
		SenderName:   hv.fromName,
		SenderDomain: hv.senderDomain,
		Body:         parsed.BodyPlain,
		WordCount:    email.WordCount(parsed.BodyPlain),
	}
}

func buildAnalysisPlan(meta contracts.MessageMeta, parsed *email.ParsedEmail) contracts.AnalysisPlan {
	expected := []string{contracts.TopicScoresHeader}
	if len(parsed.URLs) > 0 {
		expected = append(expected, contracts.TopicScoresURL)
	}
	if len(parsed.Attachments) > 0 {
		expected = append(expected, contracts.TopicScoresAttachment)
	}
	if parsed.HasBody() {
		expected = append(expected, contracts.TopicScoresNLP)
	}
	return contracts.AnalysisPlan{
		Meta:            meta,
		ExpectedScores:  expected,
		URLCount:        len(parsed.URLs),
		AttachmentCount: len(parsed.Attachments),
		HasBody:         parsed.HasBody(),
		CreatedAt:       time.Now().UTC().UnixMilli(),
	}
}

func toContractURLs(in []email.ExtractedURL) []contracts.ExtractedURL {
	out := make([]contracts.ExtractedURL, 0, len(in))
	for _, u := range in {
		out = append(out, contracts.ExtractedURL{
			URL:         u.URL,
			VisibleText: u.VisibleText,
			Position:    u.Position,
			HTMLContext: u.HTMLContext,
		})
	}
	return out
}

func toContractAttachments(in []email.Attachment) []contracts.Attachment {
	out := make([]contracts.Attachment, 0, len(in))
	for _, a := range in {
		out = append(out, contracts.Attachment{
			SHA256:       a.SHA256,
			MD5:          a.MD5,
			SHA1:         a.SHA1,
			Filename:     a.Filename,
			ContentType:  a.ContentType,
			ContentID:    a.ContentID,
			Disposition:  a.Disposition,
			SizeBytes:    a.SizeBytes,
			Entropy:      a.Entropy,
			DetectedType: a.DetectedType,
		})
	}
	return out
}

// ── derived header view ─────────────────────────────────────────────────────

// headerView holds the values derived once per email from the raw headers so
// that splitAddress(From), ParseAuthResults, and headerMapJSON each run a
// single time and are shared by buildPersist / buildAnalysisHeaders /
// buildAnalysisText instead of being recomputed in each builder.
type headerView struct {
	fromAddr     string
	fromName     string
	senderDomain string
	auth         map[string]string
	headersJSON  []byte
}

// newHeaderView derives the shared header view from a parsed email.
func newHeaderView(parsed *email.ParsedEmail) headerView {
	h := parsed.Header
	fromAddr, fromName := splitAddress(h.Get("From"))
	return headerView{
		fromAddr:     fromAddr,
		fromName:     fromName,
		senderDomain: domainOf(fromAddr),
		auth:         email.ParseAuthResults(h.Get("Authentication-Results")),
		headersJSON:  headerMapJSON(h),
	}
}

// ── small header / value helpers ────────────────────────────────────────────

func storageURIAt(uris []string, i int) string {
	if i < 0 || i >= len(uris) {
		return ""
	}
	return uris[i]
}

func messageID(raw contracts.EmailsRaw, h mail.Header) string {
	if raw.MessageID != "" {
		return raw.MessageID
	}
	return strings.Trim(h.Get("Message-Id"), "<>")
}

func splitAddress(raw string) (addr, name string) {
	a, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw), ""
	}
	return a.Address, a.Name
}

func addressOnly(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	a, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	return a.Address
}

func domainOf(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}

func splitReferences(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	fields := strings.Fields(raw)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.Trim(f, "<>")
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func charsetFrom(contentType string) string {
	for _, part := range strings.Split(contentType, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "charset=") {
			return strings.Trim(part[len("charset="):], `"`)
		}
	}
	return ""
}

func sentTimestamp(dateStr string) int64 {
	if strings.TrimSpace(dateStr) == "" {
		return 0
	}
	if t, err := mail.ParseDate(dateStr); err == nil {
		return t.Unix()
	}
	return 0
}

func hopCount(h mail.Header) int {
	return len(h["Received"])
}

// parseIP pulls the first IPv4/IPv6 literal out of a header value (e.g. a
// Received line or X-Originating-IP) and returns it as a *netip.Addr suitable
// for the emails.originating_ip / x_originating_ip INET columns. nil when none.
func parseIP(raw string) *netip.Addr {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	// Strip common bracket/paren framing then scan tokens for a valid address.
	repl := strings.NewReplacer("[", " ", "]", " ", "(", " ", ")", " ", ";", " ")
	for _, tok := range strings.Fields(repl.Replace(raw)) {
		tok = strings.Trim(tok, "<>,")
		if addr, err := netip.ParseAddr(tok); err == nil {
			return &addr
		}
	}
	return nil
}

// isPublicAddr reports whether a is a routable public unicast address (not
// private / loopback / link-local / unspecified) — used to pick the
// originating sender's hop out of the Received chain.
func isPublicAddr(a netip.Addr) bool {
	return a.IsValid() && !a.IsPrivate() && !a.IsLoopback() &&
		!a.IsLinkLocalUnicast() && !a.IsUnspecified()
}

// addrString renders an optional address as a string ("" when nil).
func addrString(a *netip.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

// originatingAddr returns the sender's IP: the first PUBLIC address found
// scanning the Received chain from the origin hop (the last/bottom Received
// header) toward the most-recent, falling back to the first address seen.
// NOTE: the topmost Received header is the receiving MX, NOT the origin, so
// mail.Header.Get("Received") (which returns the first/topmost) is the wrong
// hop for sender-IP reputation — we walk from the bottom instead.
func originatingAddr(h mail.Header) *netip.Addr {
	raw := h["Received"]
	var firstAny *netip.Addr
	for i := len(raw) - 1; i >= 0; i-- {
		addr := parseIP(raw[i])
		if addr == nil {
			continue
		}
		if firstAny == nil {
			firstAny = addr
		}
		if isPublicAddr(*addr) {
			return addr
		}
	}
	return firstAny
}

// receivedChain parses every Received header into a hop (header order, so
// index 0 is the most-recent hop). The from/by hosts and the hand-off
// timestamp are best-effort; unparsable parts stay zero. SVC-04 uses this for
// hop-count + timestamp-drift signals (D9 / ARCH-SPEC §3b).
func receivedChain(h mail.Header) []contracts.ReceivedHop {
	raw := h["Received"]
	if len(raw) == 0 {
		return nil
	}
	hops := make([]contracts.ReceivedHop, 0, len(raw))
	for _, r := range raw {
		hop := contracts.ReceivedHop{
			From: receivedToken(r, "from"),
			By:   receivedToken(r, "by"),
		}
		if i := strings.LastIndex(r, ";"); i >= 0 {
			hop.Timestamp = sentTimestamp(r[i+1:])
		}
		hops = append(hops, hop)
	}
	return hops
}

// receivedToken returns the first whitespace-delimited token after the given
// keyword (case-insensitive) in a Received header, stripped of the usual
// bracket/paren framing. "" when the keyword is absent.
func receivedToken(s, keyword string) string {
	fields := strings.Fields(s)
	for i := 0; i+1 < len(fields); i++ {
		if strings.EqualFold(fields[i], keyword) {
			return strings.Trim(fields[i+1], "[]()<>;,")
		}
	}
	return ""
}

// ── metrics ─────────────────────────────────────────────────────────────────

// parserMetrics holds the per-message Prometheus collectors for SVC-02 (the
// shared/kafka package owns the consumer/producer-level counters).
type parserMetrics struct {
	// MessagesTotal is partitioned by result: "ok" for a fully
	// parsed-persisted-published message, "degraded" for a malformed-MIME message
	// persisted+published from a best-effort parse (no headers), and "dropped"
	// for a permanent bad-data message whose offset is committed without
	// processing.
	MessagesTotal *prometheus.CounterVec // result=ok|degraded|dropped
}

// newParserMetrics registers the SVC-02 metrics and returns the holder.
func newParserMetrics(reg *prometheus.Registry) *parserMetrics {
	m := &parserMetrics{}
	m.MessagesTotal = registerParserCounterVec(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "parser_messages_total",
			Help: "Total emails.raw messages handled by SVC-02 partitioned by result.",
		},
		[]string{"result"},
	))
	return m
}

func (m *parserMetrics) processed() {
	if m == nil || m.MessagesTotal == nil {
		return
	}
	m.MessagesTotal.WithLabelValues("ok").Inc()
}

func (m *parserMetrics) degraded() {
	if m == nil || m.MessagesTotal == nil {
		return
	}
	m.MessagesTotal.WithLabelValues("degraded").Inc()
}

func (m *parserMetrics) dropped() {
	if m == nil || m.MessagesTotal == nil {
		return
	}
	m.MessagesTotal.WithLabelValues("dropped").Inc()
}

func registerParserCounterVec(reg *prometheus.Registry, c *prometheus.CounterVec) *prometheus.CounterVec {
	if reg == nil {
		return c
	}
	if err := reg.Register(c); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing
			}
		}
	}
	return c
}

// headerMapJSON flattens the raw header map into headers_json, preserving the
// full list of values per key so repeated headers (e.g. Received,
// Authentication-Results) are not collapsed to their first occurrence.
func headerMapJSON(h mail.Header) []byte {
	flat := make(map[string][]string, len(h))
	for k, vv := range h {
		if len(vv) == 0 {
			continue
		}
		flat[k] = vv
	}
	b, err := json.Marshal(flat)
	if err != nil {
		return nil
	}
	return b
}
