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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/mail"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"

	db "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/services/svc-02-parser/internal/email"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/normalization"
	"github.com/saif/cybersiren/shared/objectstore"
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
// object store (attachment binaries, G6) and the email repository (the 6
// org-scoped write-groups). They are constructed once in onReady.
type parserApp struct {
	store objectstore.Store
	repo  *repository.EmailRepository
}

// onReady connects the object store and builds the email repository. The store
// is optional in dev — if it cannot be reached the service still parses and
// persists, just without storage_uri (logged as a warning).
func (a *parserApp) onReady(ctx context.Context, deps svckit.Deps) error {
	a.repo = repository.NewEmailRepository(deps.Pool)

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
		deps.Log.Warn().Err(err).Msg("object store unavailable; attachments will persist without storage_uri")
		return nil
	}
	a.store = store
	return nil
}

func (a *parserApp) handle(ctx context.Context, msg kafkaconsumer.Message, deps svckit.Deps) error {
	var raw contracts.EmailsRaw
	if err := json.Unmarshal(msg.Value, &raw); err != nil {
		return fmt.Errorf("decode emails.raw: %w", err)
	}
	if raw.Meta.OrgID <= 0 {
		// RLS requires a real org on every write; a missing org is unroutable.
		return fmt.Errorf("svc-02: emails.raw email_id=%d has no org_id", raw.Meta.EmailID)
	}

	rawBytes, err := base64.StdEncoding.DecodeString(raw.RawMessageB64)
	if err != nil {
		return fmt.Errorf("decode raw_rfc822: %w", err)
	}

	parsed, err := email.Parse(rawBytes)
	if err != nil {
		return fmt.Errorf("parse rfc822: %w", err)
	}

	fetchedAt := raw.FetchedAt
	if fetchedAt.IsZero() {
		fetchedAt = time.Now().UTC()
	}

	// Upload each attachment binary to object storage (G6) and record the
	// storage_uri so attachment_library points at the persisted blob.
	storageURIs := a.uploadAttachments(ctx, deps, raw.Meta.OrgID, parsed.Attachments)

	// Persist the 6 write-groups atomically under one org GUC, capturing the
	// DB-assigned (internal_id, fetched_at) composite key (G5/G17).
	key, err := a.repo.PersistParsed(ctx, raw.Meta.OrgID, buildPersist(raw, parsed, fetchedAt, storageURIs))
	if err != nil {
		return fmt.Errorf("persist parsed email: %w", err)
	}

	if err := a.publishAll(ctx, deps, raw, parsed, key, fetchedAt, storageURIs); err != nil {
		return err
	}

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
// the storage_uri per attachment index (empty string when the store is absent
// or the upload failed — persistence still proceeds without the pointer).
func (a *parserApp) uploadAttachments(ctx context.Context, deps svckit.Deps, orgID int64, atts []email.Attachment) []string {
	uris := make([]string, len(atts))
	if a.store == nil {
		return uris
	}
	for i, att := range atts {
		key := attachmentObjectKey(orgID, att.SHA256)
		info, err := a.store.Put(ctx, key, strings.NewReader(string(att.Data)), objectstore.PutOptions{
			ContentType: att.ContentType,
			Size:        att.SizeBytes,
		})
		if err != nil {
			deps.Log.Warn().Err(err).Str("sha256", att.SHA256).Msg("attachment upload failed; persisting without storage_uri")
			continue
		}
		uris[i] = fmt.Sprintf("s3://%s/%s", a.store.Bucket(), info.Key)
	}
	return uris
}

// attachmentObjectKey is the content-addressed object key for an attachment:
// org-scoped and sha256-fanned (ab/cd/<sha256>) so a tenant's blobs stay under
// one prefix and the directory does not grow unbounded in one node.
func attachmentObjectKey(orgID int64, sha256hex string) string {
	h := sha256hex
	if len(h) < 4 {
		// Defensive: a missing/short hash should still produce a stable key.
		sum := sha256.Sum256([]byte(sha256hex))
		h = hex.EncodeToString(sum[:])
	}
	return fmt.Sprintf("attachments/%d/%s/%s/%s", orgID, h[0:2], h[2:4], h)
}

// publishAll marshals and publishes the 5 analysis.* messages, keyed by the
// logical email_id partition key.
func (a *parserApp) publishAll(ctx context.Context, deps svckit.Deps, raw contracts.EmailsRaw, parsed *email.ParsedEmail, key repository.EmailKey, fetchedAt time.Time, storageURIs []string) error {
	emailID := raw.Meta.EmailID
	orgID := raw.Meta.OrgID
	meta := contracts.NewMetaWithFetched(emailID, orgID, fetchedAt)
	kafkaKey := []byte(strconv.FormatInt(emailID, 10))

	headersMsg := buildAnalysisHeaders(emailID, key.InternalID, orgID, fetchedAt, parsed)

	out := []struct {
		topic   string
		payload any
	}{
		{contracts.TopicAnalysisURLs, contracts.AnalysisURLs{Meta: meta, URLs: toContractURLs(parsed.URLs)}},
		{contracts.TopicAnalysisHeaders, headersMsg},
		{contracts.TopicAnalysisAttachments, contracts.AnalysisAttachments{Meta: meta, Attachments: toContractAttachments(parsed.Attachments)}},
		{contracts.TopicAnalysisText, buildAnalysisText(meta, parsed)},
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
func buildPersist(raw contracts.EmailsRaw, parsed *email.ParsedEmail, fetchedAt time.Time, storageURIs []string) repository.PersistParsedFull {
	h := parsed.Header
	fromAddr, fromName := splitAddress(h.Get("From"))
	senderDomain := domainOf(fromAddr)
	auth := email.ParseAuthResults(h.Get("Authentication-Results"))

	headersJSON := headerMapJSON(h)

	emailParams := db.InsertEmailParams{
		FetchedAt:      pgTimestamptz(fetchedAt),
		OrgID:          pgInt8(raw.Meta.OrgID),
		MessageID:      pgText(messageID(raw, h)),
		SenderName:     pgText(fromName),
		SenderEmail:    pgText(fromAddr),
		SenderDomain:   pgText(senderDomain),
		ReplyToEmail:   pgText(addressOnly(h.Get("Reply-To"))),
		ReturnPath:     pgText(addressOnly(h.Get("Return-Path"))),
		OriginatingIp:  originatingAddr(h),
		AuthSpf:        pgText(auth["spf"]),
		AuthDkim:       pgText(auth["dkim"]),
		AuthDmarc:      pgText(auth["dmarc"]),
		AuthArc:        pgText(auth["arc"]),
		XOriginatingIp: parseIP(h.Get("X-Originating-IP")),
		MailerAgent:    pgText(h.Get("X-Mailer")),
		InReplyTo:      pgText(h.Get("In-Reply-To")),
		ReferencesList: splitReferences(h.Get("References")),
		ContentCharset: pgText(charsetFrom(h.Get("Content-Type"))),
		Precedence:     pgText(h.Get("Precedence")),
		ListID:         pgText(h.Get("List-Id")),
		Subject:        pgText(parsed.Subject),
		SentTimestamp:  pgSentTimestamp(h.Get("Date")),
		HeadersJson:    headersJSON,
		BodyPlain:      pgText(parsed.BodyPlain),
		BodyHtml:       pgText(parsed.BodyHTML),
	}

	urls := make([]repository.ParsedURL, 0, len(parsed.URLs))
	for _, u := range parsed.URLs {
		domain, _ := normalization.ExtractDomain(u.URL)
		urls = append(urls, repository.ParsedURL{
			URL:         u.URL,
			Domain:      pgText(domain),
			TLD:         pgText(tldOf(domain)),
			VisibleText: pgText(u.VisibleText),
		})
	}

	atts := make([]repository.ParsedAttachment, 0, len(parsed.Attachments))
	for i, att := range parsed.Attachments {
		atts = append(atts, repository.ParsedAttachment{
			Library: db.UpsertParsedAttachmentParams{
				Sha256:          att.SHA256,
				Md5:             pgText(att.MD5),
				Sha1:            pgText(att.SHA1),
				ActualExtension: pgText(att.ActualExtension()),
				SizeBytes:       pgInt8(att.SizeBytes),
				Entropy:         pgFloat8(att.Entropy),
				StorageUri:      pgText(storageURIAt(storageURIs, i)),
			},
			Filename:    pgText(att.Filename),
			ContentType: pgText(att.ContentType),
			ContentID:   pgText(att.ContentID),
			Disposition: pgText(att.Disposition),
		})
	}

	recips := make([]repository.ChildRecipient, 0, len(parsed.Recipients))
	for _, rc := range parsed.Recipients {
		recips = append(recips, repository.ChildRecipient{
			Address:       rc.Address,
			DisplayName:   pgText(rc.DisplayName),
			RecipientType: rc.Type,
		})
	}

	return repository.PersistParsedFull{
		Email:       emailParams,
		URLs:        urls,
		Attachments: atts,
		Recipients:  recips,
	}
}

// buildAnalysisHeaders projects the parsed headers + body onto svc-04's
// AnalysisHeadersMessage, carrying BOTH ids (G5/G17) and the body content (D9 —
// the parser ships the body, svc-04 computes the structural flags).
func buildAnalysisHeaders(emailID, internalID, orgID int64, fetchedAt time.Time, parsed *email.ParsedEmail) contracts.AnalysisHeadersMessage {
	h := parsed.Header
	fromAddr, fromName := splitAddress(h.Get("From"))
	auth := email.ParseAuthResults(h.Get("Authentication-Results"))

	return contracts.AnalysisHeadersMessage{
		EmailID:        emailID,
		InternalID:     internalID,
		FetchedAt:      fetchedAt,
		OrgID:          orgID,
		SenderEmail:    fromAddr,
		SenderDomain:   domainOf(fromAddr),
		SenderName:     fromName,
		ReplyToEmail:   addressOnly(h.Get("Reply-To")),
		ReturnPath:     addressOnly(h.Get("Return-Path")),
		MailerAgent:    h.Get("X-Mailer"),
		OriginatingIP:  addrString(originatingAddr(h)),
		XOriginatingIP: addrString(parseIP(h.Get("X-Originating-IP"))),
		AuthSPF:        auth["spf"],
		AuthDKIM:       auth["dkim"],
		AuthDMARC:      auth["dmarc"],
		AuthARC:        auth["arc"],
		InReplyTo:      h.Get("In-Reply-To"),
		ReferencesList: splitReferences(h.Get("References")),
		SentTimestamp:  sentTimestamp(h.Get("Date")),
		ContentCharset: charsetFrom(h.Get("Content-Type")),
		Precedence:     h.Get("Precedence"),
		ListID:         h.Get("List-Id"),
		HopCount:       hopCount(h),
		ReceivedChain:  receivedChain(h),
		HeadersJSON:    headerMapJSON(h),
		BodyHTML:       parsed.BodyHTML,
		BodyPlain:      parsed.BodyPlain,
	}
}

func buildAnalysisText(meta contracts.MessageMeta, parsed *email.ParsedEmail) contracts.AnalysisText {
	fromAddr, fromName := splitAddress(parsed.Header.Get("From"))
	return contracts.AnalysisText{
		Meta:         meta,
		Subject:      parsed.Subject,
		SenderName:   fromName,
		SenderDomain: domainOf(fromAddr),
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

func tldOf(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return ""
	}
	if dot := strings.LastIndex(domain, "."); dot >= 0 {
		return domain[dot+1:]
	}
	return ""
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

func headerMapJSON(h mail.Header) []byte {
	flat := make(map[string]string, len(h))
	for k, vv := range h {
		if len(vv) == 0 {
			continue
		}
		flat[k] = vv[0]
	}
	b, err := json.Marshal(flat)
	if err != nil {
		return nil
	}
	return b
}

// ── pgtype constructors ─────────────────────────────────────────────────────

func pgText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

func pgInt8(v int64) pgtype.Int8 { return pgtype.Int8{Int64: v, Valid: true} }

func pgFloat8(v float64) pgtype.Float8 { return pgtype.Float8{Float64: v, Valid: true} }

func pgTimestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}

func pgSentTimestamp(dateStr string) pgtype.Int8 {
	ts := sentTimestamp(dateStr)
	if ts == 0 {
		return pgtype.Int8{}
	}
	return pgtype.Int8{Int64: ts, Valid: true}
}
