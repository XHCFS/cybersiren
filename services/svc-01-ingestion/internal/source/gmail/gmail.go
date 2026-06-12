package gmail

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/source"
)

// adapterName labels emails.raw rows ingested over Gmail (matches the spec's
// source_adapter enum).
const adapterName = "gmail"

// WatchRenewInterval is the cadence the runbook recommends for re-issuing
// watch(). Gmail caps a watch at 7 days; we renew daily so a missed renewal
// still leaves several days of slack (ARCH-SPEC §2.1: "Watch request expires
// every 7 days — auto-renew").
const WatchRenewInterval = 24 * time.Hour

// HistoryStore persists the Gmail historyId cursor (the delta-sync watermark)
// across restarts. Backed by Valkey in production; an in-memory implementation
// backs the tests.
type HistoryStore interface {
	// Get returns the stored historyId for orgID, or "" if none is stored.
	Get(ctx context.Context, orgID int64) (string, error)
	// Set persists historyID as the new cursor for orgID.
	Set(ctx context.Context, orgID int64, historyID string) error
}

// Options bundle the adapter's collaborators and tuning.
type Options struct {
	// Core is the shared ingestion engine (auth/dedup/quota/publish). The Gmail
	// adapter calls it exactly like the API-upload adapter does.
	Core source.Ingestor
	// OrgID is the tenant the watched mailbox belongs to (G10: bound from
	// config, never a request body). APIKeyID is 0 — Gmail does not authenticate
	// per message via an API key.
	OrgID int64
	// Client is the Gmail REST client.
	Client *client
	// History persists the historyId cursor.
	History HistoryStore
	// LabelIDs narrows watch()/history.list (e.g. ["INBOX"]).
	LabelIDs []string
	// WatchTopic is the fully-qualified Pub/Sub topic for watch() (push only).
	WatchTopic string
	// PushToken / PushAudience verify inbound push requests (see push.go).
	PushToken    string
	PushAudience string
	// PollInterval is the fallback poll cadence.
	PollInterval time.Duration
	// Log is the service logger.
	Log zerolog.Logger
}

// Adapter is the Gmail EmailSource. It owns the /gmail/push webhook, the
// fallback poll loop, and the watch() registration; all three converge on
// processMessage, which fetches → decodes → hands the RFC-822 bytes to the
// shared ingestion core.
type Adapter struct {
	opts    Options
	gmail   *client
	core    source.Ingestor
	history HistoryStore
	log     zerolog.Logger

	// mu serialises history-sync runs so a push and a poll tick cannot
	// double-walk the same history window concurrently (Gmail history is
	// monotonic but the cursor read-modify-write must not interleave).
	mu sync.Mutex
}

// New builds the Gmail adapter from Options.
func New(opts Options) *Adapter {
	return &Adapter{
		opts:    opts,
		gmail:   opts.Client,
		core:    opts.Core,
		history: opts.History,
		log:     opts.Log,
	}
}

// Name is the adapter's registry key.
func (a *Adapter) Name() string { return adapterName }

// Register binds the push webhook on the service mux.
func (a *Adapter) Register(mux *http.ServeMux) {
	mux.HandleFunc("/gmail/push", a.handlePush)
}

// Watch registers (or renews) the Gmail push watch and stores the returned
// historyId as the baseline cursor when none is stored yet. Call it at startup
// and on WatchRenewInterval. Returns the watch expiration so the caller can log
// the 7-day renewal deadline.
func (a *Adapter) Watch(ctx context.Context) (WatchResponse, error) {
	resp, err := a.gmail.watch(ctx, a.opts.WatchTopic, a.opts.LabelIDs)
	if err != nil {
		return WatchResponse{}, fmt.Errorf("gmail watch: %w", err)
	}
	// Seed the cursor only if we don't already have one — re-watching must not
	// rewind past mail we've already ingested.
	cur, gerr := a.history.Get(ctx, a.opts.OrgID)
	if gerr == nil && cur == "" && resp.HistoryID != "" {
		if serr := a.history.Set(ctx, a.opts.OrgID, resp.HistoryID); serr != nil {
			a.log.Warn().Err(serr).Msg("gmail: failed to seed history cursor")
		}
	}
	a.log.Info().
		Str("history_id", resp.HistoryID).
		Str("expiration_epoch_ms", resp.Expiration).
		Str("watch_topic", a.opts.WatchTopic).
		Msg("gmail watch registered (renew within 7 days)")
	return resp, nil
}

// Stop cancels the active watch (best-effort; used on shutdown).
func (a *Adapter) Stop(ctx context.Context) error {
	return a.gmail.stop(ctx)
}

// RunWatchRenewer renews the watch on WatchRenewInterval until ctx is done. Run
// it in a goroutine for the lifetime of the service so the watch never lapses.
func (a *Adapter) RunWatchRenewer(ctx context.Context) {
	t := time.NewTicker(WatchRenewInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := a.Watch(ctx); err != nil {
				a.log.Error().Err(err).Msg("gmail: watch renewal failed")
			}
		}
	}
}

// RunPollLoop runs the fallback delta-poll: every PollInterval it walks
// history.list from the stored cursor and ingests anything new. It catches mail
// missed while the push webhook was unreachable; the push path is primary.
func (a *Adapter) RunPollLoop(ctx context.Context) {
	interval := a.opts.PollInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	a.log.Info().Dur("interval", interval).Msg("gmail: fallback poll loop started")
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := a.syncHistory(ctx); err != nil {
				a.log.Error().Err(err).Msg("gmail: poll sync failed")
			}
		}
	}
}

// syncHistory walks history.list from the stored cursor, ingests each new
// message, and advances the cursor. It is the single shared body both the push
// handler and the poll loop call, so dedup/quota/UUIDv7 apply once per message
// regardless of which trigger fired. Serialised by a.mu.
func (a *Adapter) syncHistory(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	cursor, err := a.history.Get(ctx, a.opts.OrgID)
	if err != nil {
		return fmt.Errorf("read history cursor: %w", err)
	}
	if cursor == "" {
		// No baseline yet — a watch() must run first to seed it. Without a
		// startHistoryId, history.list cannot delta-sync, so skip quietly.
		a.log.Debug().Msg("gmail: no history cursor yet; skipping sync (run Watch first)")
		return nil
	}

	msgIDs, latest, err := a.gmail.listHistory(ctx, cursor, a.opts.LabelIDs)
	if err != nil {
		return fmt.Errorf("list history: %w", err)
	}

	for _, id := range msgIDs {
		if err := a.processMessage(ctx, id); err != nil {
			// A single bad message must not stall the whole window; log and
			// continue. The cursor only advances past it once we persist
			// `latest`, but a transient fetch error here means we'd reprocess
			// it next tick — dedup makes that safe.
			a.log.Warn().Err(err).Str("gmail_message_id", id).Msg("gmail: message ingest failed; will retry next sync")
		}
	}

	if latest != "" && latest != cursor {
		if err := a.history.Set(ctx, a.opts.OrgID, latest); err != nil {
			return fmt.Errorf("persist history cursor: %w", err)
		}
	}
	return nil
}

// processMessage fetches one Gmail message in raw form, decodes it to RFC-822,
// and feeds it through the shared ingestion core (org bound from config — G10).
func (a *Adapter) processMessage(ctx context.Context, gmailMessageID string) error {
	msg, err := a.gmail.getRawMessage(ctx, gmailMessageID)
	if err != nil {
		return fmt.Errorf("get raw message: %w", err)
	}
	raw, err := decodeRawRFC822(msg.Raw)
	if err != nil {
		return fmt.Errorf("decode message %s: %w", gmailMessageID, err)
	}

	req := source.IngestRequest{
		Raw:           raw,
		MessageID:     messageIDFromRaw(raw),
		SourceAdapter: adapterName,
	}
	// APIKeyID is 0: Gmail mail is not API-key authenticated. The org is bound
	// from config, never a request body (G10).
	outcome, err := a.core.Ingest(ctx, a.opts.OrgID, 0, req)
	if err != nil {
		return fmt.Errorf("ingest gmail message %s: %w", gmailMessageID, err)
	}

	a.log.Info().
		Str("gmail_message_id", gmailMessageID).
		Str("email_id", outcome.EmailID).
		Int("status", int(outcome.Status)).
		Msg("gmail: message ingested")
	return nil
}

// compile-time assertion: the adapter satisfies EmailSource.
var _ source.EmailSource = (*Adapter)(nil)
