package gmail

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/source"
	"github.com/saif/cybersiren/shared/rfc822"
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
	// rewind past mail we've already ingested. A Get error must not silently
	// skip seeding the watch baseline (a Valkey blip would otherwise leave us
	// un-seeded); log it, but still never rewind an existing non-empty cursor.
	cur, gerr := a.history.Get(ctx, a.opts.OrgID)
	if gerr != nil {
		a.log.Warn().Err(gerr).Msg("gmail: read history cursor failed during watch seed; skipping seed this round")
	} else if cur == "" && resp.HistoryID != "" {
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

// EnsureSeeded guarantees a history cursor exists before the poll loop runs.
// Watch() seeds the cursor for push deployments, but a poll-only deployment
// (push_enabled=false, poll_enabled=true — the no-public-webhook case
// GmailConfig.Validate permits) has no watch() to provide a baseline, so
// syncHistory would forever hit the cursor=="" guard and ingest nothing. When
// no cursor is stored, EnsureSeeded fetches the mailbox's current historyId via
// users.getProfile and stores it, so poll — like watch — ingests only mail
// arriving AFTER startup. It is a no-op when a cursor already exists, so calling
// it alongside Watch() (which may have already seeded) is safe.
func (a *Adapter) EnsureSeeded(ctx context.Context) error {
	cur, err := a.history.Get(ctx, a.opts.OrgID)
	if err != nil {
		return fmt.Errorf("read history cursor: %w", err)
	}
	if cur != "" {
		return nil // already seeded (by Watch or a prior run); never rewind.
	}
	historyID, err := a.gmail.getProfile(ctx)
	if err != nil {
		return fmt.Errorf("seed history cursor via getProfile: %w", err)
	}
	if historyID == "" {
		return fmt.Errorf("seed history cursor: getProfile returned an empty historyId")
	}
	if err := a.history.Set(ctx, a.opts.OrgID, historyID); err != nil {
		return fmt.Errorf("persist seeded history cursor: %w", err)
	}
	a.log.Info().Str("history_id", historyID).Msg("gmail: seeded history cursor from mailbox profile (poll baseline)")
	return nil
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
		// No baseline yet. A push deployment seeds via watch(), but a poll-only
		// deployment has none — so self-heal by seeding from the mailbox profile
		// rather than bailing forever. (Without a startHistoryId, history.list
		// cannot delta-sync.) After seeding there is by construction no backlog
		// to walk this tick (we seed to "now"), so return and let the next tick
		// pick up new mail.
		if serr := a.EnsureSeeded(ctx); serr != nil {
			return fmt.Errorf("seed history cursor before sync: %w", serr)
		}
		a.log.Debug().Msg("gmail: seeded history cursor on first sync; next tick will delta-sync")
		return nil
	}

	msgIDs, latest, err := a.gmail.listHistory(ctx, cursor, a.opts.LabelIDs)
	if err != nil {
		// startHistoryId aged out of Gmail's ~1-week history retention. A delta
		// sync is impossible; per Gmail's documented full-sync requirement we
		// re-seed to the mailbox's current historyId to un-stick the pipeline.
		// Mail that arrived during the outage gap is unavoidably missed — but
		// that is strictly better than a cursor stuck forever (silent halt).
		if errors.Is(err, errHistoryTooOld) {
			fresh, perr := a.gmail.getProfile(ctx)
			if perr != nil {
				return fmt.Errorf("history too old; re-seed via getProfile: %w", perr)
			}
			if fresh == "" {
				return fmt.Errorf("history too old; getProfile returned an empty historyId")
			}
			if serr := a.history.Set(ctx, a.opts.OrgID, fresh); serr != nil {
				return fmt.Errorf("history too old; persist re-seeded cursor: %w", serr)
			}
			a.log.Warn().
				Str("old_cursor", cursor).
				Str("new_cursor", fresh).
				Msg("gmail: history too old (404); re-seeded cursor — mail in the outage gap is missed per Gmail's full-sync requirement")
			return nil
		}
		return fmt.Errorf("list history: %w", err)
	}

	failed := false
	for _, id := range msgIDs {
		if err := a.processMessage(ctx, id); err != nil {
			// A single bad message must not stall the whole window: log and
			// continue the loop. But we must NOT advance the cursor past it,
			// or it is silently dropped forever (never re-listed).
			failed = true
			a.log.Warn().Err(err).Str("gmail_message_id", id).Msg("gmail: message ingest failed; cursor held so window re-walks next sync")
		}
	}

	// Advance the cursor only when every message in the window succeeded. On a
	// failure we leave the cursor so the whole window re-walks next tick; dedup
	// suppresses re-publishing the ones that already succeeded. A *transient*
	// failure thus recovers automatically; a *permanently* poison message
	// re-walks until the deferred shared-consumer DLQ work (batch 8a-v) lands —
	// acceptable versus silent loss.
	if !failed && latest != "" && latest != cursor {
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
		MessageID:     rfc822.MessageID(raw),
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
