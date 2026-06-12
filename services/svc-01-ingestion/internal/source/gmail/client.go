package gmail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// googleAPIBase is the Gmail API v1 root; overridable via config for tests.
const googleAPIBase = "https://gmail.googleapis.com"

// client is a thin Gmail API v1 REST client over an OAuth2 token source. Only
// the four calls the adapter needs are implemented: history.list, messages.get
// (format=raw), users.watch, users.stop.
type client struct {
	base       string
	user       string
	tokens     *tokenSource
	httpClient *http.Client
}

// newClient builds a Gmail client. base empty falls back to the real Gmail API.
func newClient(base, user string, tokens *tokenSource, httpClient *http.Client) *client {
	if base == "" {
		base = googleAPIBase
	}
	if user == "" {
		user = "me"
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &client{base: strings.TrimRight(base, "/"), user: user, tokens: tokens, httpClient: httpClient}
}

// historyRecord is one entry of a history.list page. We only consume the
// messagesAdded sub-list (new mail); label changes / deletes are ignored.
type historyRecord struct {
	ID            string `json:"id"`
	MessagesAdded []struct {
		Message historyMessage `json:"message"`
	} `json:"messagesAdded"`
}

// historyMessage is the message stub embedded in a history record.
type historyMessage struct {
	ID       string   `json:"id"`
	ThreadID string   `json:"threadId"`
	LabelIDs []string `json:"labelIds"`
}

// historyListResponse is the history.list reply.
type historyListResponse struct {
	History       []historyRecord `json:"history"`
	NextPageToken string          `json:"nextPageToken"`
	HistoryID     string          `json:"historyId"`
}

// listHistory pages through history.list starting at startHistoryID, returning
// every newly-added message id (deduplicated) and the latest historyId to
// persist as the new cursor. labelIDs (e.g. ["INBOX"]) narrows the result.
func (c *client) listHistory(ctx context.Context, startHistoryID string, labelIDs []string) (msgIDs []string, latestHistoryID string, err error) {
	seen := map[string]struct{}{}
	pageToken := ""
	latestHistoryID = startHistoryID

	for {
		q := url.Values{}
		q.Set("startHistoryId", startHistoryID)
		q.Set("historyTypes", "messageAdded")
		for _, l := range labelIDs {
			q.Add("labelId", l)
		}
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}

		var page historyListResponse
		if err := c.getJSON(ctx, fmt.Sprintf("/gmail/v1/users/%s/history?%s", url.PathEscape(c.user), q.Encode()), &page); err != nil {
			return nil, startHistoryID, err
		}
		// The page-level historyId is the mailbox's current high-water mark and
		// is the correct cursor to resume from next time (record-level ids are
		// older). Advance only forward, never backward.
		latestHistoryID = maxHistoryID(latestHistoryID, page.HistoryID)
		for _, h := range page.History {
			latestHistoryID = maxHistoryID(latestHistoryID, h.ID)
			for _, ma := range h.MessagesAdded {
				id := ma.Message.ID
				if id == "" {
					continue
				}
				if _, dup := seen[id]; dup {
					continue
				}
				seen[id] = struct{}{}
				msgIDs = append(msgIDs, id)
			}
		}
		if page.NextPageToken == "" {
			break
		}
		pageToken = page.NextPageToken
	}
	return msgIDs, latestHistoryID, nil
}

// maxHistoryID returns the numerically-larger of two Gmail historyId strings
// (they are uint64). An unparseable / empty value loses to a parseable one so
// the cursor only ever moves forward.
func maxHistoryID(a, b string) string {
	av, aok := parseHistoryID(a)
	bv, bok := parseHistoryID(b)
	switch {
	case aok && bok:
		if bv > av {
			return b
		}
		return a
	case bok:
		return b
	default:
		return a
	}
}

// parseHistoryID parses a Gmail historyId; ok is false for an empty/invalid one.
func parseHistoryID(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// rawMessage is the messages.get?format=raw reply: `raw` holds the entire
// RFC-822 message, web-safe-base64-encoded.
type rawMessage struct {
	ID       string `json:"id"`
	ThreadID string `json:"threadId"`
	Raw      string `json:"raw"`
}

// getRawMessage fetches a single message in raw RFC-822 form.
func (c *client) getRawMessage(ctx context.Context, messageID string) (rawMessage, error) {
	var m rawMessage
	path := fmt.Sprintf("/gmail/v1/users/%s/messages/%s?format=raw", url.PathEscape(c.user), url.PathEscape(messageID))
	if err := c.getJSON(ctx, path, &m); err != nil {
		return rawMessage{}, err
	}
	return m, nil
}

// watchRequest is the users.watch body.
type watchRequest struct {
	TopicName string   `json:"topicName"`
	LabelIDs  []string `json:"labelIds,omitempty"`
}

// WatchResponse is the users.watch reply: the historyId to start delta-syncing
// from and the watch expiration (epoch millis; renew before it lapses — Gmail
// caps a watch at 7 days).
type WatchResponse struct {
	HistoryID  string `json:"historyId"`
	Expiration string `json:"expiration"`
}

// watch registers a Gmail push watch on topicName for the given labels. It
// returns the baseline historyId + the expiration timestamp.
func (c *client) watch(ctx context.Context, topicName string, labelIDs []string) (WatchResponse, error) {
	body := watchRequest{TopicName: topicName, LabelIDs: labelIDs}
	var resp WatchResponse
	if err := c.postJSON(ctx, fmt.Sprintf("/gmail/v1/users/%s/watch", url.PathEscape(c.user)), body, &resp); err != nil {
		return WatchResponse{}, err
	}
	return resp, nil
}

// stop cancels an active watch (users.stop). Best-effort; safe to call when no
// watch is active.
func (c *client) stop(ctx context.Context) error {
	return c.postJSON(ctx, fmt.Sprintf("/gmail/v1/users/%s/stop", url.PathEscape(c.user)), struct{}{}, nil)
}

// getJSON performs an authenticated GET and decodes the JSON body into out.
func (c *client) getJSON(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// postJSON performs an authenticated POST of body (JSON) and decodes the reply
// into out (out may be nil to discard the body).
func (c *client) postJSON(ctx context.Context, path string, body, out any) error {
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		buf = bytes.NewReader(b)
	}
	return c.do(ctx, http.MethodPost, path, buf, out)
}

// do is the authenticated request core: mint a token, attach it, execute, and
// surface a non-2xx as an error carrying the response body.
func (c *client) do(ctx context.Context, method, path string, body io.Reader, out any) error {
	token, err := c.tokens.token(ctx)
	if err != nil {
		return fmt.Errorf("acquire access token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("gmail api request %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		return fmt.Errorf("gmail api %s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response %s %s: %w", method, path, err)
	}
	return nil
}
