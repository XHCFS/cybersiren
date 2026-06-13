// services/api.js — typed fetch wrapper for the svc-10 console API.
//
// Base URL is empty by default so dev requests use relative paths that the Vite
// proxy (vite.config.js) forwards to the backend on :8088. A production build
// served behind a different origin can set VITE_API_BASE_URL to the backend.
//
// The Bearer token + the on-401 logout hook are injected from AuthContext at
// startup (registerAuth) so this module never imports React or owns auth state.

const BASE = import.meta.env.VITE_API_BASE_URL || '';
const TOKEN_KEY = 'cybersiren.console.token';

// Auth wiring, set by AuthContext via registerAuth(). getToken reads the live
// token; onUnauthorized is invoked when the server rejects the session (401).
let getToken = () => {
  try {
    return localStorage.getItem(TOKEN_KEY) || null;
  } catch {
    return null;
  }
};
let onUnauthorized = () => {};

export function registerAuth({ getToken: gt, onUnauthorized: ou }) {
  if (gt) getToken = gt;
  if (ou) onUnauthorized = ou;
}

// ApiError carries the HTTP status + the server's {error} message (when any) so
// views can branch on .status (e.g. 404 vs 401) and surface .message.
export class ApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

// request is the single entry point. It attaches the Bearer token, parses JSON,
// and on a 401 clears the session via onUnauthorized before throwing so the
// caller's catch still runs (and the router redirects to /login).
async function request(path, { method = 'GET', body, headers = {}, rawBody = false } = {}) {
  const token = getToken();
  const h = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;

  let payload = body;
  if (body != null && !rawBody) {
    h['Content-Type'] = h['Content-Type'] || 'application/json';
    payload = typeof body === 'string' ? body : JSON.stringify(body);
  }

  let resp;
  try {
    resp = await fetch(`${BASE}${path}`, { method, headers: h, body: payload });
  } catch (networkErr) {
    throw new ApiError(
      'Could not reach the console API. Is the backend running on :8088?',
      0,
      null
    );
  }

  if (resp.status === 401) {
    onUnauthorized();
    throw new ApiError('Your session has expired. Please sign in again.', 401, null);
  }

  const ct = resp.headers.get('content-type') || '';
  let data = null;
  if (ct.includes('application/json')) {
    data = await resp.json().catch(() => null);
  } else {
    const txt = await resp.text().catch(() => '');
    data = txt ? { error: txt } : null;
  }

  if (!resp.ok) {
    const msg = (data && data.error) || `Request failed (${resp.status})`;
    throw new ApiError(msg, resp.status, data);
  }
  return data;
}

// ── auth ────────────────────────────────────────────────────────
export function login(email, password) {
  return request('/api/v1/auth/login', { method: 'POST', body: { email, password } });
}
export function getMe() {
  return request('/api/v1/me');
}

// ── emails ──────────────────────────────────────────────────────
export function listEmails({ limit = 50, offset = 0 } = {}) {
  const q = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  return request(`/api/v1/emails?${q.toString()}`);
}
export function getEmail(id) {
  return request(`/api/v1/emails/${encodeURIComponent(id)}`);
}

// ── rules (read-only) ───────────────────────────────────────────
export function listRules() {
  return request('/api/v1/rules');
}

// ── stats (5 materialized-view dashboards) ──────────────────────
export const statThreats = () => request('/api/v1/stats/threats');
export const statCampaigns = () => request('/api/v1/stats/campaigns');
export const statFeeds = () => request('/api/v1/stats/feeds');
export const statRules = () => request('/api/v1/stats/rules');
export const statIngestion = () => request('/api/v1/stats/ingestion');

// ── scan submission ─────────────────────────────────────────────
// submitScan forwards a raw RFC-822 message. The backend echoes svc-01's
// {status, email_id}; a non-2xx upstream still returns HTTP 200 with a status
// like "http_429"/"error", so callers MUST branch on result.status, not the
// HTTP code. We send raw bytes as Content-Type message/rfc822 (the backend also
// accepts JSON {raw_rfc822: base64}, but raw is simpler and avoids re-encoding).
export function submitScan(raw) {
  return request('/api/v1/scan', {
    method: 'POST',
    rawBody: true,
    headers: { 'Content-Type': 'message/rfc822' },
    body: raw,
  });
}

export { TOKEN_KEY };
