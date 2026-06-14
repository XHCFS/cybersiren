import React, { useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { submitScan } from '../services/api.js';

// ScanForm — submit a raw .eml (file upload or pasted text) to POST
// /api/v1/scan. The backend echoes svc-01's {status, email_id}. CRITICAL: a
// non-2xx upstream still returns HTTP 200 with a status like "http_429" /
// "error", so we branch on result.status, never the HTTP code. Known statuses
// are surfaced with the right tone; an email_id (when present) links to detail.

// classifyStatus maps a status string to {tone, title, msg}. svc-01's exact
// vocabulary can drift, so we recognise the documented values and degrade
// gracefully ("http_*" / unknown) rather than asserting a closed set.
function classifyStatus(status, emailId) {
  const s = (status || '').toLowerCase();
  if (s === 'accepted' || s === 'queued' || s === 'ok' || s === 'scanned') {
    return { tone: 'ok', title: 'Accepted for scanning', msg: 'The message was forwarded to the pipeline.' };
  }
  if (s === 'duplicate' || s === 'already_scanned') {
    return { tone: 'ok', title: 'Already scanned', msg: 'This message was submitted before; the existing scan was returned.' };
  }
  if (s === 'quota_exceeded') {
    return { tone: 'warn', title: 'Quota exceeded', msg: 'The submission quota for this organization has been reached. Try again later.' };
  }
  if (s.startsWith('http_429')) {
    return { tone: 'warn', title: 'Rate limited', msg: 'The scan service is rate-limiting submissions (HTTP 429). Try again shortly.' };
  }
  if (s.startsWith('http_5')) {
    return { tone: 'err', title: 'Upstream error', msg: `The scan service reported an error (${status}).` };
  }
  if (s.startsWith('http_4')) {
    return { tone: 'err', title: 'Rejected', msg: `The scan service rejected the message (${status}).` };
  }
  if (s === 'error' || s === 'failed') {
    return { tone: 'err', title: 'Scan failed', msg: 'The scan service could not process the message.' };
  }
  // Unknown but with an id → treat as accepted; otherwise neutral report.
  if (emailId) {
    return { tone: 'ok', title: `Submitted (${status || 'ok'})`, msg: 'The message was forwarded.' };
  }
  return { tone: 'warn', title: `Status: ${status || 'unknown'}`, msg: 'The scan service returned an unrecognized status.' };
}

export default function ScanForm() {
  const [text, setText] = useState('');
  const [fileName, setFileName] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null); // {status, email_id}
  const [error, setError] = useState(null);
  const fileRef = useRef(null);

  async function onFile(e) {
    const f = e.target.files?.[0];
    if (!f) return;
    setFileName(f.name);
    setError(null);
    const content = await f.text();
    setText(content);
  }

  async function onSubmit(e) {
    e.preventDefault();
    if (busy) return;
    const raw = text.trim();
    if (!raw) {
      setError('Paste a raw email or choose a .eml file first.');
      return;
    }
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const res = await submitScan(text);
      setResult(res || { status: 'unknown' });
    } catch (err) {
      // Transport/HTTP-level failure (the backend itself errored, e.g. 502/503).
      setError(err.message || 'Submission failed.');
    } finally {
      setBusy(false);
    }
  }

  function reset() {
    setText('');
    setFileName('');
    setResult(null);
    setError(null);
    if (fileRef.current) fileRef.current.value = '';
  }

  const verdict = result ? classifyStatus(result.status, result.email_id) : null;

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Submit for scanning</h2>
          <div className="lede">Upload a .eml file or paste a raw RFC-822 message to run it through the detection pipeline.</div>
        </div>
      </div>

      <div className="card" style={{ maxWidth: 760 }}>
        <form onSubmit={onSubmit}>
          <div className="row" style={{ marginBottom: 12 }}>
            <label className="btn sm filebtn">
              Choose .eml file
              <input ref={fileRef} type="file" accept=".eml,message/rfc822,text/plain" onChange={onFile} />
            </label>
            {fileName && <span className="muted small">{fileName}</span>}
            {(text || fileName) && (
              <button type="button" className="btn sm ghost" onClick={reset}>
                Clear
              </button>
            )}
          </div>

          <label className="field">
            <span>Raw message (RFC-822)</span>
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={'From: attacker@example.com\nTo: you@org.com\nSubject: Urgent — verify your account\n\nClick https://bad.example to continue…'}
              style={{ minHeight: 240 }}
            />
          </label>

          {error && <div className="form-error">{error}</div>}

          <div className="row" style={{ marginTop: 6 }}>
            <button className="btn primary" type="submit" disabled={busy || !text.trim()}>
              {busy ? 'Submitting…' : 'Submit scan'}
            </button>
            <span className="faint small">
              Sent as <code className="mono">message/rfc822</code>. Max 25 MiB.
            </span>
          </div>
        </form>

        {verdict && (
          <div className={verdict.tone === 'ok' ? 'form-ok' : verdict.tone === 'warn' ? 'login-hint' : 'form-error'} style={{ marginTop: 16 }}>
            <div style={{ fontWeight: 600, marginBottom: 4 }}>{verdict.title}</div>
            <div className="small">{verdict.msg}</div>
            <div className="small mono faint" style={{ marginTop: 6 }}>
              status: {result.status || 'unknown'}
              {result.email_id ? ` · email_id: ${result.email_id}` : ''}
            </div>
            {result.email_id && (
              <div style={{ marginTop: 8 }}>
                <Link className="btn sm" to={`/scans/${result.email_id}`}>
                  View scan detail →
                </Link>
              </div>
            )}
          </div>
        )}
      </div>
    </>
  );
}
