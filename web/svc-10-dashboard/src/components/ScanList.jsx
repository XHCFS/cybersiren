import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { listEmails } from '../services/api.js';
import { Loading, ErrorState, EmptyState, RiskPill, VerdictChip } from './Shared.jsx';
import { fmtDate } from '../lib/format.js';

const LIMIT = 50;

// ScanList — paginated table of scanned emails (GET /api/v1/emails). offset is
// kept in the URL query so pagination is shareable + survives a reload. A row
// is only clickable when it has a resolved email_id (the detail route keys on
// the UUIDv7; an unresolvable row would 404).

export default function ScanList() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const offset = Math.max(0, parseInt(params.get('offset') || '0', 10) || 0);

  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    listEmails({ limit: LIMIT, offset })
      .then((res) => setData(res))
      .catch((err) => setError(err))
      .finally(() => setLoading(false));
  }, [offset]);

  useEffect(() => {
    load();
  }, [load]);

  const setOffset = (next) => {
    const p = new URLSearchParams(params);
    if (next <= 0) p.delete('offset');
    else p.set('offset', String(next));
    setParams(p);
  };

  const items = data?.items || [];
  const count = data?.count ?? items.length;
  const hasPrev = offset > 0;
  const hasNext = count >= LIMIT; // a full page implies there may be more

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Scanned email</h2>
          <div className="lede">Every message ingested for this organization, newest first.</div>
        </div>
        <button className="btn sm ghost" onClick={load} disabled={loading}>
          Refresh
        </button>
      </div>

      {loading && <Loading label="Loading scans…" min="40vh" />}
      {!loading && error && <ErrorState error={error} onRetry={load} min="40vh" />}
      {!loading && !error && items.length === 0 && (
        <EmptyState
          title="No scanned email yet"
          hint="Submit a message on the Submit tab, or connect an inbox, to populate this list."
          min="40vh"
        />
      )}

      {!loading && !error && items.length > 0 && (
        <>
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th style={{ width: '26%' }}>Sender</th>
                  <th>Subject</th>
                  <th style={{ width: 110 }}>Risk</th>
                  <th style={{ width: 130 }}>Verdict</th>
                  <th style={{ width: 170 }}>Fetched</th>
                </tr>
              </thead>
              <tbody>
                {items.map((it) => {
                  const clickable = Boolean(it.email_id);
                  return (
                    <tr
                      key={it.internal_id || it.email_id}
                      className={clickable ? 'clickable' : ''}
                      onClick={clickable ? () => navigate(`/scans/${it.email_id}`) : undefined}
                      title={clickable ? 'Open detail' : 'Detail unavailable (unmapped id)'}
                    >
                      <td>
                        <div className="cell-strong truncate">
                          {it.sender_name || it.sender_email || it.sender_domain || '—'}
                        </div>
                        {it.sender_name && it.sender_email && (
                          <div className="cell-sub truncate">{it.sender_email}</div>
                        )}
                      </td>
                      <td>
                        <div className="truncate" style={{ maxWidth: 380 }}>
                          {it.subject || <span className="faint">(no subject)</span>}
                        </div>
                      </td>
                      <td>
                        <RiskPill score={it.risk_score == null ? null : it.risk_score} />
                      </td>
                      <td>
                        <VerdictChip label={it.verdict_label} />
                      </td>
                      <td className="cell-sub">{fmtDate(it.fetched_at)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="pager">
            <button className="btn sm" disabled={!hasPrev} onClick={() => setOffset(offset - LIMIT)}>
              ← Previous
            </button>
            <button className="btn sm" disabled={!hasNext} onClick={() => setOffset(offset + LIMIT)}>
              Next →
            </button>
            <span className="pinfo">
              Showing {offset + 1}–{offset + items.length}
              {hasNext ? '' : ' (end)'}
            </span>
          </div>
        </>
      )}
    </>
  );
}
