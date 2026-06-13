import React, { useCallback, useEffect, useState } from 'react';
import { listRules } from '../services/api.js';
import { Loading, ErrorState, EmptyState } from './Shared.jsx';

// RulesView — READ-ONLY detection-rule catalogue (GET /api/v1/rules). There are
// deliberately no create / edit / delete / activate controls: rule management
// is out of scope for the analyst console (MVP-7). This is a reference table
// only, so an analyst can map a rule hit on a scan back to its definition.

function statusBadge(status) {
  const s = (status || '').toLowerCase();
  if (s === 'active' || s === 'enabled') return 'ok';
  if (s === 'archived' || s === 'disabled' || s === 'inactive') return 'warn';
  return 'info';
}

export default function RulesView() {
  const [rules, setRules] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    listRules()
      .then((res) => setRules(res?.rules || []))
      .catch((err) => setError(err))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Detection rules</h2>
          <div className="lede">Read-only catalogue of the rules that score incoming email.</div>
        </div>
        <button className="btn sm ghost" onClick={load} disabled={loading}>
          Refresh
        </button>
      </div>

      {loading && <Loading label="Loading rules…" min="40vh" />}
      {!loading && error && <ErrorState error={error} onRetry={load} min="40vh" />}
      {!loading && !error && rules && rules.length === 0 && (
        <EmptyState title="No rules defined" hint="No detection rules are configured for this organization." min="40vh" />
      )}

      {!loading && !error && rules && rules.length > 0 && (
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th style={{ width: '24%' }}>Name</th>
                <th style={{ width: 100 }}>Target</th>
                <th style={{ width: 80 }}>Version</th>
                <th style={{ width: 100 }}>Status</th>
                <th style={{ width: 80 }}>Impact</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id}>
                  <td>
                    <div className="cell-strong">{r.name}</div>
                    {r.org_id == null && <span className="badge violet">global</span>}
                  </td>
                  <td>
                    <span className="badge">{r.target || '—'}</span>
                  </td>
                  <td className="mono small">{r.version || '—'}</td>
                  <td>
                    <span className={`badge ${statusBadge(r.status)}`}>{r.status || 'unknown'}</span>
                  </td>
                  <td className="num">{r.score_impact > 0 ? `+${r.score_impact}` : r.score_impact}</td>
                  <td className="muted small">{r.description || <span className="faint">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
