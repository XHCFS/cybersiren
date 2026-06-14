import React, { useCallback, useEffect, useState } from 'react';
import {
  statIngestion,
  statThreats,
  statCampaigns,
  statFeeds,
  statRules,
} from '../services/api.js';
import { Loading, ErrorState } from './Shared.jsx';
import { num, num1, fmtDate, fmtAgo } from '../lib/format.js';

// Dashboard — all 5 materialized-view stats panels. The MVs refresh out-of-band
// so any panel can be empty/stale; each Panel owns its own loading / error /
// empty state and renders "no data yet" gracefully rather than failing the
// whole page. Visualizations are hand-rolled SVG/CSS (no charting lib).

// usePanel fetches one stats endpoint and extracts its payload. `extract` pulls
// the array/object out of the {key: ...} envelope the backend wraps responses in.
function usePanel(fetcher, extract) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    fetcher()
      .then((res) => setData(extract(res)))
      .catch((err) => setError(err))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return { data, error, loading, reload: load };
}

const STALE = 'No data yet — stats refresh out-of-band and may lag live ingestion.';

function PanelShell({ title, sub, children }) {
  return (
    <section className="dash-section">
      <h3 className="sec-title">
        {title}
        {sub && (
          <span className="faint small" style={{ fontWeight: 400, fontFamily: 'var(--font-ui)' }}>
            {sub}
          </span>
        )}
      </h3>
      {children}
    </section>
  );
}

function PanelBody({ loading, error, empty, reload, children }) {
  if (loading) return <Loading label="Loading…" min="160px" />;
  if (error) return <ErrorState error={error} onRetry={reload} min="160px" />;
  if (empty) return <div className="card"><div className="empty-inline">{STALE}</div></div>;
  return children;
}

// HBar — a simple horizontal labelled bar (hand-rolled) for distributions.
function HBar({ label, value, max, tone = 'low' }) {
  const w = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div style={{ marginBottom: 9 }}>
      <div className="spread" style={{ marginBottom: 4 }}>
        <span className="small">{label}</span>
        <span className="mono small">{num(value)}</span>
      </div>
      <div className="meter">
        <i className={tone} style={{ width: `${w}%` }} />
      </div>
    </div>
  );
}

export default function Dashboard() {
  return (
    <>
      <div className="page-head">
        <div>
          <h2>Dashboards</h2>
          <div className="lede">Ingestion, threat intelligence, campaigns, feed health, and rule performance.</div>
        </div>
      </div>

      <IngestionPanel />
      <ThreatPanel />
      <CampaignPanel />
      <FeedPanel />
      <RulePanel />
    </>
  );
}

// ── 1. Ingestion summary (single object) ──────────────────────────
function IngestionPanel() {
  const { data, error, loading, reload } = usePanel(statIngestion, (r) => r || null);
  // The single row is always present (zero-valued when empty); treat all-zero
  // totals as "no data yet" for a friendlier message.
  const empty = data && data.total_emails === 0;
  const maxBand = data ? Math.max(1, data.high_risk_count, data.medium_risk_count, data.low_risk_count) : 1;
  const maxVerdict = data
    ? Math.max(1, data.confirmed_phishing, data.confirmed_malware, data.confirmed_spam, data.confirmed_benign, data.unclassified)
    : 1;

  return (
    <PanelShell title="Ingestion" sub="email volume + risk distribution">
      <PanelBody loading={loading} error={error} empty={empty} reload={reload}>
        {data && (
          <>
            <div className="grid-cards" style={{ marginBottom: 16 }}>
              <div className="statcard">
                <div className="k">Total emails</div>
                <div className="v accent">{num(data.total_emails)}</div>
              </div>
              <div className="statcard">
                <div className="k">Last 24h</div>
                <div className="v">{num(data.emails_last_24h)}</div>
              </div>
              <div className="statcard">
                <div className="k">Last 7d</div>
                <div className="v">{num(data.emails_last_7d)}</div>
              </div>
              <div className="statcard">
                <div className="k">Last 30d</div>
                <div className="v">{num(data.emails_last_30d)}</div>
              </div>
              <div className="statcard">
                <div className="k">Avg risk</div>
                <div className="v">{num1(data.avg_risk_score)}</div>
              </div>
              <div className="statcard">
                <div className="k">Max risk</div>
                <div className="v">{data.max_risk_score == null ? '—' : data.max_risk_score}</div>
              </div>
            </div>

            <div className="detail-grid">
              <div className="card">
                <h3 className="sec-h">Risk bands</h3>
                <HBar label="High (≥70)" value={data.high_risk_count} max={maxBand} tone="high" />
                <HBar label="Medium (40–69)" value={data.medium_risk_count} max={maxBand} tone="med" />
                <HBar label="Low (<40)" value={data.low_risk_count} max={maxBand} tone="low" />
              </div>
              <div className="card">
                <h3 className="sec-h">Confirmed verdicts</h3>
                <HBar label="Phishing" value={data.confirmed_phishing} max={maxVerdict} tone="high" />
                <HBar label="Malware" value={data.confirmed_malware} max={maxVerdict} tone="high" />
                <HBar label="Spam" value={data.confirmed_spam} max={maxVerdict} tone="med" />
                <HBar label="Benign" value={data.confirmed_benign} max={maxVerdict} tone="low" />
                <HBar label="Unclassified" value={data.unclassified} max={maxVerdict} tone="med" />
              </div>
            </div>
          </>
        )}
      </PanelBody>
    </PanelShell>
  );
}

// ── 2. Threat summary (by type / country / ASN) ──────────────────
function ThreatPanel() {
  const { data, error, loading, reload } = usePanel(statThreats, (r) => r?.threats || []);
  const empty = data && data.length === 0;
  return (
    <PanelShell title="Threat intelligence" sub="enriched threats by type & origin">
      <PanelBody loading={loading} error={error} empty={empty} reload={reload}>
        {data && data.length > 0 && (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Threat type</th>
                  <th>Country</th>
                  <th>ASN</th>
                  <th className="num" style={{ textAlign: 'right' }}>Total</th>
                  <th className="num" style={{ textAlign: 'right' }}>Online</th>
                  <th className="num" style={{ textAlign: 'right' }}>Offline</th>
                  <th className="num" style={{ textAlign: 'right' }}>Avg risk</th>
                  <th>Scope</th>
                </tr>
              </thead>
              <tbody>
                {data.map((t, i) => (
                  <tr key={`${t.threat_type}-${t.country}-${t.asn}-${i}`}>
                    <td>
                      <span className="badge bad">{t.threat_type || 'unknown'}</span>
                    </td>
                    <td>{t.country || '—'}</td>
                    <td className="small">
                      {t.asn ? `AS${t.asn}` : '—'}
                      {t.asn_name && <div className="cell-sub truncate" style={{ maxWidth: 160 }}>{t.asn_name}</div>}
                    </td>
                    <td className="num">{num(t.total)}</td>
                    <td className="num" style={{ color: 'var(--rose)' }}>{num(t.online_count)}</td>
                    <td className="num muted">{num(t.offline_count)}</td>
                    <td className="num">{num1(t.avg_risk_score)}</td>
                    <td>{t.is_global ? <span className="badge violet">global</span> : <span className="badge">org</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </PanelBody>
    </PanelShell>
  );
}

// ── 3. Campaign summary (table + verdict breakdown) ──────────────
function CampaignPanel() {
  const { data, error, loading, reload } = usePanel(statCampaigns, (r) => r?.campaigns || []);
  const empty = data && data.length === 0;
  return (
    <PanelShell title="Campaigns" sub="clustered attack campaigns">
      <PanelBody loading={loading} error={error} empty={empty} reload={reload}>
        {data && data.length > 0 && (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Campaign</th>
                  <th>Type</th>
                  <th>Brand</th>
                  <th className="num" style={{ textAlign: 'right' }}>Emails</th>
                  <th className="num" style={{ textAlign: 'right' }}>Avg risk</th>
                  <th>Verdict mix</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {data.map((c) => (
                  <tr key={c.campaign_id}>
                    <td>
                      <div className="cell-strong truncate" style={{ maxWidth: 200 }}>{c.name || `campaign ${c.campaign_id}`}</div>
                      {c.fingerprint && <div className="cell-sub mono truncate" style={{ maxWidth: 200 }}>{c.fingerprint}</div>}
                    </td>
                    <td>{c.threat_type ? <span className="badge bad">{c.threat_type}</span> : '—'}</td>
                    <td className="small">{c.target_brand || '—'}</td>
                    <td className="num">{num(c.email_count)}</td>
                    <td className="num">{num1(c.avg_email_risk_score)}</td>
                    <td>
                      <VerdictMix c={c} />
                    </td>
                    <td className="cell-sub">{fmtDate(c.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </PanelBody>
    </PanelShell>
  );
}

// VerdictMix renders a compact stacked-segment bar of a campaign's verdict
// counts, with tooltips per segment.
function VerdictMix({ c }) {
  const segs = [
    { k: 'phishing', v: c.verdict_phishing, color: 'var(--rose)' },
    { k: 'malware', v: c.verdict_malware, color: 'var(--violet)' },
    { k: 'suspicious', v: c.verdict_suspicious, color: 'var(--amber)' },
    { k: 'spam', v: c.verdict_spam, color: 'var(--amber)' },
    { k: 'benign', v: c.verdict_benign, color: 'var(--green)' },
    { k: 'unknown', v: c.verdict_unknown, color: 'var(--faint)' },
  ].filter((s) => s.v > 0);
  const total = segs.reduce((a, s) => a + s.v, 0);
  if (total === 0) return <span className="faint small">—</span>;
  return (
    <div style={{ minWidth: 120 }}>
      <div style={{ display: 'flex', height: 8, borderRadius: 6, overflow: 'hidden', background: '#152339' }}>
        {segs.map((s) => (
          <div
            key={s.k}
            title={`${s.k}: ${s.v}`}
            style={{ width: `${(s.v / total) * 100}%`, background: s.color }}
          />
        ))}
      </div>
      <div className="cell-sub" style={{ marginTop: 3 }}>{total} classified</div>
    </div>
  );
}

// ── 4. Feed health ───────────────────────────────────────────────
function FeedPanel() {
  const { data, error, loading, reload } = usePanel(statFeeds, (r) => r?.feeds || []);
  const empty = data && data.length === 0;
  return (
    <PanelShell title="Feed health" sub="threat-intelligence sources">
      <PanelBody loading={loading} error={error} empty={empty} reload={reload}>
        {data && data.length > 0 && (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Feed</th>
                  <th>Type</th>
                  <th>Enabled</th>
                  <th className="num" style={{ textAlign: 'right' }}>Weight</th>
                  <th>Last fetch</th>
                  <th className="num" style={{ textAlign: 'right' }}>Contributed</th>
                  <th className="num" style={{ textAlign: 'right' }}>Active</th>
                  <th className="num" style={{ textAlign: 'right' }}>Avg risk</th>
                </tr>
              </thead>
              <tbody>
                {data.map((f) => (
                  <tr key={f.feed_id}>
                    <td className="cell-strong">{f.display_name || f.name}</td>
                    <td className="small">{f.feed_type || '—'}</td>
                    <td>
                      {f.enabled == null ? (
                        '—'
                      ) : (
                        <span className={`badge ${f.enabled ? 'ok' : 'warn'}`}>
                          <span className={`dot ${f.enabled ? 'on' : 'off'}`} style={{ marginRight: 5 }} />
                          {f.enabled ? 'on' : 'off'}
                        </span>
                      )}
                    </td>
                    <td className="num">{num1(f.reliability_weight)}</td>
                    <td className="cell-sub" title={fmtDate(f.last_fetched_at)}>
                      {fmtAgo(f.seconds_since_fetch)}
                    </td>
                    <td className="num">{num(f.total_threats_contributed)}</td>
                    <td className="num">{num(f.active_threats)}</td>
                    <td className="num">{num1(f.avg_threat_risk_score)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </PanelBody>
    </PanelShell>
  );
}

// ── 5. Rule performance ──────────────────────────────────────────
function RulePanel() {
  const { data, error, loading, reload } = usePanel(statRules, (r) => r?.rules || []);
  const empty = data && data.length === 0;
  return (
    <PanelShell title="Rule performance" sub="detection-rule firing volume">
      <PanelBody loading={loading} error={error} empty={empty} reload={reload}>
        {data && data.length > 0 && (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Target</th>
                  <th>Status</th>
                  <th className="num" style={{ textAlign: 'right' }}>Hits 24h</th>
                  <th className="num" style={{ textAlign: 'right' }}>Hits 7d</th>
                  <th className="num" style={{ textAlign: 'right' }}>Total hits</th>
                  <th className="num" style={{ textAlign: 'right' }}>Score Σ</th>
                  <th>Last fired</th>
                </tr>
              </thead>
              <tbody>
                {data.map((r) => (
                  <tr key={r.rule_id}>
                    <td>
                      <div className="cell-strong truncate" style={{ maxWidth: 220 }}>{r.name}</div>
                      <div className="cell-sub mono">v{r.version}</div>
                    </td>
                    <td>
                      <span className="badge">{r.target || '—'}</span>
                    </td>
                    <td>
                      <span className={`badge ${(r.status || '').toLowerCase() === 'active' ? 'ok' : 'warn'}`}>
                        {r.status || 'unknown'}
                      </span>
                    </td>
                    <td className="num">{num(r.hits_last_24h)}</td>
                    <td className="num">{num(r.hits_last_7d)}</td>
                    <td className="num">{num(r.total_hits)}</td>
                    <td className="num">{num(r.total_score_contributed)}</td>
                    <td className="cell-sub">{r.last_fired_at ? fmtDate(r.last_fired_at) : 'never'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </PanelBody>
    </PanelShell>
  );
}
