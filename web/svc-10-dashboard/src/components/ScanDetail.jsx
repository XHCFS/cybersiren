import React, { useCallback, useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getEmail } from '../services/api.js';
import { Loading, ErrorState, EmptyState, RiskPill, VerdictChip } from './Shared.jsx';
import {
  riskBand,
  gaugeClass,
  fmtDate,
  pct,
  authClass,
  matchDetailText,
} from '../lib/format.js';

// ScanDetail — the full composite for one email (GET /api/v1/emails/{id}).
// Renders: hero verdict gauge, per-module risk bars, the rule-hits
// explainability table, URLs with TI matches + enriched threat, attachments,
// recipients, headers, verdict history timeline, and the message body. A 404
// (unmapped / RLS-hidden id) shows a graceful not-found state.

function ModuleBar({ label, score }) {
  const band = riskBand(score);
  const width = score == null ? 0 : Math.min(100, Math.max(0, score));
  return (
    <div className="modbar">
      <div className="spread">
        <span className="mk">{label}</span>
        <span className="mv">{score == null ? 'n/a' : `${score}/100`}</span>
      </div>
      <div className="meter">
        <i className={band === 'na' ? 'low' : band} style={{ width: `${width}%` }} />
      </div>
    </div>
  );
}

function AuthRow({ label, value }) {
  return (
    <div className="kv">
      <span className="k">{label}</span>
      <span className="v">
        <span className={`badge ${authClass(value)}`}>{value || 'none'}</span>
      </span>
    </div>
  );
}

export default function ScanDetail() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    getEmail(id)
      .then((res) => setData(res))
      .catch((err) => setError(err))
      .finally(() => setLoading(false));
  }, [id]);

  useEffect(() => {
    load();
  }, [load]);

  if (loading) return <Loading label="Loading scan detail…" min="50vh" />;

  if (error) {
    if (error.status === 404) {
      return (
        <>
          <BackLink />
          <EmptyState
            title="Email not found"
            hint="This message id is not mapped to a stored email, or it belongs to another organization."
            min="40vh"
          />
        </>
      );
    }
    return (
      <>
        <BackLink />
        <ErrorState error={error} onRetry={load} min="40vh" />
      </>
    );
  }

  const d = data;
  const band = riskBand(d.risk_score);
  const verdict = d.current_verdict;
  const history = d.verdict_history || [];
  const ruleHits = d.rule_hits || [];
  const urls = d.urls || [];
  const attachments = d.attachments || [];
  const recipients = d.recipients || [];

  return (
    <>
      <BackLink />

      {/* hero */}
      <div className={`hero ${band === 'na' ? '' : band}`}>
        <div className={`gauge ${gaugeClass(band)}`} style={{ '--p': d.risk_score ?? 0 }}>
          <b>{d.risk_score ?? '—'}</b>
        </div>
        <div className="htitle">
          <div className="hlabel">
            <VerdictChip label={verdict?.label || d.current_verdict?.label} />
          </div>
          <div className="hsub" style={{ marginTop: 8 }}>
            {d.subject || '(no subject)'}
          </div>
          <div className="hsub mono" style={{ marginTop: 4 }}>
            {d.sender_name ? `${d.sender_name} · ` : ''}
            {d.sender_email || d.sender_domain || 'unknown sender'}
          </div>
        </div>
        <div className="stack" style={{ alignItems: 'flex-end', gap: 4 }}>
          {verdict?.source && <span className="badge info">{verdict.source}</span>}
          {verdict?.confidence != null && (
            <span className="muted small">confidence {pct(verdict.confidence)}</span>
          )}
          {verdict?.model_version && (
            <span className="faint small mono">{verdict.model_version}</span>
          )}
        </div>
      </div>

      <div className="detail-grid">
        {/* ── LEFT column ───────────────────────────────────────── */}
        <div>
          {/* per-module sub-scores */}
          <div className="card">
            <h3 className="sec-h">Risk breakdown</h3>
            <div className="modgrid">
              <ModuleBar label="Header" score={d.header_risk_score} />
              <ModuleBar label="Content" score={d.content_risk_score} />
              <ModuleBar label="URLs" score={d.url_risk_score} />
              <ModuleBar label="Attachments" score={d.attachment_risk_score} />
            </div>
          </div>

          {/* rule hits — explainability surface */}
          <div className="card">
            <h3 className="sec-h">
              Rule hits <span className="count">{ruleHits.length}</span>
            </h3>
            {ruleHits.length === 0 ? (
              <div className="empty-inline">No detection rules fired on this message.</div>
            ) : (
              <div className="tbl-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>Rule</th>
                      <th style={{ width: 90 }}>Target</th>
                      <th style={{ width: 70 }}>Impact</th>
                      <th>Match</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ruleHits.map((h) => (
                      <tr key={h.id}>
                        <td>
                          <div className="cell-strong">{h.rule_name || `rule ${h.rule_id ?? '?'}`}</div>
                          {h.rule_description && (
                            <div className="cell-sub truncate" style={{ maxWidth: 280 }}>
                              {h.rule_description}
                            </div>
                          )}
                        </td>
                        <td>
                          <span className="badge">{h.rule_target || '—'}</span>
                        </td>
                        <td className="num">
                          {h.score_impact > 0 ? `+${h.score_impact}` : h.score_impact}
                        </td>
                        <td className="mono small truncate" style={{ maxWidth: 240 }} title={matchDetailText(h.match_detail)}>
                          {matchDetailText(h.match_detail) || '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* URLs + TI + enriched threat */}
          <div className="card">
            <h3 className="sec-h">
              URLs <span className="count">{urls.length}</span>
            </h3>
            {urls.length === 0 ? (
              <div className="empty-inline">No URLs were extracted from this message.</div>
            ) : (
              urls.map((u) => <UrlCard key={u.id} url={u} />)
            )}
          </div>

          {/* body */}
          {(d.body_plain || d.body_html) && (
            <div className="card">
              <h3 className="sec-h">Message body</h3>
              {d.body_plain ? (
                <pre
                  className="mono small"
                  style={{
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                    margin: 0,
                    maxHeight: 360,
                    overflow: 'auto',
                    color: 'var(--muted)',
                  }}
                >
                  {d.body_plain}
                </pre>
              ) : (
                <div className="muted small">
                  Only an HTML body is stored ({d.body_html.length.toLocaleString()} bytes). Raw HTML
                  is not rendered in the console for safety.
                </div>
              )}
            </div>
          )}
        </div>

        {/* ── RIGHT column ──────────────────────────────────────── */}
        <div>
          {/* headers + authentication */}
          <div className="card">
            <h3 className="sec-h">Headers</h3>
            <div className="kv">
              <span className="k">From</span>
              <span className="v">{d.sender_email || '—'}</span>
            </div>
            {d.sender_domain && (
              <div className="kv">
                <span className="k">Domain</span>
                <span className="v">{d.sender_domain}</span>
              </div>
            )}
            {d.reply_to_email && (
              <div className="kv">
                <span className="k">Reply-To</span>
                <span className="v">{d.reply_to_email}</span>
              </div>
            )}
            {d.return_path && (
              <div className="kv">
                <span className="k">Return-Path</span>
                <span className="v">{d.return_path}</span>
              </div>
            )}
            {d.message_id && (
              <div className="kv">
                <span className="k">Message-ID</span>
                <span className="v truncate" style={{ maxWidth: 180 }} title={d.message_id}>
                  {d.message_id}
                </span>
              </div>
            )}
            <hr className="divider" />
            <AuthRow label="SPF" value={d.auth_spf} />
            <AuthRow label="DKIM" value={d.auth_dkim} />
            <AuthRow label="DMARC" value={d.auth_dmarc} />
            <hr className="divider" />
            <div className="kv">
              <span className="k">Sent</span>
              <span className="v">{fmtDate(d.sent_at)}</span>
            </div>
            <div className="kv">
              <span className="k">Fetched</span>
              <span className="v">{fmtDate(d.fetched_at)}</span>
            </div>
            <div className="kv">
              <span className="k">Internal ID</span>
              <span className="v">{d.internal_id}</span>
            </div>
          </div>

          {/* verdict history timeline */}
          <div className="card">
            <h3 className="sec-h">
              Verdict history <span className="count">{history.length}</span>
            </h3>
            {history.length === 0 ? (
              <div className="empty-inline">No verdict has been recorded yet.</div>
            ) : (
              <div className="timeline">
                {history.map((v, idx) => (
                  <div key={v.id} className={`tl-item ${idx === 0 ? 'current' : ''}`}>
                    <div className="row" style={{ gap: 8 }}>
                      <VerdictChip label={v.label} />
                      {v.source && <span className="badge">{v.source}</span>}
                      {v.confidence != null && (
                        <span className="muted small">{pct(v.confidence)}</span>
                      )}
                    </div>
                    {v.notes && <div className="small muted" style={{ marginTop: 4 }}>{v.notes}</div>}
                    <div className="tl-meta">
                      {fmtDate(v.created_at)}
                      {v.model_version ? ` · ${v.model_version}` : ''}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* attachments */}
          <div className="card">
            <h3 className="sec-h">
              Attachments <span className="count">{attachments.length}</span>
            </h3>
            {attachments.length === 0 ? (
              <div className="empty-inline">No attachments.</div>
            ) : (
              attachments.map((a) => (
                <div className="kv" key={a.attachment_id}>
                  <span className="k truncate" style={{ maxWidth: 170 }} title={a.filename}>
                    {a.filename || '(unnamed)'}
                  </span>
                  <span className="v row" style={{ justifyContent: 'flex-end' }}>
                    <span className="faint small">{a.content_type || '—'}</span>
                    <RiskPill score={a.risk_score == null ? null : a.risk_score} />
                  </span>
                </div>
              ))
            )}
          </div>

          {/* recipients */}
          <div className="card">
            <h3 className="sec-h">
              Recipients <span className="count">{recipients.length}</span>
            </h3>
            {recipients.length === 0 ? (
              <div className="empty-inline">No recipients recorded.</div>
            ) : (
              recipients.map((r) => (
                <div className="kv" key={r.id}>
                  <span className="k">
                    <span className="badge" style={{ marginRight: 6 }}>
                      {r.recipient_type || 'to'}
                    </span>
                    {r.display_name || ''}
                  </span>
                  <span className="v">{r.address}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </>
  );
}

function BackLink() {
  return (
    <div style={{ marginBottom: 14 }}>
      <Link to="/scans" className="small">
        ← Back to scans
      </Link>
    </div>
  );
}

// UrlCard renders one extracted URL with its TI matches + the enriched threat
// record (domain, country, ASN, threat type, online status).
function UrlCard({ url }) {
  const t = url.threat;
  const ti = url.ti_matches || [];
  return (
    <div className="urlcard">
      <div className="url">{t?.url || url.visible_text || `link #${url.id}`}</div>
      {url.visible_text && t?.url && url.visible_text !== t.url && (
        <div className="faint small" style={{ marginTop: 3 }}>
          shown as: {url.visible_text}
        </div>
      )}
      {t ? (
        <div className="pills">
          {t.threat_type && <span className="badge bad">{t.threat_type}</span>}
          {t.online != null && (
            <span className={`badge ${t.online ? 'bad' : 'ok'}`}>
              <span className={`dot ${t.online ? 'on' : 'off'}`} style={{ marginRight: 5 }} />
              {t.online ? 'online' : 'offline'}
            </span>
          )}
          {t.domain && <span className="badge">{t.domain}</span>}
          {t.country && <span className="badge">{t.country}</span>}
          {t.asn != null && (
            <span className="badge" title={t.asn_name || ''}>
              AS{t.asn}
              {t.asn_name ? ` ${t.asn_name}` : ''}
            </span>
          )}
          {t.ip_address && <span className="badge mono">{t.ip_address}</span>}
          {t.registrar && <span className="badge">{t.registrar}</span>}
          {t.risk_score != null && <RiskPill score={t.risk_score} />}
          {t.is_global && <span className="badge violet">global TI</span>}
        </div>
      ) : (
        <div className="faint small" style={{ marginTop: 6 }}>
          Not matched to enriched threat intelligence.
        </div>
      )}
      {ti.length > 0 && (
        <div className="pills">
          {ti.map((m) => (
            <span key={m.id} className="badge info" title={`TI indicator ${m.ti_indicator_id}`}>
              {m.match_type} match
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
