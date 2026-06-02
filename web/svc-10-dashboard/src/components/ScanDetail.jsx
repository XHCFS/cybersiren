import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import api from "../services/api.js";
import { pg, verdictClass } from "../services/format.js";

export default function ScanDetail() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    api
      .get(`/emails/${id}`)
      .then((resp) => active && setData(resp.data))
      .catch(() => active && setError("Failed to load scan"));
    return () => {
      active = false;
    };
  }, [id]);

  if (error) return <p className="error">{error}</p>;
  if (!data) return <p className="muted">Loading…</p>;

  const e = data.email || {};
  const verdict = pg(e.current_verdict_label) || "unknown";

  return (
    <section className="detail">
      <Link to="/scans" className="back">← Scans</Link>
      <h2>Scan #{pg(e.internal_id)} <span className={verdictClass(verdict)}>{verdict}</span></h2>

      <div className="card">
        <h3>Header</h3>
        <dl className="kv">
          <dt>From</dt><dd>{pg(e.sender_email) || "—"}</dd>
          <dt>Subject</dt><dd>{pg(e.subject) || "—"}</dd>
          <dt>Risk score</dt><dd>{pg(e.risk_score) ?? 0}</dd>
          <dt>SPF / DKIM / DMARC</dt><dd>{[pg(e.auth_spf), pg(e.auth_dkim), pg(e.auth_dmarc)].map((v) => v || "—").join(" / ")}</dd>
        </dl>
      </div>

      <Section title={`URLs (${(data.urls || []).length})`}>
        {(data.urls || []).map((u) => (
          <div key={pg(u.id)} className="row">
            <code className="truncate">{pg(u.url)}</code>
            <span className="muted">{pg(u.threat_type) || "—"}</span>
            <span>{pg(u.risk_score) ?? 0}</span>
          </div>
        ))}
      </Section>

      <Section title={`Attachments (${(data.attachments || []).length})`}>
        {(data.attachments || []).map((a) => (
          <div key={pg(a.attachment_id)} className="row">
            <span>{pg(a.filename) || "—"}</span>
            <span className="muted">{pg(a.content_type) || "—"}</span>
            <span>{pg(a.is_malicious) ? "malicious" : ""} {pg(a.risk_score) ?? 0}</span>
          </div>
        ))}
      </Section>

      <Section title={`Recipients (${(data.recipients || []).length})`}>
        {(data.recipients || []).map((r, i) => (
          <div key={i} className="row"><span>{pg(r.address)}</span><span className="muted">{pg(r.recipient_type)}</span></div>
        ))}
      </Section>

      <Section title={`Verdict history (${(data.verdicts || []).length})`}>
        {(data.verdicts || []).map((v, i) => (
          <div key={i} className="row">
            <span className={verdictClass(pg(v.label))}>{pg(v.label)}</span>
            <span className="muted">{pg(v.source)}</span>
            <span>{Math.round((pg(v.confidence) || 0) * 100)}%</span>
          </div>
        ))}
      </Section>
    </section>
  );
}

function Section({ title, children }) {
  return (
    <div className="card">
      <h3>{title}</h3>
      {children}
    </div>
  );
}
