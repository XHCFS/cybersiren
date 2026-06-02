import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../services/api.js";
import { verdictClass } from "../services/format.js";

const REFRESH_MS = 5000;

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [recent, setRecent] = useState([]);

  useEffect(() => {
    let active = true;
    const load = () => {
      api.get("/stats").then(({ data }) => active && setStats(data)).catch(() => {});
      api.get("/verdicts/recent").then(({ data }) => active && setRecent(data.verdicts || [])).catch(() => {});
    };
    load();
    const t = setInterval(load, REFRESH_MS);
    return () => {
      active = false;
      clearInterval(t);
    };
  }, []);

  return (
    <section>
      <h2>Overview</h2>
      <div className="cards">
        <Stat label="Total scans" value={stats?.total} />
        <Stat label="Phishing" value={stats?.phishing} tone="danger" />
        <Stat label="Suspicious" value={stats?.suspicious} tone="warn" />
        <Stat label="High risk" value={stats?.high_risk} tone="danger" />
        <Stat label="Last 24h" value={stats?.last_24h} />
      </div>

      <h3>Recent verdicts</h3>
      <div className="card">
        {recent.length === 0 && <p className="muted">No verdicts yet.</p>}
        {recent.map((v, i) => (
          <div key={i} className="row">
            <Link to={`/scans/${v.internal_id}`}>#{v.internal_id}</Link>
            <span className={verdictClass(v.verdict_label)}>{v.verdict_label}</span>
            <span>{v.risk_score}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function Stat({ label, value, tone }) {
  return (
    <div className={`card stat stat-${tone || "default"}`}>
      <div className="stat-value">{value ?? "—"}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
