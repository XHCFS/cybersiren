import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../services/api.js";
import { pg, verdictClass } from "../services/format.js";

export default function ScanList() {
  const [emails, setEmails] = useState([]);
  const [page, setPage] = useState(1);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setLoading(true);
    api
      .get("/emails", { params: { page, page_size: 25 } })
      .then(({ data }) => active && setEmails(data.emails || []))
      .catch(() => active && setError("Failed to load scans"))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [page]);

  return (
    <section>
      <h2>Scans</h2>
      {error && <p className="error">{error}</p>}
      <table className="table">
        <thead>
          <tr><th>ID</th><th>Sender</th><th>Subject</th><th>Score</th><th>Verdict</th></tr>
        </thead>
        <tbody>
          {emails.map((e) => {
            const id = pg(e.internal_id);
            const verdict = pg(e.current_verdict_label) || "unknown";
            return (
              <tr key={id}>
                <td><Link to={`/scans/${id}`}>{id}</Link></td>
                <td>{pg(e.sender_email) || "—"}</td>
                <td className="truncate">{pg(e.subject) || "—"}</td>
                <td>{pg(e.risk_score) ?? 0}</td>
                <td><span className={verdictClass(verdict)}>{verdict}</span></td>
              </tr>
            );
          })}
          {!loading && emails.length === 0 && (
            <tr><td colSpan="5" className="muted">No scans yet.</td></tr>
          )}
        </tbody>
      </table>
      <div className="pager">
        <button disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Prev</button>
        <span>Page {page}</span>
        <button disabled={emails.length < 25} onClick={() => setPage((p) => p + 1)}>Next</button>
      </div>
    </section>
  );
}
