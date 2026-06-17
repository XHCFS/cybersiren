// External dashboard links shown on the Monitoring page.
//
// The analyst console is served at cs-analyst.<domain>; its sibling dashboards
// live at cs-demo / cs-trace / cs-grafana.<domain>. We derive those from the
// current hostname so this works on any domain the box is fronted by, fall back
// to the public deployment, and allow explicit build-time overrides via Vite env
// (VITE_DEMO_URL / VITE_TRACE_URL / VITE_GRAFANA_URL).

const PUBLIC = {
  demo: 'https://cs-demo.cie21grad.systems',
  trace: 'https://cs-trace.cie21grad.systems',
  grafana: 'https://cs-grafana.cie21grad.systems',
};

// cs-analyst.example.com -> cs-<sub>.example.com (null off the public host, e.g. localhost dev)
function sibling(sub) {
  if (typeof window === 'undefined') return null;
  const { protocol, hostname, port } = window.location;
  const m = hostname.match(/^cs-analyst\.(.+)$/);
  if (!m) return null;
  return `${protocol}//cs-${sub}.${m[1]}${port ? `:${port}` : ''}`;
}

function base(sub, envVal) {
  return envVal || sibling(sub) || PUBLIC[sub];
}

const env = import.meta.env || {};
export const demoUrl = base('demo', env.VITE_DEMO_URL);
export const traceUrl = base('trace', env.VITE_TRACE_URL);
export const grafanaUrl = base('grafana', env.VITE_GRAFANA_URL);

// Grafana deep links resolve to each board's full slug automatically.
const gd = (uid) => `${grafanaUrl}/d/${uid}`;

// Top-level surfaces (the other demoable dashboards on the box).
export const surfaceLinks = [
  { href: demoUrl, name: 'Inbox Scanner', tag: 'demo', desc: 'Interactive end-to-end demo — upload an .eml or load a sample and watch the pipeline score it.' },
  { href: traceUrl, name: 'Jaeger Tracing', tag: 'traces', desc: 'Distributed trace across all pipeline services for a single email.' },
  { href: grafanaUrl, name: 'Grafana Home', tag: 'metrics', desc: 'Metrics dashboards (anonymous read-only viewer).' },
];

// Per-service Grafana dashboards (one card each).
export const grafanaBoards = [
  { href: gd('cybersiren-svc-01'), svc: 'svc-01', name: 'Ingestion' },
  { href: gd('cybersiren-svc-02'), svc: 'svc-02', name: 'Parser' },
  { href: gd('cybersiren-svc03'), svc: 'svc-03', name: 'URL Analysis' },
  { href: gd('cybersiren-svc03-phishing'), svc: 'svc-03', name: 'Phishing — Domain Guard + L2 Fusion' },
  { href: gd('cybersiren-svc-04'), svc: 'svc-04', name: 'Header Analysis' },
  { href: gd('cybersiren-svc-05'), svc: 'svc-05', name: 'Attachment Analysis' },
  { href: gd('cybersiren-svc06'), svc: 'svc-06', name: 'NLP' },
  { href: gd('cybersiren-svc-07'), svc: 'svc-07', name: 'Aggregator' },
  { href: gd('cybersiren-svc-08'), svc: 'svc-08', name: 'Decision Engine' },
  { href: gd('cybersiren-svc-09'), svc: 'svc-09', name: 'Notification' },
  { href: gd('cybersiren-svc-10'), svc: 'svc-10', name: 'API / Console Backend' },
  { href: gd('cybersiren-svc11'), svc: 'svc-11', name: 'TI Sync' },
];
