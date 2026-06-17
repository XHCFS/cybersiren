import React from 'react';
import { surfaceLinks, grafanaBoards } from '../lib/links.js';

// Monitoring — a links panel to the other CyberSiren dashboards on this box
// (the interactive demo, Jaeger traces, and the per-service Grafana boards).
// These are sibling subdomains, so each opens in a new tab.

function LinkTile({ href, tag, name, desc }) {
  return (
    <a className="link-tile" href={href} target="_blank" rel="noopener noreferrer">
      <div className="link-tile-head">
        {tag && <span className="tag">{tag}</span>}
        <span className="link-tile-name">{name}</span>
        <span className="link-tile-ext" aria-hidden="true">↗</span>
      </div>
      {desc && <div className="link-tile-desc">{desc}</div>}
    </a>
  );
}

export default function Monitoring() {
  return (
    <div className="monitoring">
      <section className="dash-section">
        <h3 className="sec-title">
          Dashboards
          <span className="faint small" style={{ fontWeight: 400, fontFamily: 'var(--font-ui)' }}>
            demo &amp; observability surfaces — open in a new tab
          </span>
        </h3>
        <div className="grid-cards">
          {surfaceLinks.map((l) => (
            <LinkTile key={l.href} href={l.href} tag={l.tag} name={l.name} desc={l.desc} />
          ))}
        </div>
      </section>

      <section className="dash-section">
        <h3 className="sec-title">
          Grafana — per-service metrics
          <span className="faint small" style={{ fontWeight: 400, fontFamily: 'var(--font-ui)' }}>
            one board per pipeline service
          </span>
        </h3>
        <div className="grid-cards">
          {grafanaBoards.map((b) => (
            <LinkTile key={b.href} href={b.href} tag={b.svc} name={b.name} />
          ))}
        </div>
      </section>
    </div>
  );
}
