import React from 'react';
import { riskBand, verdictClass, verdictText } from '../lib/format.js';

// Shared presentational primitives reused across views: explicit loading,
// error, and empty states (so a reviewer never sees a blank white screen), plus
// the risk-score pill and verdict chip used in tables and detail.

export function Loading({ label = 'Loading…', min }) {
  return (
    <div className="state" style={min ? { minHeight: min } : undefined}>
      <div className="spinner" />
      <div className="state-title">{label}</div>
    </div>
  );
}

export function ErrorState({ error, onRetry, min }) {
  const msg = (error && error.message) || 'Something went wrong.';
  return (
    <div className="state error" style={min ? { minHeight: min } : undefined}>
      <div className="state-title">Could not load</div>
      <div style={{ maxWidth: 460 }}>{msg}</div>
      {onRetry && (
        <button className="btn sm" onClick={onRetry} style={{ marginTop: 6 }}>
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyState({ title = 'Nothing here yet', hint, min }) {
  return (
    <div className="state" style={min ? { minHeight: min } : undefined}>
      <div className="state-title">{title}</div>
      {hint && <div style={{ maxWidth: 460 }}>{hint}</div>}
    </div>
  );
}

// RiskPill renders a 0..100 score in a color band. null → "n/a".
export function RiskPill({ score }) {
  const band = riskBand(score);
  if (band === 'na') {
    return (
      <span className="risk na" title="not scored">
        n/a
      </span>
    );
  }
  return (
    <span className={`risk ${band}`}>
      {score}
      <span className="out">/100</span>
    </span>
  );
}

// VerdictChip renders a verdict label in its semantic color.
export function VerdictChip({ label }) {
  return <span className={`chip ${verdictClass(label)}`}>{verdictText(label)}</span>;
}

// ErrorBoundary catches render-time throws anywhere in the subtree so an
// unanticipated error (e.g. a contract field arriving in an unexpected shape)
// degrades to the shared ErrorState chrome with a reload action instead of
// unmounting the whole app to a blank white screen.
export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // Surface the failure for diagnostics without crashing the tree.
    // eslint-disable-next-line no-console
    console.error('Render error caught by ErrorBoundary:', error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="state error" style={{ minHeight: '60vh' }}>
          <div className="state-title">Something went wrong</div>
          <div style={{ maxWidth: 460 }}>
            {(this.state.error && this.state.error.message) ||
              'An unexpected error interrupted this view.'}
          </div>
          <button
            className="btn sm"
            onClick={() => window.location.reload()}
            style={{ marginTop: 6 }}
          >
            Reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
