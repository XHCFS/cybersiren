// format.js — pure display helpers shared across views. No React, no API.

// Risk scores are 0..100. Bands: low <40, med 40..69, high >=70. A null/0 score
// is common for un-scored emails — treat null/undefined as "na" but 0 as a real
// (low) score so a confirmed-benign 0 still reads green rather than greyed out.
export function riskBand(score) {
  if (score == null) return 'na';
  if (score >= 70) return 'high';
  if (score >= 40) return 'med';
  return 'low';
}

// gaugeClass maps a band to the conic-gradient color helper class.
export function gaugeClass(band) {
  return { low: 'gc-green', med: 'gc-amber', high: 'gc-rose', na: 'gc-muted' }[band] || 'gc-muted';
}

// verdictClass normalises a verdict label to a known chip class. Empty labels
// (un-scored emails) fall back to "none".
export function verdictClass(label) {
  const v = (label || '').toLowerCase().trim();
  if (!v) return 'none';
  if (['benign', 'suspicious', 'spam', 'phishing', 'malware', 'unknown'].includes(v)) return v;
  return 'unknown';
}

export function verdictText(label) {
  return label && label.trim() ? label : 'unscored';
}

// fmtDate renders an RFC-3339 timestamp compactly; "—" for missing.
export function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

// fmtAgo renders a coarse relative-age string from seconds (feed health).
export function fmtAgo(seconds) {
  if (seconds == null) return 'never';
  const s = Math.max(0, Math.floor(seconds));
  if (s < 90) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 90) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

// num formats an integer with grouping; "0" stays "0".
export function num(n) {
  if (n == null) return '—';
  return Number(n).toLocaleString();
}

// num1 formats a float to one decimal place.
export function num1(n) {
  if (n == null) return '—';
  return Number(n).toFixed(1);
}

// pct converts a 0..1 confidence to a percent string.
export function pct(conf) {
  if (conf == null) return '—';
  return `${Math.round(conf * 100)}%`;
}

// authClass maps an SPF/DKIM/DMARC result to a badge tone.
export function authClass(result) {
  const r = (result || '').toLowerCase();
  if (r === 'pass') return 'ok';
  if (['fail', 'softfail', 'permerror', 'reject'].includes(r)) return 'bad';
  if (['neutral', 'none', 'temperror', ''].includes(r)) return 'warn';
  return 'info';
}

// matchDetailText renders a rule-hit match_detail (which may be a string, an
// object, or null) into a short human-readable string for the explainability
// table.
export function matchDetailText(detail) {
  if (detail == null) return '';
  if (typeof detail === 'string') return detail;
  try {
    return JSON.stringify(detail);
  } catch {
    return String(detail);
  }
}
