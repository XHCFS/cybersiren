import React, { useState } from 'react';
import { useNavigate, useLocation, Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';

// LoginForm — email + password against POST /api/v1/auth/login. The backend
// returns a deliberately generic 401 ("invalid email or password") so the UI
// never reveals which field was wrong. On success we land back on the page the
// user was bounced from (or /scans).

export default function LoginForm() {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const dest = location.state?.from?.pathname || '/scans';

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  // Already signed in → skip the form.
  if (isAuthenticated) {
    return <Navigate to={dest} replace />;
  }

  async function onSubmit(e) {
    e.preventDefault();
    if (busy) return;
    setError(null);
    setBusy(true);
    try {
      await login(email.trim(), password);
      navigate(dest, { replace: true });
    } catch (err) {
      setError(err.message || 'Sign in failed.');
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={onSubmit}>
        <div className="brand">
          <div className="sigil">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
              <path
                d="M12 2l8 3v6c0 5-3.4 8.5-8 11-4.6-2.5-8-6-8-11V5l8-3z"
                stroke="#2ee6c4"
                strokeWidth="1.5"
                strokeLinejoin="round"
              />
              <path d="M12 7v6M12 16v0.5" stroke="#2ee6c4" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
          </div>
          <div>
            <h1>CyberSiren</h1>
            <div className="sub">Analyst Console</div>
          </div>
        </div>

        <p className="muted small" style={{ margin: '14px 0 18px' }}>
          Sign in to review scanned email, threat intelligence, and detection performance.
        </p>

        <label className="field">
          <span>Email</span>
          <input
            type="email"
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="analyst@demo.cybersiren"
            required
            autoFocus
          />
        </label>
        <label className="field">
          <span>Password</span>
          <input
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••••"
            required
          />
        </label>

        {error && <div className="form-error">{error}</div>}

        <button className="btn primary" type="submit" disabled={busy} style={{ width: '100%', marginTop: 14, justifyContent: 'center' }}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>

        <div className="login-hint">
          Demo credentials — <code>analyst@demo.cybersiren</code> / <code>analyst-demo-2026</code>
        </div>
      </form>
    </div>
  );
}
