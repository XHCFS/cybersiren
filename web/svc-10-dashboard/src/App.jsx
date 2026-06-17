import React from 'react';
import { Routes, Route, Navigate, NavLink, useNavigate } from 'react-router-dom';
import { useAuth, RequireAuth } from './context/AuthContext.jsx';
import LoginForm from './components/LoginForm.jsx';
import ScanList from './components/ScanList.jsx';
import ScanDetail from './components/ScanDetail.jsx';
import ScanForm from './components/ScanForm.jsx';
import Dashboard from './components/Dashboard.jsx';
import RulesView from './components/RulesView.jsx';
import Monitoring from './components/Monitoring.jsx';

// Sigil — the shared CyberSiren shield mark.
function Sigil() {
  return (
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
  );
}

// Shell wraps every authenticated view with the top nav + session widget.
function Shell({ children }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const onLogout = () => {
    logout();
    navigate('/login', { replace: true });
  };

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <Sigil />
          <div>
            <h1>CyberSiren</h1>
            <div className="sub">Analyst Console</div>
          </div>
        </div>
        <nav className="nav">
          <NavLink to="/scans" className={({ isActive }) => (isActive ? 'active' : '')}>
            Scans
          </NavLink>
          <NavLink to="/submit" className={({ isActive }) => (isActive ? 'active' : '')}>
            Submit
          </NavLink>
          <NavLink to="/stats" className={({ isActive }) => (isActive ? 'active' : '')}>
            Dashboards
          </NavLink>
          <NavLink to="/rules" className={({ isActive }) => (isActive ? 'active' : '')}>
            Rules
          </NavLink>
          <NavLink to="/monitoring" className={({ isActive }) => (isActive ? 'active' : '')}>
            Monitoring
          </NavLink>
        </nav>
        <div className="session">
          {user && (
            <div className="who">
              <div className="name">{user.display_name || user.email}</div>
              <div className="role">
                {user.role} · org {user.org_id}
              </div>
            </div>
          )}
          <button className="btn sm ghost" onClick={onLogout}>
            Sign out
          </button>
        </div>
      </header>
      <main className="main">{children}</main>
    </div>
  );
}

// Protected wraps a view in both the auth gate and the chrome shell.
function Protected({ children }) {
  return (
    <RequireAuth>
      <Shell>{children}</Shell>
    </RequireAuth>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginForm />} />

      <Route
        path="/scans"
        element={
          <Protected>
            <ScanList />
          </Protected>
        }
      />
      <Route
        path="/scans/:id"
        element={
          <Protected>
            <ScanDetail />
          </Protected>
        }
      />
      <Route
        path="/submit"
        element={
          <Protected>
            <ScanForm />
          </Protected>
        }
      />
      <Route
        path="/stats"
        element={
          <Protected>
            <Dashboard />
          </Protected>
        }
      />
      <Route
        path="/rules"
        element={
          <Protected>
            <RulesView />
          </Protected>
        }
      />
      <Route
        path="/monitoring"
        element={
          <Protected>
            <Monitoring />
          </Protected>
        }
      />

      <Route path="/" element={<Navigate to="/scans" replace />} />
      <Route path="*" element={<Navigate to="/scans" replace />} />
    </Routes>
  );
}
