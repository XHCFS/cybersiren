import React, { createContext, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import * as api from '../services/api.js';

// AuthContext holds {token, user} and persists the token in localStorage so a
// page reload keeps the session. The login response carries the user record, so
// no extra /me round-trip is needed on login; getMe() is used to re-hydrate the
// user after a reload when only the token survives.

const STORAGE_TOKEN = api.TOKEN_KEY;
const STORAGE_USER = 'cybersiren.console.user';

const Ctx = createContext(null);

function readStored(key) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => readStored(STORAGE_TOKEN));
  const [user, setUser] = useState(() => {
    const raw = readStored(STORAGE_USER);
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  });
  // hydrating guards the first render while a reloaded token re-fetches /me, so
  // RequireAuth does not bounce a valid (but not-yet-hydrated) session.
  const [hydrating, setHydrating] = useState(() => Boolean(readStored(STORAGE_TOKEN)));

  // tokenRef gives the api layer a synchronous read of the current token without
  // it importing React state.
  const tokenRef = useRef(token);
  tokenRef.current = token;

  // logout clears everything. Wrapped in useRef so the api 401 hook keeps a
  // stable reference across renders.
  const logoutRef = useRef(() => {});
  logoutRef.current = () => {
    setToken(null);
    setUser(null);
    try {
      localStorage.removeItem(STORAGE_TOKEN);
      localStorage.removeItem(STORAGE_USER);
    } catch {
      /* ignore storage errors */
    }
  };

  // Wire the api layer to our live token + 401 handler exactly once.
  useEffect(() => {
    api.registerAuth({
      getToken: () => tokenRef.current,
      onUnauthorized: () => logoutRef.current(),
    });
  }, []);

  // On reload with a surviving token but no cached user, re-fetch /me. A 401
  // here trips onUnauthorized and clears the stale token.
  useEffect(() => {
    if (token && !user) {
      api
        .getMe()
        .then((me) => {
          setUser(me);
          try {
            localStorage.setItem(STORAGE_USER, JSON.stringify(me));
          } catch {
            /* ignore */
          }
        })
        .catch(() => {
          /* onUnauthorized already cleared the session on 401 */
        })
        .finally(() => setHydrating(false));
    } else {
      setHydrating(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function login(email, password) {
    const res = await api.login(email, password);
    setToken(res.token);
    setUser(res.user);
    try {
      localStorage.setItem(STORAGE_TOKEN, res.token);
      localStorage.setItem(STORAGE_USER, JSON.stringify(res.user));
    } catch {
      /* ignore */
    }
    return res.user;
  }

  const value = useMemo(
    () => ({
      token,
      user,
      hydrating,
      isAuthenticated: Boolean(token),
      login,
      logout: () => logoutRef.current(),
    }),
    [token, user, hydrating]
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
}

// RequireAuth gates protected routes. Unauthenticated users are redirected to
// /login (preserving the attempted path for post-login return).
export function RequireAuth({ children }) {
  const { isAuthenticated, hydrating } = useAuth();
  const location = useLocation();

  if (hydrating) {
    return (
      <div className="state" style={{ minHeight: '60vh' }}>
        <div className="spinner" />
        <div className="state-title">Restoring session…</div>
      </div>
    );
  }
  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }
  return children;
}
