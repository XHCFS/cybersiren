# CyberSiren Dashboard (SVC-10 frontend)

React + Vite SPA for the SVC-10 API. Login (JWT), scan list, scan detail, and a
live overview.

## Develop

```bash
npm install
npm run dev      # http://localhost:5173, proxies /api -> http://localhost:8080
```

## Build

```bash
npm run build    # -> dist/  (served behind the same host as the API in prod)
```

## Layout
- `src/services/api.js` — axios instance + JWT interceptor (token in localStorage).
- `src/context/AuthContext.jsx` — login/logout state.
- `src/components/` — `LoginForm`, `ScanList`, `ScanDetail`, `Dashboard`.

Talks to: `POST /api/v1/auth/login`, `GET /api/v1/{emails,emails/:id,stats,campaigns,verdicts/recent}`.
