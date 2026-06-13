# svc-10 Analyst Console (SPA)

A single-page React analyst console for CyberSiren. Talks to the svc-10 read API
(`services/svc-10-api-dashboard`, listens on `:8088`).

## Stack

- Vite + React 18, `react-router-dom` for routing.
- No charting library — stat visualizations are hand-rolled SVG/CSS.
- State visualizations and styling follow the dark security-console design used
  by `demo/dashboard`.

## Develop

```sh
npm ci          # install from the committed lockfile
npm run dev     # Vite dev server on http://localhost:5173
```

In dev the SPA calls **same-origin relative paths** (`/api/...`, `/healthz`).
Vite proxies those to the backend (default `http://localhost:8088`, overridable
via `VITE_PROXY_TARGET`). The backend CORS allow-list expects the SPA origin
`http://localhost:5173`.

Start the backend first (it serves login + the read API). Sign in with the
seeded MVP-1 demo analyst:

```
analyst@demo.cybersiren / analyst-demo-2026
```

## Build

```sh
npm run build   # emits dist/ (Vite default) — what the Dockerfile copies to nginx
npm run preview # serve the built dist/ on :5173
```

For a production build behind a different origin, set `VITE_API_BASE_URL` to the
backend base URL at build time (it defaults to `''` → relative paths).

## Routes

| Path         | View       | Backend |
| ------------ | ---------- | ------- |
| `/login`     | LoginForm  | `POST /api/v1/auth/login` |
| `/scans`     | ScanList   | `GET /api/v1/emails` |
| `/scans/:id` | ScanDetail | `GET /api/v1/emails/{id}` |
| `/submit`    | ScanForm   | `POST /api/v1/scan` |
| `/stats`     | Dashboard  | the 5 `GET /api/v1/stats/*` endpoints |
| `/rules`     | RulesView  | `GET /api/v1/rules` (read-only) |

## Scope

MVP-7 is read-mostly: JWT login, scan list/detail, scan submission, the 5 stats
dashboards, and a read-only rules view. There is intentionally **no** API-key
manager, user/org/feed management, rule editing, verdict-override, audit-log, or
live-feed UI.
