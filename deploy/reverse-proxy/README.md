# CyberSiren — Public Dashboards (reverse proxy)

How CyberSiren's dashboards are exposed publicly on `cie21grad.systems`, behind a
single shared host-level Caddy. This file is the reverse-proxy runbook.

## Model (one door for the whole box)

```
internet ──(only :22, :80, :443)──▶ host Caddy (systemd: caddy)
                                     /etc/caddy/Caddyfile → imports sites/*.caddy
                                     terminates TLS (Let's Encrypt, auto)
                                          │ reverse_proxy → 127.0.0.1:<port>
                                          ▼
                         cybersiren containers, published on 127.0.0.1 ONLY
```

- Only **22/80/443** are open (ufw). Docker bypasses ufw for published ports, so a
  **DOCKER-USER** iptables rule (`docker-internet-lockdown.service`) drops all
  internet→container traffic. Containers also bind `127.0.0.1` (defense in depth —
  done in `deploy/compose/docker-compose.yml`).
- Wildcard DNS `*.cie21grad.systems` → this VPS, so any subdomain already resolves
  and Caddy issues a cert on first request. No per-subdomain DNS needed.

## Public URLs

| URL | → upstream (loopback) | Container | Auth |
|---|---|---|---|
| https://cs-demo.cie21grad.systems | `127.0.0.1:18090` | `portal` (inbox scanner) | open |
| https://cs-analyst.cie21grad.systems | `127.0.0.1:18089` | `svc-10-web` (analyst console) | app's own JWT login |
| https://cs-trace.cie21grad.systems | `127.0.0.1:16686` | `jaeger` | open (read-only) |
| https://cs-grafana.cie21grad.systems | `127.0.0.1:3001` | `grafana` | anon Viewer; admin login to edit |

Demo analyst login (seeded): `analyst@demo.cybersiren` / `analyst-demo-2026`.

## Deploy / change the proxy

The site file `cybersiren.caddy` here is the canonical copy. It carries no secrets
(no basic_auth), so it deploys verbatim:

```bash
sudo install -m 0644 deploy/reverse-proxy/cybersiren.caddy /etc/caddy/sites/cybersiren.caddy
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

To add/remove a dashboard: edit `cybersiren.caddy`, re-copy, reload. To gate a UI,
add a `basic_auth` block (`caddy hash-password --plaintext '…'`).

## Bring up the live stack

```bash
cd deploy/compose
docker compose --profile full --profile monitoring up -d --build
```

`full` runs the entire pipeline + both frontends; `monitoring` adds Prometheus +
Grafana (also folded into `full`'s profile list). Every published port binds
`127.0.0.1`. Data persists in the `pgdata` / `redpandadata` / `miniodata` volumes;
`restart: unless-stopped` survives reboot.

## Notes

- **Grafana data:** Prometheus scrapes the containerized full-profile services by
  name on `:9090` (job `cybersiren-full` in `prometheus/prometheus.yml`). The
  older `cybersiren-demos` / `cybersiren-pipeline` jobs target the standalone demo
  containers and native smoke stubs and stay "down" under `full` — that's expected.
- **nginx upstream:** `web/svc-10-dashboard/nginx.conf` uses Docker's resolver +
  a variable upstream so the analyst API survives `svc-10-api` recreation (no
  stale-IP 502s).
- **Gmail "Sign in with Google" (optional):** disabled while `GOOGLE_CLIENT_ID` is
  empty (the `.eml` / sample-phish flow needs nothing). To enable for a controlled
  audience: set `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` in
  `deploy/compose/.env`, register `https://cs-demo.cie21grad.systems/oauth/callback`
  as an authorized redirect URI on the OAuth client, add testers (the app is
  unverified), then `docker compose ... up -d portal`.

## Troubleshooting

| Symptom | Check |
|---|---|
| 502 from a subdomain | upstream container/port up? `docker ps`, `curl 127.0.0.1:<port>` |
| Cert won't issue | `dig +short <host> @8.8.8.8` → VPS IP; `sudo journalctl -u caddy` for ACME |
| Reload proxy | `sudo systemctl reload caddy` |
| Re-apply Docker firewall (after `systemctl restart docker`) | auto via `docker-internet-lockdown.service` |
