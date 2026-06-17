# CyberSiren — offline / emergency demo bundle

Run the **entire** CyberSiren stack on a laptop with **one command**, from prebuilt
images — no VPS, no local build. This is the viva fallback if the live VPS
(`*.cie21grad.systems`) is unreachable.

## Why it never goes stale (CI/CD)

`.github/workflows/demo-images.yml` rebuilds **all 15 service images and pushes them
to GHCR** (`ghcr.io/xhcfs/cybersiren-<svc>:latest`) on every merge to `main`. The
laptop just pulls those — so the bundle always reflects the latest `main`. The main
compose file stays the single source of truth; `images.override.yml` only pins the
GHCR image names on top of it (no duplicated/ drifting compose).

## One-time prep (do this while you HAVE internet, e.g. the night before)

```bash
git clone https://github.com/XHCFS/cybersiren && cd cybersiren
bash deploy/offline-bundle/START.sh          # pulls images, starts everything
```

Docker caches the pulled images locally, so every later run works **fully offline**.

> GHCR packages must be pullable. Easiest: make them **public** once
> (GitHub → repo → Packages → each package → visibility → Public). Otherwise
> `echo $GH_PAT | docker login ghcr.io -u <you> --password-stdin` first.

## At the viva (offline)

```bash
bash deploy/offline-bundle/START.sh
```

Prints the local URLs when ready:

| Surface | URL | Auth |
|---|---|---|
| Inbox scanner / demo | http://localhost:18090 | open |
| Analyst console | http://localhost:18089 | `analyst@demo.cybersiren` / `analyst-demo-2026` |
| Jaeger tracing | http://localhost:16686 | open |
| Grafana metrics | http://localhost:3001 | `admin` / `admin` |

Seed data (TI domains incl. the demo C2 domain, the malicious attachment hash, the
demo API key, the analyst login) is applied automatically by the `demo-seed` step,
so the sample emails classify correctly out of the box.

Stop: `docker compose -f deploy/compose/docker-compose.yml -f deploy/offline-bundle/images.override.yml -p cybersiren --profile full --profile monitoring down`

## Truly zero-internet (no GHCR at all)

If the venue has *no* network and you couldn't pre-pull:

```bash
# on any machine that has the images (the VPS, or your laptop after one online run):
bash deploy/offline-bundle/save-images.sh      # → deploy/offline-bundle/cybersiren-images.tar.gz (~8 GB)
# copy the whole repo (incl. that tarball) to the laptop, then:
bash deploy/offline-bundle/START.sh            # auto-loads the tarball, no network needed
```

## Notes

- `WITH_MONITORING=0 bash deploy/offline-bundle/START.sh` skips Grafana+Prometheus (~2 GB lighter).
- `CS_IMAGE_TAG=<commit-sha>` pins a specific build instead of `latest`.
- Gmail is intentionally excluded (no OAuth in the offline bundle); the `.eml` /
  sample-phish flow needs nothing.
- First boot pulls ~8 GB and builds no code; subsequent boots are fast.
