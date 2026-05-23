# Deployment

## Single-pod stack (backend + Prometheus sibling)

The metrics pipeline phase 1 introduces a Prometheus sibling container.
Install becomes `podman-compose up` / `docker compose up` rather than
`podman run`.

### One-time setup

1. Generate a master key and the shared internal secret. Both
   containers read the secret from the same file via volume mount,
   so there's no `.env` step:
   ```sh
   cd deploy/
   head -c 32 /dev/urandom > master.key
   chmod 600 master.key
   head -c 24 /dev/urandom | base64 > internal-secret
   chmod 600 internal-secret
   ```

2. Build the backend image:
   ```sh
   podman build -t system-wrangler:latest .
   ```

3. Bring up the stack:
   ```sh
   podman-compose -f deploy/compose.yml up -d
   ```

### What runs where

- `system-wrangler:8080` — the existing SPA + API.
- `prometheus:9090` — TSDB + scrape engine. Bound on the compose
  network only; the SPA reaches it via the
  `/api/metrics/query{,_range}` thin proxy on the backend.
- Targets file lives on the shared `sw-targets` volume. The backend
  writes `/var/lib/sw-targets/targets.json` on every inventory change;
  Prometheus reads it from the same volume mounted at
  `/etc/prometheus/sw-targets/targets.json` and reloads via the
  `file_sd_configs` watcher.

### Trust boundary

- `/internal/scrape/{system}/{exporter}` is gated by the shared
  secret. Prometheus's `authorization.credentials_file` sends it as
  `Authorization: Bearer <secret>` on every scrape; the backend
  accepts that or the convenience `X-Sw-Internal-Secret: <secret>`
  header (useful when poking the endpoint with curl). Without
  either, the endpoint returns 403.
- The secret file lives at `deploy/internal-secret` on the host and
  is mounted read-only into both containers — same bytes in both
  places, no copy-paste step.
- Prometheus binds the compose network only and is not published on
  the host. The thin proxy at `/api/metrics/query{,_range}` is the
  only path the SPA has to Prometheus.

### Retention

Prometheus is configured for **365-day retention** out of the box —
matches the longest chart range preset (`1y`) the SPA offers. Adjust
`--storage.tsdb.retention.time` on the prometheus service if the
deployment needs a different window. Long-term storage is a separate
decision — see `research/retention.md`.
