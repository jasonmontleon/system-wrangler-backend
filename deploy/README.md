# Deployment

## Single-pod stack (backend + Prometheus sibling)

The metrics pipeline phase 1 introduces a Prometheus sibling container.
Both containers share a single network namespace so they reach each
other over `127.0.0.1` instead of container DNS; install becomes
`podman-compose up` rather than `podman run`.

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

- `system-wrangler:8080` — the existing SPA + API. Published on the
  host via `ports: ["8080:8080"]`.
- `prometheus:9090` — TSDB + scrape engine. Bound inside the pod
  only (no `ports:` mapping); the SPA reaches it via the
  `/api/metrics/query{,_range}` thin proxy on the backend, and the
  backend reaches it on `127.0.0.1:9090` because both containers
  share one netns.
- Targets file lives on the shared `sw-targets` volume. The backend
  writes `/var/lib/sw-targets/targets.json` on every inventory change;
  Prometheus reads it from the same volume mounted at
  `/etc/prometheus/sw-targets/targets.json` and reloads via the
  `file_sd_configs` watcher.

### Shared network namespace

Prometheus joins the backend's netns via `network_mode: "service:system-wrangler"`.
Compose translates that to `--network=container:<backend-id>`; the two
containers share one netns and reach each other over `127.0.0.1`
(no container DNS, no `system-wrangler` / `prometheus` hostname
dependency). The backend publishes both ports (`8080` for the SPA,
`9090` for Prometheus's UI if you keep that mapping).

The backend defaults track this layout: `SW_BACKEND_TARGET` defaults
to `127.0.0.1:8080` (what gets written into each `targets.json`
entry so Prometheus knows where to scrape) and `SW_PROMETHEUS_URL`
defaults to `http://127.0.0.1:9090` (where the metrics proxy
forwards SPA queries). Neither is set explicitly in `compose.yml`.

The `networks.default` block at the top points compose at the
pre-existing `podman` network instead of creating a project-scoped
`<project>_default`.

Restarting the backend container restarts Prometheus too — the
netns goes stale when the container holding it exits. `depends_on`
keeps start order; `restart: unless-stopped` on both keeps them up.

#### Operators on the legacy two-namespace layout

If you're on an older `compose.yml` that ran the two services in
separate netns (`networks:` block, container-DNS resolution),
override the two env vars to keep the previous behaviour:

```yaml
environment:
  SW_BACKEND_TARGET: system-wrangler:8080
  SW_PROMETHEUS_URL: http://prometheus:9090
```

Nothing forces the upgrade; the new shared-netns `compose.yml` is
opt-in via redeploy.

#### Why not podman pods via `x-podman.in_pod`?

It looks cleaner on paper but doesn't work transparently with
podman-compose: even with `pod_args: "--infra --share=net"`, compose
still attaches each member to a network with its own netns, which
overrides the pod's shared one. `network_mode: "service:..."` is
the working path on both podman-compose and docker compose.

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
