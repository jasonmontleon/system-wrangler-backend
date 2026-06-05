<!-- SPDX-License-Identifier: Apache-2.0 -->

# Installation guide

How to deploy and operate System Wrangler. For a first run, the
[Quick start](quickstart.md) is faster; this guide covers production concerns.

## Requirements

- A container runtime (`podman` or `docker`).
- Persistent storage for the SQLite database.
- Network reach over **SSH** to the systems you intend to manage. The image
  bundles `ansible-core`, `openssh-clients`, and the `ansible.windows`
  collection, so it can drive Linux, macOS, Windows, and BSD hosts.
- *(Optional)* a **Prometheus** that scrapes your hosts' exporters, for the
  telemetry pages and metric-based alerts.

## Environment variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `SW_MASTER_KEY_FILE` | **yes** | — | Path to a file containing the base64 of 32 random bytes; used to seal secrets at rest (AES-256-GCM). |
| `SW_MASTER_KEY_FILE_PREVIOUS` | no | — | The outgoing key during a [key rotation](#rotating-the-master-key). |
| `PORT` | no | `8080` | Port the HTTP(S) server listens on. |
| `DB_PATH` | no | `/var/lib/system-wrangler/system-wrangler.db` (image) | SQLite database path. |
| `SW_PROMETHEUS_URL` | no | `http://127.0.0.1:9090` | Upstream Prometheus for telemetry and metric alerts. |
| `TLS_CERT_PATH` / `TLS_KEY_PATH` | no | — | Enable HTTPS (see [TLS](#tls)). Both or neither. |
| `SW_SECURE_COOKIES` | no | tracks TLS | Force the `Secure` flag on auth cookies. Defaults to on when the app serves TLS directly; set `true` when TLS terminates at a reverse proxy (see [TLS](#tls)). |
| `SW_OIDC_*` | no | — | Optional OIDC single sign-on (see [OIDC](#oidc-single-sign-on)). |
| `SW_TARGETS_FILE` | no | — | When set, write a Prometheus file-discovery targets file here so Prometheus finds the exporters (see [Deploying with Prometheus](#deploying-with-prometheus)). |
| `SW_INTERNAL_SECRET_FILE` | no | — | Shared bearer secret that gates the `/internal/scrape/...` proxy Prometheus scrapes through. |
| `SW_BACKEND_TARGET` | no | `127.0.0.1:8080` | Address written into each targets entry — where Prometheus reaches the scrape proxy. |

## Deploying with Prometheus

The standalone `podman run` above gets you the app, but the telemetry pages need
a Prometheus. The repo ships a ready-made two-container stack in
[`deploy/`](../deploy) that wires it up for you — this is the recommended way to
run System Wrangler with metrics.

```
deploy/
  compose.yml      the two services (system-wrangler + prometheus)
  prometheus.yml   Prometheus's scrape config for this stack
```

### How it fits together

- The two containers **share one network namespace**
  (`network_mode: "service:system-wrangler"`), so they reach each other over
  `127.0.0.1` — no container DNS. That's why the defaults
  (`SW_BACKEND_TARGET=127.0.0.1:8080`, `SW_PROMETHEUS_URL=http://127.0.0.1:9090`)
  work without being set.
- System Wrangler **writes the scrape targets** to a file on the shared
  `sw-targets` volume (`SW_TARGETS_FILE`) on every inventory change. Prometheus
  watches that file via `file_sd_configs` and picks up new exporters within
  seconds — you never hand-edit `prometheus.yml` to add a host.
- Prometheus **scrapes through System Wrangler**, at
  `/internal/scrape/{system}/{exporter}`, authenticating with a shared bearer
  secret (`SW_INTERNAL_SECRET_FILE`). Only the app is published on the host
  (`8080`); Prometheus is reachable only inside the shared namespace, and the SPA
  queries it through the app's `/api/metrics/query` proxy.

So **`prometheus.yml` is part of this stack, not a standalone Prometheus
config** — it defines the single `system-wrangler-exporters` job that reads the
discovered targets and sends the bearer token. Keep it alongside `compose.yml`.

### One-time setup

From `deploy/`, create the two secret files both containers mount read-only:

```sh
cd deploy/
# Master key: base64 of 32 random bytes (seals secrets at rest).
head -c 32 /dev/urandom | base64 > master.key
chmod 600 master.key
# Internal secret: the bearer token Prometheus uses to scrape through the app.
head -c 24 /dev/urandom | base64 > internal-secret
chmod 600 internal-secret
```

### Bring it up

```sh
podman-compose -f deploy/compose.yml up -d
```

Open <http://localhost:8080> and create the initial administrator. Install an
exporter on a host from its **Monitoring** tab; within a few seconds Prometheus
discovers it and the telemetry pages light up.

### Operational notes

- **Retention** is 365 days out of the box, matching the SPA's longest chart
  range (`1y`). Adjust `--storage.tsdb.retention.time` on the prometheus service
  to change it.
- **Restarts:** restarting the `system-wrangler` container restarts Prometheus
  too, since Prometheus borrows its network namespace. `depends_on` keeps start
  order and `restart: unless-stopped` keeps both up.
- **Separate-namespace layout:** if you'd rather run the two services on their
  own networks with DNS instead of a shared namespace, drop the
  `network_mode:` line and set `SW_BACKEND_TARGET=system-wrangler:8080` and
  `SW_PROMETHEUS_URL=http://prometheus:9090`. (Podman pods via
  `x-podman.in_pod` aren't used: podman-compose still attaches each member to
  its own namespace, which overrides the pod's shared one.)

## Persistence

The SQLite database is the only state. In the image it lives under
`/var/lib/system-wrangler` (declared as a `VOLUME`). Mount a host directory or
named volume there so it survives restarts and image upgrades:

```sh
  -v system-wrangler-data:/var/lib/system-wrangler
```

## TLS

Set both `TLS_CERT_PATH` and `TLS_KEY_PATH` to PEM files and the server serves
HTTPS instead of HTTP (the image also exposes `8443`). Setting only one is
rejected, to fail loud on misconfiguration.

```sh
  -p 8443:8443 -e PORT=8443 \
  -v "$PWD/tls":/etc/system-wrangler/tls:ro \
  -e TLS_CERT_PATH=/etc/system-wrangler/tls/server.crt \
  -e TLS_KEY_PATH=/etc/system-wrangler/tls/server.key
```

Terminating TLS at a reverse proxy in front of System Wrangler also works. In
that setup the app speaks plain HTTP, so it can't tell the browser connection
is encrypted — set `SW_SECURE_COOKIES=true` so the auth cookies still carry the
`Secure` flag.

## Authentication

System Wrangler ships with **local accounts** — bcrypt-hashed passwords and
signed session cookies — and optional **TOTP two-factor authentication** that
users enable from their profile.

### OIDC single sign-on

To add an OIDC provider alongside (or instead of) local accounts, set:

| Variable | Purpose |
|---|---|
| `SW_OIDC_ENABLED` | `true` to turn it on. |
| `SW_OIDC_ISSUER` | Issuer URL (discovery document is fetched from here). |
| `SW_OIDC_CLIENT_ID` / `SW_OIDC_CLIENT_SECRET` | OAuth client credentials. |
| `SW_OIDC_REDIRECT_URL` | Callback URL — `https://<host>/api/auth/oidc/callback`. |
| `SW_OIDC_SCOPES` | Requested scopes (e.g. `openid email profile`). |
| `SW_OIDC_USERNAME_CLAIM` | Which claim maps to the username. |
| `SW_OIDC_PROVISION` | Whether to auto-create accounts on first login. |
| `SW_OIDC_DISPLAY_NAME` | Label shown on the sign-in button. |

Roles are still granted inside System Wrangler — an OIDC login authenticates a
user; an admin assigns what they can do.

## Backups

Trigger a backup from **Administration → Backup** in the UI (it produces a
consistent snapshot of the database). Restore by placing the snapshot where
`DB_PATH` points **and** providing the same `SW_MASTER_KEY_FILE` that sealed its
secrets — a restore against a mismatched key is detected and refused.

## Rotating the master key

To rotate the key that seals secrets:

1. Generate a new key file.
2. Start the server once with the **new** key as `SW_MASTER_KEY_FILE`, the
   **old** key as `SW_MASTER_KEY_FILE_PREVIOUS`, and the `--rotate-keys` flag.
   It re-seals every secret under the new key and exits.
3. Run normally afterward with only the new `SW_MASTER_KEY_FILE` set.

```sh
podman run --rm \
  -v "$PWD/data":/var/lib/system-wrangler \
  -v "$PWD/new.key":/keys/new:ro -v "$PWD/old.key":/keys/old:ro \
  -e SW_MASTER_KEY_FILE=/keys/new \
  -e SW_MASTER_KEY_FILE_PREVIOUS=/keys/old \
  quay.io/jasonmontleon/system-wrangler:latest --rotate-keys
```

## Tenancy

System Wrangler is **single-tenant** by design. To isolate separate
environments, run a second container with its own database and key — there is no
tenant concept inside one instance.

## Health checks

- `GET /api/health` — liveness.
- `GET /api/ready` — readiness.

Point your orchestrator's probes at these.
