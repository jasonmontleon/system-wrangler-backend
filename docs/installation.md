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
| `SW_OIDC_*` | no | — | Optional OIDC single sign-on (see [OIDC](#oidc-single-sign-on)). |

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

Terminating TLS at a reverse proxy in front of System Wrangler also works.

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
  system-wrangler --rotate-keys
```

## Tenancy

System Wrangler is **single-tenant** by design. To isolate separate
environments, run a second container with its own database and key — there is no
tenant concept inside one instance.

## Health checks

- `GET /api/health` — liveness.
- `GET /api/ready` — readiness.

Point your orchestrator's probes at these.
