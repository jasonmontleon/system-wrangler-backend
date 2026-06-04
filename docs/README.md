<!-- SPDX-License-Identifier: Apache-2.0 -->

# System Wrangler documentation

Documentation for System Wrangler — a single-container dashboard for managing
package updates, telemetry, alerts, and notifications across every system you
run. If you're new here, start with the [project README](../README.md) for the
high-level pitch and a quick start.

## For users

- **[Quick start](quickstart.md)** — get a running instance and sign in.
- **[User guide](user-guide.md)** — a guided tour of every area of the UI, with
  screenshots: the dashboard, inventory, monitoring, alerts, and administration.

## For operators

- **[Installation guide](installation.md)** — deployment, environment variables,
  TLS, reverse-proxy mode, backups, and master-key rotation.
- **[Troubleshooting](troubleshooting.md)** — common problems and how to resolve
  them.

## For developers

- **[Architecture](architecture.md)** — how the backend, embedded SPA, SQLite,
  SSH/Ansible, and Prometheus fit together.
- **[API reference](api-reference.md)** — the HTTP API surface.
- **[Development guide](development.md)** — building from source, the dev server,
  tests, and quality gates.

## Conventions

- Screenshots live in [`images/`](images) and are regenerated from a
  deterministic demo dataset (see [`fixtures/`](fixtures)) so they stay
  consistent.
- Commands assume `podman`; `docker` works identically unless noted.

> **Status:** Initial drafts of all sections are in place. The User guide is the
> most complete; the others will be expanded as features evolve.
