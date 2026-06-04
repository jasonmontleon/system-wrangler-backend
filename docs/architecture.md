<!-- SPDX-License-Identifier: Apache-2.0 -->

# Architecture

System Wrangler is deliberately small to operate: **one Go process, one SQLite
file**. This page explains how the pieces fit together.

## The big picture

```
            ┌─────────────────────────────────────────────┐
            │            System Wrangler (one Go binary)   │
  Browser ──┤  embedded React/PatternFly SPA  +  JSON API  │
            │                                              │
            │  background loops:                           │
            │   • reachability probe                       │
            │   • alert evaluator                          │
            │   • schedule ticker                          │
            │   • notification dispatcher                  │
            └───┬───────────────┬──────────────────┬───────┘
                │               │                  │
             SQLite         SSH / Ansible      Prometheus
          (all state)     (managed hosts)    (telemetry, read)
                                  │
                          ┌───────┴────────┐
                          │  your systems  │  (Linux / macOS / Windows / BSD)
                          └────────────────┘
```

- The **frontend** (React 19 + TypeScript + PatternFly v6, built with Vite) is
  compiled to static assets and **embedded into the Go binary** via `embed.FS`.
  There is no Node runtime in production; the same binary serves the SPA and the
  API.
- **State** lives in **SQLite** (STRICT tables; schema is built and migrated at
  startup). No external database.
- **Host actions** (update checks, applies, reboots, exporter installs,
  reachability probes) run over **SSH/Ansible**. The image bundles `ansible-core`
  and the SSH client.
- **Telemetry** is *read* from a **Prometheus** you provide. System Wrangler
  builds PromQL and proxies queries through; it does not store metrics itself.

## Request flow

1. The browser loads the embedded SPA from the Go server.
2. The SPA calls the JSON API under `/api/*`. Authentication is a **signed
   session cookie**; state-changing requests are CSRF-protected.
3. Read endpoints answer from SQLite (or proxy a metrics query to Prometheus).
4. Action endpoints enqueue or run work over SSH/Ansible and record the outcome
   (run history, audit log).
5. Live updates (status changes, new alerts) are pushed to the SPA over a
   server-sent events stream (`GET /api/events`) so pages refresh without
   polling.

## Background loops

Four loops run inside the single process, each on its own cadence (configurable
in **Settings**):

- **Reachability probe** — periodically dials each system's SSH port. A system
  flips to *unreachable* only after a configurable number of consecutive
  failures, and back to *reachable* after consecutive successes.
- **Alert evaluator** — on each tick, reconciles every enabled rule against
  current reachability and metrics. It implements Prometheus-style **"for"**
  semantics: a breaching condition is first *pending*, and only becomes *firing*
  once it has held for the rule's duration. Transitions are handed to the
  dispatcher.
- **Schedule ticker** — runs due schedules (check / apply / reboot) against
  their targets.
- **Notification dispatcher** — delivers fired/resolved transitions to channels
  per the routing and severity/quiet-hours policy, deferring non-paging alerts
  during quiet hours.

## Security model

- **Authentication:** local accounts (bcrypt + signed cookies), optional TOTP
  2FA, optional OIDC.
- **Authorization:** role-based — `admin` / `operator` / `auditor`, granted
  globally or per group. The API resolves a caller's effective scope on every
  request.
- **Secrets at rest:** SSH credentials and channel secrets are sealed with
  **AES-256-GCM** under the master key (`SW_MASTER_KEY_FILE`). The key never
  touches the database; rotation re-seals every row (see
  [Installation](installation.md#rotating-the-master-key)).
- **Audit:** significant actions are written to an append-only audit log.

## Data model highlights

- **Single-tenant** — there is no `tenant_id`; isolation is "run another
  container."
- Timestamps are stored as Unix nanoseconds (the audit log uses Unix
  milliseconds).
- Systems carry status, OS/virtualization facts, labels, group membership, and
  per-updater pending packages; groups, labels, schedules, alert rules,
  channels, exclusions, users, and roles each have their own tables.

## Code layout

```
cmd/server/      entrypoint — wires dependencies, starts the HTTP server
internal/        application packages (auth, systems, alerts, notifications,
                 metrics, secrets, …); not importable outside the module
web/dist/        embedded build of the frontend SPA
docs/            this documentation, plus the screenshot harness in fixtures/
```

See the [Development guide](development.md) to build and run it from source.
