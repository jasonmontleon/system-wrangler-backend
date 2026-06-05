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
            │   • Prometheus targets writer                │
            └───┬───────────────┬──────────────────┬───────┘
                │               │                  ↕
             SQLite         SSH / Ansible      Prometheus
          (all state)     (managed hosts)     (telemetry)
                                  │                 ┆ scrapes back
                          ┌───────┴────────┐        ┆ *through* the
                          │  your systems  │◀┄┄┄┄┄┄┄┘ SSH proxy
                          │  + exporters   │  (Linux / macOS / Windows / BSD)
                          └────────────────┘
```

The Prometheus arrow is **two-way**: System Wrangler *reads* telemetry by
proxying PromQL queries to Prometheus, and — in the bundled metrics stack —
Prometheus *scrapes back through* System Wrangler over the same SSH path (see
[How Prometheus reaches your hosts](#how-prometheus-reaches-your-hosts)).

- The **frontend** (React 19 + TypeScript + PatternFly v6, built with Vite) is
  compiled to static assets and **embedded into the Go binary** via `embed.FS`.
  There is no Node runtime in production; the same binary serves the SPA and the
  API.
- **State** lives in **SQLite** (STRICT tables; schema is built and migrated at
  startup). No external database.
- **Host actions** (update checks, applies, reboots, exporter installs,
  reachability probes) run over **SSH/Ansible**. The image bundles `ansible-core`
  and the SSH client.
- **Telemetry** is *read* from a **Prometheus**. System Wrangler builds PromQL
  and proxies queries through; it does not store metrics itself. The bundled
  `deploy/` stack also lets System Wrangler **feed Prometheus its scrape
  targets** and act as the scrape proxy — see
  [How Prometheus reaches your hosts](#how-prometheus-reaches-your-hosts).

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

Five loops run inside the single process, each on its own cadence or trigger.
Their interval/threshold knobs live in **Settings**. Every loop also tags its
JSON log lines with a `component` field and has an **independently adjustable
log level** (Settings → *Background Loop Logging*), so on a busy install you can
quieten a chatty loop or turn one up to debug while diagnosing — applied live,
no restart required. The `component` value (shown below in parentheses) is what
you filter on, e.g. `jq 'select(.component=="probe")'`.

- **Reachability probe** (`probe`) — periodically dials each system's SSH port.
  A system flips to *unreachable* only after a configurable number of
  consecutive failures, and back to *reachable* after consecutive successes.
- **Alert evaluator** (`alert`) — on each tick, reconciles every enabled rule
  against current reachability and metrics. It implements Prometheus-style
  **"for"** semantics: a breaching condition is first *pending*, and only
  becomes *firing* once it has held for the rule's duration. Transitions are
  handed to the dispatcher.
- **Schedule ticker** (`schedule`) — runs due schedules (check / apply / reboot)
  against their targets.
- **Notification dispatcher** (`notification`) — delivers fired/resolved
  transitions to channels per the routing and severity/quiet-hours policy,
  deferring non-paging alerts during quiet hours.
- **Prometheus targets writer** (`promtargets`) — when the metrics stack is
  wired (`SW_TARGETS_FILE` is set), regenerates the Prometheus file-discovery
  targets on every inventory change, so a newly added system or exporter is
  scraped within seconds. It is event-driven (debounced), not timed, and stays
  idle on the "bring your own Prometheus" layout.

Two request-path subsystems share the same `component` tag + adjustable level,
even though they aren't loops:

- **Scrape proxy** (`scrape`) — serves Prometheus's scrapes through the SSH
  tunnel (see below). It logs a warning each time an exporter is unreachable;
  on a large install with a few down hosts this is the **noisiest** line of
  all, so being able to filter it by `component=scrape` or turn it down to
  Error is the most impactful knob here.
- **HTTP access log** (`request`) — one line per HTTP request. Normal API/UI
  requests log at Info; the high-volume internal scrape endpoint
  (`/internal/scrape/...`) logs at **Debug** and is hidden by the Info default.
  Set the `request` level to Debug to also record scrape requests, or to Warn to
  silence the access log entirely.

## How Prometheus reaches your hosts

There are two ways to wire telemetry, and they differ in *who scrapes your
exporters*:

1. **Bring your own Prometheus.** Point System Wrangler at an existing
   Prometheus with `SW_PROMETHEUS_URL`. System Wrangler only ever **reads** from
   it (proxying PromQL for the charts and metric alerts); you are responsible for
   scraping your hosts however you already do.

2. **The bundled `deploy/` stack** (recommended). Here System Wrangler also
   *provides* the targets, and the scrape takes an unusual path worth
   understanding:

   - Exporters do **not** need to be exposed on the network — they can stay bound
     to `localhost` on each host. Prometheus never connects to your hosts
     directly.
   - The **targets writer** loop emits a file-discovery list in which every
     target points *back at System Wrangler*, at
     `/internal/scrape/{system}/{exporter}`, authenticated with a shared bearer
     secret (`SW_INTERNAL_SECRET_FILE`).
   - When Prometheus scrapes one of those targets, System Wrangler **proxies the
     request over its existing SSH connection** to that host and streams the
     exporter's metrics back. So the only thing that ever talks to your hosts is
     System Wrangler, over SSH — the same path used for update checks and
     applies.

   This is why metrics work without opening any exporter ports: the SSH proxy
   reuses the connectivity System Wrangler already needs. The full stack (shared
   network namespace, the two secret files, retention) is documented in
   [Deploying with Prometheus](installation.md#deploying-with-prometheus).

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
