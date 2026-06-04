<!-- SPDX-License-Identifier: Apache-2.0 -->

# API reference

System Wrangler exposes a JSON HTTP API under `/api`. The web UI is built
entirely on this API, so anything the UI can do is scriptable.

## The source of truth: OpenAPI

A machine-readable OpenAPI specification is served by every running instance:

- **`GET /api/openapi.yaml`** — the full spec.
- **`GET /api/docs`** — browsable API documentation.

Treat those as authoritative — they always match the running version. This page
is an orientation to the conventions and the resource groups.

## Conventions

- **Format:** requests and responses are JSON (`Content-Type: application/json`).
- **Authentication:** a **signed session cookie**, obtained from
  `POST /api/auth/login` (or the OIDC flow). Send it with each request.
- **CSRF:** state-changing requests (`POST`/`PUT`/`PATCH`/`DELETE`) require the
  CSRF token the app issues; the login and first-time setup POSTs are exempt.
- **Authorization:** endpoints are gated by role (`admin` / `operator` /
  `auditor`) and scope (global or per group). `GET /api/me/scope` reports the
  caller's effective scope.
- **Errors:** non-2xx responses carry a JSON error body.
- **Live updates:** `GET /api/events` is a server-sent events stream of changes.

## Resource groups

### Auth & session
`/api/auth/status`, `/api/auth/setup` (first-run admin), `/api/auth/login`,
`/api/auth/logout`, `/api/auth/profile`, `/api/auth/password`, sessions
(`/api/auth/sessions…`), TOTP 2FA (`/api/auth/totp…`), and OIDC
(`/api/auth/oidc/login`, `/api/auth/oidc/callback`).

### Systems
`/api/systems` (list/create), `/api/systems/{id}` (get/delete), plus per-system
sub-resources: labels, group, platform, host-keys (scan/accept), connection
(`test-connection`, `inspect`), updaters (`check` / `apply` / enable),
`updater-runs`, exporters (install/remove/status/scrape), `exporter-runs`,
ansible credentials, and package exclusions (incl. `…/effective`).
Bulk actions via `/api/systems/bulk-event`.

### Groups
`/api/groups` and `/api/groups/{id}` with per-group role assignments, ansible
credentials, and package exclusions.

### Monitoring & alerts
Metrics proxy: `/api/metrics/query`, `/api/metrics/query_range`. Alerts:
`/api/alerts` (rules), `/api/alerts/{id}`, `/api/alerts/active`,
`/api/alerts/catalog` (the curated metric list).

### Notifications
Shared channels (`/api/notifications/channels…`, with `…/test`), routing
(`/api/notifications/routing…`), the delivery `policy`, and `deliveries`. Each
user's personal config lives under `/api/notifications/me/…` (channels,
subscription, policy, deliveries).

### Schedules
`/api/schedules`, `/api/schedules/{id}`, `/api/schedules/{id}/runs`, and
`/api/schedules/{id}/run-now`.

### Administration
Users (`/api/admin/users…`, password and TOTP reset), role assignments,
settings (`/api/admin/settings`, `…/{key}`), updater and exporter definitions,
package exclusions, ansible credentials, the audit log (`/api/admin/audit…`),
secret health (`/api/admin/secrets/undecryptable`), and backup
(`/api/admin/backup`).

### Misc / meta
`/api/health`, `/api/ready`, `/api/build-info`, `/api/labels`,
`/api/label-styles`, `/api/dashboard/layout`.

> For exact request/response shapes, parameters, and status codes, use
> `/api/openapi.yaml` from your running instance.
