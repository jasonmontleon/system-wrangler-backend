<!-- SPDX-License-Identifier: Apache-2.0 -->

# Development guide

How to build, run, and contribute to System Wrangler. The project is two repos
that live side by side:

- `system-wrangler-backend` — the Go server (this repo). Embeds the built SPA.
- `system-wrangler-frontend` — the React/TypeScript/PatternFly SPA.

## Prerequisites

- **Go** (the version pinned in `go.mod`).
- **Node.js + npm** (for the frontend).
- **podman/docker** (for container builds and the screenshot harness).

## Running from source

The frontend dev server proxies `/api` to the backend, so run both:

```sh
# Terminal 1 — backend on :8080
cd system-wrangler-backend
head -c 32 /dev/urandom | base64 > /tmp/sw.key
SW_MASTER_KEY_FILE=/tmp/sw.key DB_PATH=/tmp/sw.db go run ./cmd/server

# Terminal 2 — frontend dev server (proxies /api -> :8080)
cd system-wrangler-frontend
npm install
npm run dev
```

Open the Vite URL it prints. To exercise the telemetry pages, also set
`SW_PROMETHEUS_URL` on the backend.

## Quality gates

Both repos must pass their gates before any commit.

**Backend:**

```sh
go build ./...
go vet ./...
go test ./... -race -cover
gofmt -l .            # must be empty
golangci-lint run     # includes gosec
govulncheck ./...
```

**Frontend:**

```sh
npm run build         # includes tsc -b — type errors fail here
npm run lint
npm test -- --run     # vitest
```

Target **90% line coverage** on any package/module you touch. Commits are signed
with DCO (`git commit -s`). Don't bypass gates or push without being asked.

## Building the container

The backend image build takes the frontend as a build context:

```sh
podman build -t system-wrangler \
  --build-context frontend=../system-wrangler-frontend \
  -f Containerfile .
```

It's a multi-stage build: stage one builds the SPA, stage two compiles the Go
binary with the SPA embedded, and the final image bundles the SSH/Ansible
runtime.

## Documentation & screenshots

User-facing docs live in [`docs/`](.). Screenshots are generated from a
deterministic demo dataset rather than hand-captured, so they stay consistent.
The harness is in [`docs/fixtures/`](fixtures):

- `seed.sql` — a deterministic demo dataset (systems, groups, users, alerts,
  schedules, …). It also seeds high probe/alert intervals so the runtime holds
  the demo data still during a capture session.
- `docs-serve.sh` — builds the server, initializes a scratch database, loads
  `seed.sql`, and serves it. `WITH_METRICS=1` also stands up telemetry.
- `gen_metrics.py` + `with-metrics.sh` — generate synthetic OpenMetrics for the
  demo systems, backfill them into a local Prometheus with `promtool`, and serve
  it, so the chart pages render real PromQL against realistic data.

```sh
# DB-backed pages:
bash docs/fixtures/docs-serve.sh
# also light up the telemetry/chart pages:
WITH_METRICS=1 bash docs/fixtures/docs-serve.sh
# then run the SPA dev server and drive the UI to capture screenshots.
```

Stop the metrics container afterward with `podman rm -f sw-docs-prom`.

## Code style

- **Standard library first** — new dependencies need justification.
- Wrap errors with context; never panic in HTTP handlers; structured logging via
  `log/slog`.
- Add tests for new behavior; prefer table-driven tests and real fakes
  (`t.TempDir()`, `httptest`, in-memory SQLite) over mocks.
- Frontend: TypeScript `strict`, PatternFly components only (no second component
  library), no `any` without a reason.

See [`CLAUDE.md`](../CLAUDE.md) in each repo for the full contributor rules.
