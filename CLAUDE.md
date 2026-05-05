# Cat Wrangler — Backend

Go backend for Cat Wrangler, a web-based fleet management dashboard providing
system telemetry and cross-platform package/update management across Linux,
macOS, and Windows. The frontend lives in a sibling repo
(`cat-wrangler-frontend`) and is embedded into this Go binary at build time
via `web/embed.FS`.

Module path is `cat-wrangler-backend` (placeholder). If/when the project moves
to a hosted git remote, update `go.mod` and the import in `cmd/server/main.go`
together.

## License (AGPL-3.0-or-later)

- Every new source file MUST begin with this header, on its own line, followed
  by a blank line:
  ```go
  // SPDX-License-Identifier: AGPL-3.0-or-later
  ```
- Do not add dependencies under licenses incompatible with AGPL (proprietary,
  or GPL-only-without-or-later).
- The running UI surfaces a "Source" link for AGPL §13 compliance. Don't remove
  the equivalent in the frontend without first verifying replacement.

## First-time setup

```sh
git config core.hooksPath .githooks    # enables pre-commit + commit-msg hooks
```

The `.claude/settings.json` PostToolUse hook auto-adds the SPDX header to new
source files written by Claude Code; no setup required.

## Commits

- **Sign every commit with DCO**: `git commit -s`. No exceptions.
- Don't commit if any quality gate below fails. Fix the root cause; never bypass
  with `--no-verify`, `-skip`, or by deleting failing tests.
- Don't commit secrets, `.env`, generated `dist/`, or compiled binaries.
- Don't push to remotes unless explicitly asked.

## Quality gates (must pass before any commit)

```sh
go build ./...
go vet ./...
go test ./... -race -cover
gofmt -l . | tee /dev/stderr | (! read)
golangci-lint run    # once configured
```

## Tests & coverage

- Add tests for every new function or behavior change — no exceptions for
  "trivial" code. A test pins the contract.
- Target **90% line coverage minimum** for any package you touch:
  ```sh
  go test ./... -coverprofile=cover.out
  go tool cover -func=cover.out | tail -1
  ```
- Prefer table-driven tests. Use stdlib `testing`; avoid third-party assertion
  libraries.
- Code that shells out (Ansible, SSH, exec) must accept an injected executor
  interface so tests use a fake instead of patching `exec.Command`.
- Don't mock things you can use real: `t.TempDir()`, `httptest.Server`,
  in-memory SQLite, etc.

## Code style

- **Standard library first.** New dependencies need justification in the commit
  message. We currently have zero — keep it that way unless there's a concrete
  problem stdlib can't solve.
- Errors: wrap with `fmt.Errorf("doing X: %w", err)`. Never panic in HTTP
  handlers.
- Logging: `log/slog` with structured kv pairs. No `fmt.Println` / `log.Printf`
  outside throwaway debugging.
- Comments: only when WHY is non-obvious. Don't restate what the code does.

## Project layout

- `cmd/server/` — entrypoint. Keep slim: wire dependencies, start HTTP server.
- `internal/` — application packages (auth, inventory, ansible, metrics will
  land here). `internal/` prevents external import of these packages.
- `web/` — `embed.FS` of the built frontend. **Do not move, rename, or empty
  `web/dist/`** — `Containerfile` and the `//go:embed all:dist` directive both
  depend on this path. Keep `.gitkeep` so the directory exists for `go build`
  outside the container.
- `Containerfile` — multi-stage build. Frontend supplied via
  `--build-context frontend=...`.

## Don't, without discussion

- Add a web framework (gin/echo/chi) unless stdlib hits a concrete limit.
- Add a database driver speculatively. Pick one when we add persistence.
- Remove the `all:` prefix from the embed directive (it's there so dotfiles in
  Vite output and `.gitkeep` are both included).
