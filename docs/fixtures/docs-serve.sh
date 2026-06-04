#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Bring up a System Wrangler instance loaded with the deterministic demo
# dataset (docs/fixtures/seed.sql) for documentation screenshots. No backend
# code changes: the seeded settings hold the reachability probe + alert
# evaluator still (see the docs-screenshots plan).
#
#   bash docs/fixtures/docs-serve.sh              # set up + run the server (:8089)
#   SETUP_ONLY=1 bash docs/fixtures/docs-serve.sh # just (re)build the scratch DB and exit
#   WITH_METRICS=1 bash docs/fixtures/docs-serve.sh  # also backfill + run Prometheus (phase 2)
#
# Then run the SPA dev server (it proxies /api -> the backend):
#   npm --prefix ../system-wrangler-frontend run dev
# and open the Vite URL. Log in as:  docs / docsdemo1
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"

PORT="${PORT:-8089}"
DB="${DB:-/tmp/sw-docs.db}"
KEY="${KEY:-/tmp/sw-docs.key}"
BIN="${BIN:-/tmp/sw-docs-server}"
HEALTH="http://127.0.0.1:${PORT}/api/health"

echo "==> building server"
( cd "$REPO" && go build -o "$BIN" ./cmd/server )

# Fixed docs master key (32 zero bytes, base64) so any sealed secrets in the
# seed open. Demo only — never use a zero key anywhere real.
head -c 32 /dev/zero | base64 > "$KEY"

echo "==> initialising schema on a fresh $DB"
rm -f "$DB" "$DB-wal" "$DB-shm"
# Boot the server just long enough to create the schema, then stop it. The
# stores build all tables during startup (before serving), so a short bounded
# run is enough; `timeout` avoids backgrounding a job.
SW_MASTER_KEY_FILE="$KEY" PORT="$PORT" DB_PATH="$DB" timeout 8 "$BIN" >/tmp/sw-docs-init.log 2>&1 || true
if [ ! -f "$DB" ]; then echo "schema init failed; see /tmp/sw-docs-init.log" >&2; exit 1; fi

echo "==> loading seed.sql"
sqlite3 "$DB" < "$SCRIPT_DIR/seed.sql"

PROM_ARGS=()
if [ "${WITH_METRICS:-0}" = "1" ]; then
  echo "==> generating + backfilling synthetic metrics (phase 2)"
  bash "$SCRIPT_DIR/with-metrics.sh" "$DB"
  PROM_ARGS=(SW_PROMETHEUS_URL=http://127.0.0.1:9090)
fi

if [ "${SETUP_ONLY:-0}" = "1" ]; then
  echo "==> SETUP_ONLY: scratch DB ready at $DB"
  exit 0
fi

echo "==> serving on :$PORT  (login: docs / docsdemo1)"
echo "    SPA: npm --prefix $REPO/../system-wrangler-frontend run dev"
exec env SW_MASTER_KEY_FILE="$KEY" PORT="$PORT" DB_PATH="$DB" "${PROM_ARGS[@]}" "$BIN"
