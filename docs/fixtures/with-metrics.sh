#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Phase 2 of the documentation harness: stand up a local Prometheus full of
# synthetic telemetry so the chart pages (Monitoring panels, dashboard
# trend/leaderboard/sparkline cards, per-system graphs) render with real data
# flowing through the real PromQL — nothing is faked at the query layer.
#
# Invoked by docs-serve.sh when WITH_METRICS=1, with the scratch DB as $1:
#   bash with-metrics.sh /tmp/sw-docs.db
# It generates an OpenMetrics dump from the seeded hosts, backfills it into a
# TSDB block with promtool, and runs prom/prometheus serving that block on
# :9090. docs-serve.sh then points the server's SW_PROMETHEUS_URL at it.
#
# Stop the metrics container when done:  podman rm -f sw-docs-prom
set -euo pipefail

DB="${1:?usage: with-metrics.sh <sqlite-db>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PROM_IMAGE="${PROM_IMAGE:-quay.io/prometheus/prometheus:latest}"
PROM_PORT="${PROM_PORT:-9090}"
CONTAINER="${CONTAINER:-sw-docs-prom}"
WORK="${WORK:-/tmp/sw-docs-metrics}"
OM="$WORK/metrics.om"
DATA="$WORK/data"

# The TSDB block + WAL get written by the rootless container as a mapped
# subuid, so a plain `rm -rf` from the host can't remove them; clear any
# prior run from inside the user namespace first.
podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
podman unshare rm -rf "$WORK" >/dev/null 2>&1 || true
mkdir -p "$DATA"
chmod -R 0777 "$WORK"

echo "==> generating synthetic OpenMetrics from $DB"
python3 "$SCRIPT_DIR/gen_metrics.py" "$DB" > "$OM"
chmod 0666 "$OM"
echo "    $(wc -l < "$OM") samples -> $OM"

echo "==> backfilling TSDB block with promtool"
podman run --rm --entrypoint promtool -v "$WORK":/work:Z "$PROM_IMAGE" \
  tsdb create-blocks-from openmetrics /work/metrics.om /work/data

cat > "$WORK/prometheus.yml" <<'YML'
global:
  scrape_interval: 1m
scrape_configs: []
YML
chmod 0666 "$WORK/prometheus.yml"

echo "==> starting Prometheus on :$PROM_PORT (container $CONTAINER)"
podman run -d --name "$CONTAINER" -p "$PROM_PORT":9090 \
  -v "$WORK/prometheus.yml":/etc/prometheus/prometheus.yml:Z \
  -v "$DATA":/prometheus:Z \
  "$PROM_IMAGE" \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/prometheus \
  --storage.tsdb.retention.time=60d >/dev/null

for _ in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:${PROM_PORT}/-/ready" >/dev/null 2>&1; then
    echo "==> Prometheus ready on http://127.0.0.1:${PROM_PORT}"
    exit 0
  fi
  sleep 1
done
echo "Prometheus did not become ready on :$PROM_PORT" >&2
exit 1
