#!/usr/bin/env bash
set -euo pipefail

# govulncheck gate with a TEMPORARY, self-expiring allowlist.
#
# Each ALLOW entry suppresses one OSV id. This is deliberately fragile: the
# build fails if an allowlisted id stops matching any finding (guard 2) or once
# the expiry date passes (guard 3), so a stale suppression can never linger.
#
# Accepted entries:
#   GO-2026-5662 (CVE-2026-40179 / GHSA-vffh-x6r8-xx99): stored XSS in the
#     Prometheus *web UI* (React/TS chart tooltips + metrics explorer). We
#     import only promql/parser and model/labels server-side and never compile
#     or serve the web UI, so the vulnerable code is not in our binary. The Go
#     vuln DB entry is also over-broad (introduced:0 with no fix on two of three
#     ranges), so no module bump can clear it. Retraction proposed upstream:
#     https://github.com/golang/vulndb/issues/5796
#     Remove this entry (and re-check) when that lands or Prometheus ships a
#     version the DB marks fixed.
ALLOW=(
  GO-2026-5662
)

# Time-box: after this date the allowlist is treated as expired (guard 3).
EXPIRY="2026-07-25"

json="$(govulncheck -format json ./...)"

# OSV ids whose vulnerable symbols are actually reachable from our code
# (function-level trace present == govulncheck's own "your code is affected").
mapfile -t affected < <(
  printf '%s' "$json" \
    | jq -r '.finding | select(. != null) | select(.trace[0].function != null) | .osv' \
    | sort -u
)

# id -> summary, for readable messages.
summary_for() {
  printf '%s' "$json" \
    | jq -r --arg id "$1" 'select(.osv.id == $id) | .osv.summary' \
    | head -n1
}

in_list() {
  local needle="$1"; shift
  local x
  for x in "$@"; do [[ "$x" == "$needle" ]] && return 0; done
  return 1
}

status=0

# Guard 1: any affected, non-allowlisted vulnerability fails the build.
for id in "${affected[@]}"; do
  [[ -z "$id" ]] && continue
  if in_list "$id" "${ALLOW[@]}"; then
    echo "ALLOWLISTED (accepted risk): $id — $(summary_for "$id")"
  else
    echo "::error::vulnerability affecting called code: $id — $(summary_for "$id")"
    echo "  details: https://pkg.go.dev/vuln/$id"
    status=1
  fi
done

# Guard 2: an allowlist entry that no longer matches anything is dead weight.
for a in "${ALLOW[@]}"; do
  if ! in_list "$a" "${affected[@]}"; then
    echo "::error::allowlist entry $a no longer matches any finding — it was retracted or upgraded away. Remove it from scripts/govulncheck.sh."
    status=1
  fi
done

# Guard 3: the allowlist is time-boxed. Past EXPIRY, force a human to re-check.
today="$(date -u +%Y%m%d)"
if (( 10#$today > 10#${EXPIRY//-/} )); then
  echo "::error::govulncheck allowlist expired on $EXPIRY — re-evaluate every entry in scripts/govulncheck.sh and remove or renew."
  status=1
fi

if (( status == 0 )); then
  echo "govulncheck: passing; ${#ALLOW[@]} allowlisted finding(s), allowlist valid through $EXPIRY."
fi

exit "$status"
