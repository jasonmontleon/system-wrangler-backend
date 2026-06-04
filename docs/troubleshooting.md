<!-- SPDX-License-Identifier: Apache-2.0 -->

# Troubleshooting

Common problems and how to resolve them. See also the server logs (structured
JSON on stdout) and `GET /api/health` / `GET /api/ready`.

## The server won't start: master key errors

System Wrangler refuses to start without a readable master key.

- `SW_MASTER_KEY_FILE` must point to a file containing the **base64 of exactly
  32 bytes** (a trailing newline from `... | base64 > key` is fine).
- In a container, make sure the key file is mounted and the path matches the env
  var.
- If you're restoring a database, you must supply the **same** key that sealed
  its secrets — a mismatch is detected and rejected on purpose. If you've lost
  the original key, the sealed secrets (SSH credentials, channel secrets) are
  unrecoverable and must be re-entered.

## I'm locked out / forgot the admin password

- Another admin can reset a user's password from **Administration → Users**.
- If no admin can sign in, an operator with database access can intervene
  directly, or you can start fresh against a new database (you'll re-run
  first-time setup). Keep at least two admin accounts to avoid this.

## The Monitoring pages are empty

The telemetry pages need a Prometheus and per-host exporters:

1. **Is `SW_PROMETHEUS_URL` set** to a reachable Prometheus? (Default is
   `http://127.0.0.1:9090`.)
2. **Is an exporter installed** on the system? Install it from the system's
   **Monitoring** tab.
3. **Is Prometheus actually scraping it?** The **System graphs** page lists only
   systems Prometheus reports as up — specifically those with an
   `up{job="system-wrangler-exporters"}` series. If a system is missing from the
   list, check the scrape config and that the exporter is running.
4. The cross-system **Systems overview** reads metrics by `system_id` label;
   confirm your scrape attaches the right `system_id`.

Some metrics are platform-specific (e.g. load average on Linux/BSD only), so a
blank panel for one metric on one OS can be expected rather than a fault.

## A system is stuck "Unreachable"

Reachability is an SSH-port probe. Check, in order:

- The hostname resolves and the SSH port is reachable from the container.
- Host keys are accepted — use **scan** then **accept** on the system's
  **Connection** tab, or via the host-keys endpoints.
- Credentials are correct (system, group, or global ansible credential).
- Remember a system only flips back to *reachable* after a configurable number
  of **consecutive** successful probes — give it a cycle or two, or lower the
  thresholds in **Settings**.

## Update checks find nothing / the wrong packages

- Confirm the right **updater** is detected on the host (**System detail →
  Updaters**); the binary it looks for must be installed and on `PATH`.
- Check your **package exclusions** — global, group, and system patterns union
  together, so a broad global pattern (e.g. `*`) can hide everything. The
  system's **effective** exclusions show the combined set.

## Alerts aren't firing (or aren't being delivered)

- **Metric alerts** evaluate against Prometheus — if telemetry is down, those
  rules are skipped (reachability rules still work).
- A rule with a **for** duration stays *pending* until the condition has held
  long enough; that's expected, not a failure.
- For delivery, check the rule's **routing** (which channels), the channel's
  **enabled** toggle, and the **delivery policy** — info-severity defaults to
  dashboard-only, and quiet hours defer non-paging alerts. The **deliveries**
  view shows attempts and failures.

## Notifications fail with DNS/connection errors

That's the channel's destination being unreachable from the container (wrong
URL, SMTP host, or network egress). Use the channel's **Test** action to
validate it, and check the **deliveries** log for the exact error.

## Telemetry charts go blank after a while in a demo/test setup

If you're using the screenshot harness, the synthetic data extends a couple of
hours past "now"; a session running longer than that can outrun the data.
Regenerate with `WITH_METRICS=1 bash docs/fixtures/docs-serve.sh`. (Production
data from a live Prometheus doesn't have this limit.)

---

Still stuck? Capture the server logs around the failure and the output of
`GET /api/health` and `GET /api/build-info` when reporting an issue.
