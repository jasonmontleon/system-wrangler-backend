<!-- SPDX-License-Identifier: Apache-2.0 -->

# Quick start

Get a System Wrangler instance running and sign in. This uses the container
image; for production options (TLS, OIDC, backups, key rotation) see the
[Installation guide](installation.md).

## Prerequisites

- A container runtime — `podman` or `docker`.
- The two source repos checked out side by side (`system-wrangler-backend` and
  `system-wrangler-frontend`), since the frontend is supplied to the build.
- *(Optional, for telemetry)* a Prometheus that scrapes your hosts' exporters.

## 1. Build the image

From the backend repo, with the frontend supplied as a build context:

```sh
podman build -t system-wrangler \
  --build-context frontend=../system-wrangler-frontend \
  -f Containerfile .
```

## 2. Create a master key

System Wrangler seals secrets (SSH credentials, channel secrets) at rest with
AES-256-GCM. It needs a 32-byte key, base64-encoded, in a file:

```sh
head -c 32 /dev/urandom | base64 > master.key
```

Keep this file safe and backed up — without it, sealed secrets can't be read.

## 3. Run it

```sh
podman run -d --name system-wrangler \
  -p 8080:8080 \
  -v "$PWD/data":/var/lib/system-wrangler \
  -v "$PWD/master.key":/etc/system-wrangler/master.key:ro \
  -e SW_MASTER_KEY_FILE=/etc/system-wrangler/master.key \
  system-wrangler
```

The `data` volume holds the SQLite database, so your state survives restarts and
upgrades.

## 4. Create the first administrator

Open <http://localhost:8080>. On first launch the app detects there are no
accounts and prompts you to **create the initial administrator**. Fill it in and
you're signed in.

## 5. (Optional) wire up telemetry

To populate the Monitoring graphs and the cross-system overview, point the
server at your Prometheus and restart:

```sh
  -e SW_PROMETHEUS_URL=http://prometheus.internal:9090
```

Then install an exporter on a host from its **Monitoring** tab.

## Next steps

- Add your first systems and run an update check — see the
  [User guide](user-guide.md).
- Harden the deployment with TLS, OIDC, and backups — see the
  [Installation guide](installation.md).
