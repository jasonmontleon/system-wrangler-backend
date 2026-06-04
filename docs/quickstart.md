<!-- SPDX-License-Identifier: Apache-2.0 -->

# Quick start

Get a System Wrangler instance running and sign in. This uses the container
image; for production options (TLS, OIDC, backups, key rotation) see the
[Installation guide](installation.md).

## Prerequisites

- A container runtime — `podman` or `docker`.
- *(Optional, for telemetry)* a Prometheus that scrapes your hosts' exporters.

## 1. Pull the image

```sh
podman pull quay.io/jasonmontleon/system-wrangler:latest
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
  quay.io/jasonmontleon/system-wrangler:latest
```

The `data` volume holds the SQLite database, so your state survives restarts and
upgrades.

## 4. Create the first administrator

Open <http://localhost:8080>. On first launch the app detects there are no
accounts and prompts you to **create the initial administrator**. Fill it in and
you're signed in.

## 5. (Optional) wire up telemetry

The telemetry pages need a Prometheus. The easiest way is the ready-made
compose stack in [`deploy/`](../deploy), which runs System Wrangler and
Prometheus together and wires up discovery for you — see
[Deploying with Prometheus](installation.md#deploying-with-prometheus).

If you already run a Prometheus, point the server at it instead and restart:

```sh
  -e SW_PROMETHEUS_URL=http://prometheus.internal:9090
```

Either way, install an exporter on a host from its **Monitoring** tab.

## Next steps

- Add your first systems and run an update check — see the
  [User guide](user-guide.md).
- Harden the deployment with TLS, OIDC, and backups — see the
  [Installation guide](installation.md).
