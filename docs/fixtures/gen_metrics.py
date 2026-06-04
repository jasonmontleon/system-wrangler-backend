#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Generate a synthetic OpenMetrics dump for the documentation harness.
#
#   python3 gen_metrics.py /tmp/sw-docs.db > /tmp/metrics.om
#
# It reads the *reachable* hosts straight out of the seeded SQLite (so the
# system_id labels line up with seed.sql by construction — no separate
# manifest to drift), classifies each by OS into the node_exporter (Linux),
# node_exporter-BSD, or windows_exporter metric namespace, and emits the
# series the SPA's PromQL (src/api/promql.ts) and the alert catalog
# (internal/alerts/catalog.go) actually consume.
#
# Design notes:
#   * Time axis ends a couple of hours PAST wall-clock now and runs back 14
#     days, at a fine step. The SPA's rate() windows are as short as 5m, so
#     a trailing window must always hold >=2 samples; the future buffer keeps
#     that true as the session's "now" edge advances during a capture run.
#   * Values are deterministic given the host id (seeded per-series RNG), so
#     regeneration is shape-stable. Per-host baselines put one host in each
#     attention band so leaderboards rank and the seeded alert rules breach:
#     web-01 mem ~88% + CPU ~92%, db-01 worst-mount ~93%.
#   * Output is grouped by metric family (one `# TYPE` per family, all its
#     samples contiguous) and terminated with `# EOF`, as the OpenMetrics
#     parser in `promtool tsdb create-blocks-from openmetrics` requires.
#
# Dev-only; never shipped in the binary.

import hashlib
import math
import sqlite3
import sys
import time

GiB = 1024 ** 3
STEP = 120                       # 2 min — keeps >=2 samples inside any 5m rate window
SPAN = 14 * 86400                # 14 days of history (the widest chart range)
FUTURE = 2 * 3600               # head room so the trailing window survives a session


def rng_for(*parts):
    """A deterministic PRNG seeded from the joined parts (no global state)."""
    h = hashlib.sha256("|".join(str(p) for p in parts).encode()).digest()
    seed = int.from_bytes(h[:8], "big")
    # Tiny LCG — enough jitter for charts, fully reproducible, stdlib-free of
    # the `random` module's global-seed footguns when many series interleave.
    state = [seed or 1]

    def nxt():
        state[0] = (state[0] * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        return (state[0] >> 11) / float(1 << 53)

    return nxt


def wave(base, amp, period, phase, t, t0, noise_rng, noise=0.0):
    """A gentle sinusoid around `base` plus bounded per-sample noise."""
    v = base + amp * math.sin(2 * math.pi * (t - t0) / period + phase)
    if noise:
        v += (noise_rng() * 2 - 1) * noise
    return v


def clamppct(v):
    return max(1.0, min(99.0, v))


# Per-host baselines for the hosts the docs deliberately spotlight. Anything
# not listed gets a stable mid-range baseline derived from its id hash.
# Keys: cpu (busy %), mem (used %), disk (worst-mount %), net (bytes/s),
# dsk (disk bytes/s), tcp (established conns), up (uptime days), mem_total.
SPOTLIGHT = {
    "sys-web-01":  dict(cpu=92, mem=90, disk=55, net=4.6e7, dsk=3.0e7, tcp=2200, up=23, mem_total=16 * GiB),
    "sys-web-02":  dict(cpu=48, mem=62, disk=50, net=2.9e7, dsk=1.4e7, tcp=1400, up=23, mem_total=16 * GiB),
    "sys-web-03":  dict(cpu=31, mem=55, disk=60, net=1.6e7, dsk=9.0e6, tcp=900,  up=9,  mem_total=8 * GiB),
    "sys-cache-01": dict(cpu=25, mem=72, disk=40, net=3.4e7, dsk=6.0e6, tcp=1800, up=40, mem_total=8 * GiB),
    "sys-db-01":   dict(cpu=45, mem=70, disk=94, net=2.1e7, dsk=4.2e7, tcp=1200, up=61, mem_total=32 * GiB),
    "sys-db-02":   dict(cpu=35, mem=66, disk=78, net=1.8e7, dsk=3.6e7, tcp=1000, up=61, mem_total=32 * GiB),
    "sys-bsd-01":  dict(cpu=20, mem=58, disk=45, net=9.0e6, dsk=1.1e7, tcp=400,  up=130, mem_total=16 * GiB),
    "sys-mac-01":  dict(cpu=15, mem=50, disk=35, net=6.0e6, dsk=8.0e6, tcp=250,  up=12, mem_total=32 * GiB),
    "sys-win-01":  dict(cpu=40, mem=75, disk=68, net=1.5e7, dsk=2.0e7, tcp=800,  up=14, mem_total=32 * GiB),
    "sys-edge-fra-01": dict(cpu=12, mem=45, disk=30, net=4.0e6, dsk=2.0e6, tcp=120, up=180, mem_total=2 * GiB),
    "sys-edge-nyc-01": dict(cpu=18, mem=48, disk=33, net=5.0e6, dsk=2.5e6, tcp=160, up=160, mem_total=2 * GiB),
}


def baseline(host_id):
    if host_id in SPOTLIGHT:
        return SPOTLIGHT[host_id]
    r = rng_for(host_id, "baseline")
    return dict(
        cpu=20 + r() * 40, mem=40 + r() * 35, disk=30 + r() * 40,
        net=5e6 + r() * 3e7, dsk=5e6 + r() * 3e7, tcp=200 + r() * 1500,
        up=5 + r() * 120, mem_total=8 * GiB,
    )


def host_class(os_family, is_windows):
    if is_windows:
        return "windows"
    if os_family in ("FreeBSD", "OpenBSD"):
        return "bsd"
    return "linux"  # Linux + Darwin share the node_* namespace


def load_hosts(db_path):
    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            "SELECT id, os_family, is_windows FROM hosts "
            "WHERE status = 'reachable' ORDER BY id"
        ).fetchall()
    finally:
        con.close()
    return [(hid, host_class(fam or "", bool(win))) for hid, fam, win in rows]


# --------------------------------------------------------------------------
# Series model
#
# A "series" is (family, type, labels, sample_fn). For gauges sample_fn(t)
# returns the value at t. For counters sample_fn(t) returns the instantaneous
# RATE (units/sec) at t, which the emitter integrates into a monotonic total.
# --------------------------------------------------------------------------

class Series:
    __slots__ = ("family", "mtype", "labels", "fn", "_total")

    def __init__(self, family, mtype, labels, fn):
        self.family = family
        self.mtype = mtype
        self.labels = labels
        self.fn = fn
        self._total = None

    def label_str(self):
        inner = ",".join(f'{k}="{v}"' for k, v in self.labels.items())
        return "{" + inner + "}"


def build_series(host_id, klass, t0):
    """All series for one host. t0 anchors the sinusoid phases per host."""
    b = baseline(host_id)
    out = []
    L = lambda **extra: dict({"system_id": host_id}, **extra)  # noqa: E731

    # ---- CPU (counter; modes sum to ~1.0/s per core) --------------------
    cpu_fam = "windows_cpu_time_total" if klass == "windows" else "node_cpu_seconds_total"
    core_key = "core" if klass == "windows" else "cpu"
    priv_mode = "privileged" if klass == "windows" else "system"
    cpu_rng = rng_for(host_id, "cpu")
    cpu_phase = cpu_rng() * 2 * math.pi

    def busy_frac(t):
        return clamppct(wave(b["cpu"], b["cpu"] * 0.10, 5400, cpu_phase, t, t0, cpu_rng, noise=2.0)) / 100.0

    out.append(Series(cpu_fam, "counter", L(**{core_key: "0", "mode": "idle"}),
                       lambda t: 1.0 - busy_frac(t)))
    out.append(Series(cpu_fam, "counter", L(**{core_key: "0", "mode": "user"}),
                       lambda t: busy_frac(t) * 0.6))
    out.append(Series(cpu_fam, "counter", L(**{core_key: "0", "mode": priv_mode}),
                       lambda t: busy_frac(t) * 0.3))
    if klass != "windows":
        out.append(Series(cpu_fam, "counter", L(cpu="0", mode="iowait"),
                          lambda t: busy_frac(t) * 0.1))

    # ---- Memory ---------------------------------------------------------
    mem_rng = rng_for(host_id, "mem")
    mem_phase = mem_rng() * 2 * math.pi
    total = b["mem_total"]

    def mem_used_frac(t):
        return clamppct(wave(b["mem"], b["mem"] * 0.04, 7200, mem_phase, t, t0, mem_rng, noise=1.0)) / 100.0

    if klass == "windows":
        out.append(Series("windows_memory_physical_total_bytes", "gauge", L(), lambda t: total))
        out.append(Series("windows_memory_available_bytes", "gauge", L(),
                          lambda t: total * (1 - mem_used_frac(t))))
    elif klass == "bsd":
        out.append(Series("node_memory_active_bytes", "gauge", L(),
                          lambda t: total * mem_used_frac(t) * 0.7))
        out.append(Series("node_memory_wired_bytes", "gauge", L(),
                          lambda t: total * mem_used_frac(t) * 0.3))
        out.append(Series("node_memory_inactive_bytes", "gauge", L(),
                          lambda t: total * (1 - mem_used_frac(t)) * 0.4))
        out.append(Series("node_memory_free_bytes", "gauge", L(),
                          lambda t: total * (1 - mem_used_frac(t)) * 0.6))
    else:
        out.append(Series("node_memory_MemTotal_bytes", "gauge", L(), lambda t: total))
        out.append(Series("node_memory_MemAvailable_bytes", "gauge", L(),
                          lambda t: total * (1 - mem_used_frac(t))))
        swap_total = 4 * GiB
        swap_rng = rng_for(host_id, "swap")
        swap_phase = swap_rng() * 2 * math.pi
        out.append(Series("node_memory_SwapTotal_bytes", "gauge", L(), lambda t: swap_total))
        out.append(Series("node_memory_SwapFree_bytes", "gauge", L(),
                          lambda t: swap_total * (1 - clamppct(wave(15, 6, 9000, swap_phase, t, t0, swap_rng, 2)) / 100.0)))

    # ---- Filesystems (2 mounts; worst = baseline disk%) -----------------
    disk_rng = rng_for(host_id, "disk")
    disk_phase = disk_rng() * 2 * math.pi

    def mount_used_frac(t, offset):
        return clamppct(wave(b["disk"] - offset, 1.5, 21600, disk_phase, t, t0, disk_rng, noise=0.5)) / 100.0

    if klass == "windows":
        for vol, sz, off in (("C:", 256 * GiB, 0), ("D:", 1024 * GiB, 35)):
            out.append(Series("windows_logical_disk_size_bytes", "gauge", L(volume=vol), lambda t, s=sz: s))
            out.append(Series("windows_logical_disk_free_bytes", "gauge", L(volume=vol),
                              lambda t, s=sz, o=off: s * (1 - mount_used_frac(t, o))))
    else:
        fstype = "zfs" if klass == "bsd" else ("apfs" if host_id == "sys-mac-01" else "ext4")
        for mnt, dev, sz, off in (("/", "sda1", 100 * GiB, 0), ("/var", "sda2", 200 * GiB, 28)):
            lab = L(mountpoint=mnt, device="/dev/" + dev, fstype=fstype)
            out.append(Series("node_filesystem_size_bytes", "gauge", dict(lab), lambda t, s=sz: s))
            out.append(Series("node_filesystem_avail_bytes", "gauge", dict(lab),
                              lambda t, s=sz, o=off: s * (1 - mount_used_frac(t, o))))

    # ---- Network (counter, bytes/s) -------------------------------------
    net_rng = rng_for(host_id, "net")
    net_phase = net_rng() * 2 * math.pi

    def net_rate(t, frac):
        return max(0.0, wave(b["net"] * frac, b["net"] * frac * 0.4, 3600, net_phase, t, t0, net_rng, b["net"] * 0.05))

    if klass == "windows":
        nic = "Ethernet0"
        out.append(Series("windows_net_bytes_received_total", "counter", L(nic=nic), lambda t: net_rate(t, 0.6)))
        out.append(Series("windows_net_bytes_sent_total", "counter", L(nic=nic), lambda t: net_rate(t, 0.4)))
    else:
        dev = "eth0"
        out.append(Series("node_network_receive_bytes_total", "counter", L(device=dev), lambda t: net_rate(t, 0.6)))
        out.append(Series("node_network_transmit_bytes_total", "counter", L(device=dev), lambda t: net_rate(t, 0.4)))

    # ---- Disk I/O (counter) ---------------------------------------------
    io_rng = rng_for(host_id, "diskio")
    io_phase = io_rng() * 2 * math.pi

    def io_rate(t, frac):
        return max(0.0, wave(b["dsk"] * frac, b["dsk"] * frac * 0.5, 4500, io_phase, t, t0, io_rng, b["dsk"] * 0.05))

    if klass == "windows":
        for vol in ("C:", "D:"):
            out.append(Series("windows_logical_disk_read_bytes_total", "counter", L(volume=vol), lambda t: io_rate(t, 0.4)))
            out.append(Series("windows_logical_disk_write_bytes_total", "counter", L(volume=vol), lambda t: io_rate(t, 0.6)))
            out.append(Series("windows_logical_disk_reads_total", "counter", L(volume=vol), lambda t: io_rate(t, 0.4) / 8192))
            out.append(Series("windows_logical_disk_writes_total", "counter", L(volume=vol), lambda t: io_rate(t, 0.6) / 8192))
    else:
        dev = "sda"
        out.append(Series("node_disk_read_bytes_total", "counter", L(device=dev), lambda t: io_rate(t, 0.4)))
        out.append(Series("node_disk_written_bytes_total", "counter", L(device=dev), lambda t: io_rate(t, 0.6)))
        out.append(Series("node_disk_reads_completed_total", "counter", L(device=dev), lambda t: io_rate(t, 0.4) / 8192))
        out.append(Series("node_disk_writes_completed_total", "counter", L(device=dev), lambda t: io_rate(t, 0.6) / 8192))

    # ---- Scalars --------------------------------------------------------
    boot = t0 - int(b["up"] * 86400)
    tcp_rng = rng_for(host_id, "tcp")
    tcp_phase = tcp_rng() * 2 * math.pi
    if klass == "windows":
        out.append(Series("windows_system_boot_time_timestamp", "gauge", L(), lambda t: boot))
        out.append(Series("windows_tcp_connections_established", "gauge", L(family="ipv4"),
                          lambda t: max(1, round(wave(b["tcp"], b["tcp"] * 0.3, 3600, tcp_phase, t, t0, tcp_rng, b["tcp"] * 0.05)))))
    else:
        load_rng = rng_for(host_id, "load")
        load_phase = load_rng() * 2 * math.pi
        out.append(Series("node_boot_time_seconds", "gauge", L(), lambda t: boot))
        out.append(Series("node_load1", "gauge", L(),
                          lambda t: max(0.0, wave(b["cpu"] / 100.0 * 2, 0.5, 5400, load_phase, t, t0, load_rng, 0.2))))
        out.append(Series("node_netstat_Tcp_CurrEstab", "gauge", L(),
                          lambda t: max(1, round(wave(b["tcp"], b["tcp"] * 0.3, 3600, tcp_phase, t, t0, tcp_rng, b["tcp"] * 0.05)))))

    # `up` carries the scrape `job` Prometheus would synthesize, because the
    # System-graphs page gates the system list on up{job="system-wrangler-exporters"}.
    out.append(Series("up", "gauge", L(job="system-wrangler-exporters"), lambda t: 1))
    return out


def fmt(v):
    if isinstance(v, int):
        return str(v)
    if v == int(v):
        return str(int(v))
    return repr(round(v, 4))


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: gen_metrics.py <sqlite-db>\n")
        return 2
    hosts = load_hosts(sys.argv[1])
    if not hosts:
        sys.stderr.write("gen_metrics: no reachable hosts in DB\n")
        return 1

    end = int(time.time()) + FUTURE
    end -= end % STEP
    start = end - SPAN
    times = list(range(start, end + 1, STEP))

    # Build every host's series, then group by family so each family's
    # samples are contiguous with a single TYPE line (OpenMetrics rule).
    all_series = []
    for hid, klass in hosts:
        all_series.extend(build_series(hid, klass, end))

    by_family = {}
    order = []
    for s in all_series:
        if s.family not in by_family:
            by_family[s.family] = []
            order.append(s.family)
        by_family[s.family].append(s)

    w = sys.stdout.write
    buf = []
    for fam in order:
        members = by_family[fam]
        w(f"# TYPE {fam} {members[0].mtype}\n")
        for s in members:
            lbl = s.label_str()
            if s.mtype == "counter":
                total = 0.0
                prev = times[0]
                for t in times:
                    total += s.fn(t) * (t - prev)
                    prev = t
                    buf.append(f"{fam}{lbl} {fmt(total)} {t}\n")
            else:
                for t in times:
                    buf.append(f"{fam}{lbl} {fmt(s.fn(t))} {t}\n")
            if len(buf) >= 50000:
                w("".join(buf))
                buf.clear()
    if buf:
        w("".join(buf))
        buf.clear()
    w("# EOF\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
