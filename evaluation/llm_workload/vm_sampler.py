#!/usr/bin/env python3
"""
In-VM sampler for the LLM-workload evaluation.

Samples every --interval seconds and writes one CSV row:
    ts_epoch, cpu_pct, mem_rss_mb_total, mem_available_mb,
    ima_entry_count, ima_log_bytes, load_1m

`ima_entry_count` is read from
    /sys/kernel/security/ima/runtime_measurements_count
which is cheap (one int read).  `ima_log_bytes` is obtained via stat of
    /sys/kernel/security/ima/ascii_runtime_measurements
(the file is a seq_file pseudo-file so size == total bytes currently
reported on read); skipped if unavailable.

Runs for --duration seconds then exits cleanly.  Tolerant of missing IMA
paths so the same script can be dropped on the native / tdx-only VMs
where IMA isn't exposed.

Usage:
    python3 vm_sampler.py --interval 5 --duration 360 --out sampler.csv
"""

import argparse
import csv
import os
import time

IMA_COUNT_PATH = "/sys/kernel/security/ima/runtime_measurements_count"
IMA_LOG_PATH = "/sys/kernel/security/ima/ascii_runtime_measurements"


def read_ima_count():
    try:
        with open(IMA_COUNT_PATH) as f:
            return int(f.read().strip())
    except Exception:
        return -1


def read_ima_log_bytes():
    # ascii_runtime_measurements is a seq_file; st_size is 0. We actually
    # read and count bytes. That's O(N) — so we call this sparingly
    # (every sample, not every IMA append), and only when sample interval
    # is >= 5s it stays cheap enough to not disturb measurements.
    try:
        with open(IMA_LOG_PATH, "rb") as f:
            total = 0
            while True:
                chunk = f.read(1 << 16)
                if not chunk:
                    break
                total += len(chunk)
            return total
    except Exception:
        return -1


def read_proc_stat_cpu():
    """Return (total_jiffies, idle_jiffies) snapshot from /proc/stat."""
    with open("/proc/stat") as f:
        line = f.readline()
    parts = line.split()
    nums = list(map(int, parts[1:]))
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)  # idle + iowait
    total = sum(nums)
    return total, idle


def read_meminfo():
    d = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, rest = line.partition(":")
                v = rest.strip().split()
                if v:
                    d[k] = int(v[0])  # kB
    except Exception:
        pass
    mem_total_mb = d.get("MemTotal", 0) / 1024.0
    mem_avail_mb = d.get("MemAvailable", d.get("MemFree", 0)) / 1024.0
    mem_used_mb = max(0.0, mem_total_mb - mem_avail_mb)
    return mem_used_mb, mem_avail_mb


def read_loadavg():
    try:
        with open("/proc/loadavg") as f:
            return float(f.read().split()[0])
    except Exception:
        return -1.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--duration", type=float, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--start-at-epoch", type=float, default=None,
                    help="Align first sample with this absolute ts")
    ap.add_argument("--skip-ima-bytes", action="store_true",
                    help="Don't read IMA log bytes (O(N) per sample)")
    args = ap.parse_args()

    if args.start_at_epoch is not None:
        delay = args.start_at_epoch - time.time()
        if delay > 0:
            time.sleep(delay)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)

    t_wall_start = time.time()
    t_deadline = t_wall_start + args.duration

    prev_total, prev_idle = read_proc_stat_cpu()

    with open(args.out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow([
            "ts_epoch", "cpu_pct", "mem_used_mb", "mem_available_mb",
            "ima_entry_count", "ima_log_bytes", "load_1m",
        ])

        sample_idx = 0
        while True:
            now = time.time()
            if now >= t_deadline:
                break

            cur_total, cur_idle = read_proc_stat_cpu()
            dt = cur_total - prev_total
            didle = cur_idle - prev_idle
            cpu_pct = 0.0 if dt <= 0 else 100.0 * (1.0 - didle / dt)
            prev_total, prev_idle = cur_total, cur_idle

            mem_used_mb, mem_avail_mb = read_meminfo()
            ima_count = read_ima_count()
            ima_bytes = -1 if args.skip_ima_bytes else read_ima_log_bytes()
            load1 = read_loadavg()

            w.writerow([
                round(now, 6),
                round(cpu_pct, 2),
                round(mem_used_mb, 1),
                round(mem_avail_mb, 1),
                ima_count,
                ima_bytes,
                load1,
            ])
            fh.flush()

            sample_idx += 1
            next_fire = t_wall_start + sample_idx * args.interval
            sleep_for = next_fire - time.time()
            if sleep_for > 0:
                time.sleep(sleep_for)

    print(f"[sampler] done: {sample_idx} samples → {args.out}")


if __name__ == "__main__":
    main()
