#!/usr/bin/env python3
"""Compare persistent IMA pseudo-file extraction with full reopen/reparse."""

import argparse
import csv
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.ima_rtmr3 import (
    count_ascii_ima_entries,
    locate_ima_ascii_log,
    locate_ima_binary_log,
    read_ima_ascii_log,
    read_ima_binary_log,
)
from common.ima_stream import PersistentIMAStream


FIELDS = [
    "round",
    "kernel_entries",
    "persistent_delta_entries",
    "persistent_bytes_read",
    "persistent_read_calls",
    "persistent_fast_path",
    "persistent_total_ms",
    "full_binary_bytes",
    "full_entries",
    "full_ascii_entries",
    "full_reopen_ms",
    "speedup",
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--output", default="ima_reader_benchmark.csv")
    parser.add_argument(
        "--no-full-baseline",
        action="store_true",
        help="Measure persistent extraction only; useful for very large logs",
    )
    args = parser.parse_args()

    binary_path = locate_ima_binary_log()
    ascii_path = locate_ima_ascii_log()
    stream = PersistentIMAStream(binary_path, ascii_path)
    initial = stream.sync_aligned()
    print(
        f"initial full positioning: entries={stream.entry_count:,}, "
        f"bytes={initial.binary_bytes_read + initial.ascii_bytes_read:,}, "
        f"time={initial.total_ms:.3f}ms, fd_generation={initial.fd_generation}"
    )
    print(
        "Generate IMA entries in another terminal between rounds to measure "
        "small-delta behavior."
    )

    rows = []
    for round_number in range(1, args.rounds + 1):
        sync = stream.sync_aligned()
        full_ms = 0.0
        full_bytes = 0
        full_entries = 0
        full_ascii_entries = 0
        if not args.no_full_baseline:
            started = time.perf_counter()
            blob, entries = read_ima_binary_log(binary_path)
            ascii_log = read_ima_ascii_log(ascii_path)
            full_ms = (time.perf_counter() - started) * 1000.0
            full_bytes = len(blob) + len(ascii_log.encode("utf-8"))
            full_entries = len(entries)
            full_ascii_entries = count_ascii_ima_entries(ascii_log)

        persistent_ms = sync.total_ms
        speedup = full_ms / persistent_ms if full_ms and persistent_ms else 0.0
        row = {
            "round": round_number,
            "kernel_entries": sync.kernel_count_after,
            "persistent_delta_entries": sync.delta_entries,
            "persistent_bytes_read": (
                sync.binary_bytes_read + sync.ascii_bytes_read
            ),
            "persistent_read_calls": (
                sync.binary_read_calls + sync.ascii_read_calls
            ),
            "persistent_fast_path": sync.fast_path,
            "persistent_total_ms": round(persistent_ms, 6),
            "full_binary_bytes": full_bytes,
            "full_entries": full_entries,
            "full_ascii_entries": full_ascii_entries,
            "full_reopen_ms": round(full_ms, 6),
            "speedup": round(speedup, 3),
        }
        rows.append(row)
        print(
            f"round={round_number:02d} total={stream.entry_count:,} "
            f"delta={sync.delta_entries:,} fd_gen={sync.fd_generation} "
            f"persistent_bytes={row['persistent_bytes_read']:,} "
            f"persistent={persistent_ms:.3f}ms fast={sync.fast_path} "
            f"full={full_ms:.3f}ms speedup={speedup:.2f}x"
        )
        if round_number < args.rounds:
            time.sleep(args.interval)

    stream.close()
    with open(args.output, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
