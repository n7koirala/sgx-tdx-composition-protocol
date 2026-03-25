#!/usr/bin/env python3
"""
IMA Delta Scaling Benchmark (CVM-side)

Runs ON the CVM and generates controlled numbers of new IMA entries
(via unique temp scripts), then signals the SGX benchmark to attest.

This script:
  1. Creates N unique executable scripts in /tmp/ima_delta/
  2. Executes each one (triggers IMA measurement)
  3. Waits for user to run attestation from SGX side
  4. Cleans up

Usage (on CVM):
    sudo python3 generate_ima_entries.py --count 100
    sudo python3 generate_ima_entries.py --count 1000
    sudo python3 generate_ima_entries.py --count 5000
    sudo python3 generate_ima_entries.py --count 10000
"""

import argparse
import os
import stat
import subprocess
import sys
import time


IMA_COUNT_PATH = "/sys/kernel/security/ima/runtime_measurements_count"


def get_ima_count():
    """Read current IMA entry count."""
    try:
        with open(IMA_COUNT_PATH, 'r') as f:
            return int(f.read().strip())
    except Exception:
        return -1


def generate_entries(count, batch_label=""):
    """
    Generate exactly `count` new IMA entries by creating and executing
    unique shell scripts. Each script has unique content (timestamp + index)
    so IMA will measure it as a new file.
    """
    tmp_dir = "/tmp/ima_delta"
    os.makedirs(tmp_dir, exist_ok=True)

    before = get_ima_count()
    print(f"  IMA count before: {before:,}")

    created = []
    t0 = time.perf_counter()

    for i in range(count):
        fname = f"{tmp_dir}/delta_{batch_label}_{i}.sh"
        # Unique content ensures unique SHA-256 hash → new IMA entry
        content = f"#!/bin/bash\n# {batch_label} idx={i} t={time.time_ns()}\necho ok\n"
        with open(fname, 'w') as f:
            f.write(content)
        os.chmod(fname, 0o755)
        # Execute it — IMA measures the file on exec
        os.system(f"{fname} > /dev/null 2>&1")
        created.append(fname)

        # Progress
        if (i + 1) % 500 == 0:
            print(f"    Generated {i+1}/{count}...")

    t1 = time.perf_counter()
    elapsed = (t1 - t0) * 1000

    # Wait a moment for IMA to finish
    time.sleep(0.5)
    after = get_ima_count()
    actual_new = after - before

    print(f"  IMA count after:  {after:,}")
    print(f"  New entries:      {actual_new:,} (requested {count})")
    print(f"  Generation time:  {elapsed:.0f} ms")

    return created, actual_new


def cleanup(paths):
    """Remove generated files."""
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass
    try:
        os.rmdir("/tmp/ima_delta")
    except OSError:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="Generate controlled IMA entries for delta benchmarking"
    )
    parser.add_argument("--count", type=int, required=True,
                        help="Number of new IMA entries to generate")
    parser.add_argument("--label", type=str, default="batch",
                        help="Batch label for filenames")
    parser.add_argument("--no-cleanup", action="store_true",
                        help="Don't clean up generated files")
    parser.add_argument("--wait", action="store_true",
                        help="Wait for user input before cleanup (to allow attestation)")

    args = parser.parse_args()

    print("=" * 60)
    print(f"Generating {args.count} new IMA entries")
    print("=" * 60)

    paths, actual = generate_entries(args.count, args.label)

    if args.wait:
        print(f"\n  >>> {actual} new entries generated.")
        print(f"  >>> Run attestation from SGX side now.")
        print(f"  >>> Press Enter when done to clean up...")
        input()

    if not args.no_cleanup:
        print("  Cleaning up...")
        cleanup(paths)
        print("  Done.")
    else:
        print(f"  Temp files kept in /tmp/ima_delta/ ({len(paths)} files)")


if __name__ == "__main__":
    main()
