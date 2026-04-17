#!/usr/bin/env python3
"""
IMA Baseline Generator for Incremental Attestation Benchmark

Generates IMA entries on the CVM to reach a target baseline count.
Each call creates unique executable scripts that trigger new IMA
measurements, bringing the total IMA entry count to the target value.

Also supports generating exactly Δn NEW entries on top of the current
count (for adding delta entries between attestation rounds).

Usage:
    # Bring IMA log to N=10,000 entries:
    sudo python3 generate_ima_baseline.py --target 10000

    # Add exactly 500 new entries:
    sudo python3 generate_ima_baseline.py --delta 500

    # Check current IMA count:
    sudo python3 generate_ima_baseline.py --status
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


def generate_entries(count, batch_label="bench"):
    """
    Generate exactly `count` new IMA entries by creating and executing
    unique shell scripts. Each script has unique content so IMA will
    measure it as a new file.

    Returns:
        Tuple of (files_created, list_of_paths, actual_new_entries)
    """
    tmp_dir = "/tmp/ima_bench_baseline"
    os.makedirs(tmp_dir, exist_ok=True)

    before = get_ima_count()
    created = []
    t0 = time.perf_counter()

    for i in range(count):
        fname = f"{tmp_dir}/{batch_label}_{i}.sh"
        content = f"#!/bin/bash\n# {batch_label} idx={i} t={time.time_ns()}\necho ok\n"
        with open(fname, 'w') as f:
            f.write(content)
        os.chmod(fname, 0o755)
        os.system(f"{fname} > /dev/null 2>&1")
        created.append(fname)

        # Progress reporting
        if (i + 1) % 1000 == 0:
            elapsed = (time.perf_counter() - t0) * 1000
            rate = (i + 1) / (elapsed / 1000) if elapsed > 0 else 0
            print(f"    Generated {i+1:,}/{count:,} "
                  f"({elapsed/1000:.1f}s, {rate:.0f} entries/s)")

    t1 = time.perf_counter()
    elapsed = (t1 - t0) * 1000

    # Wait for IMA to finish processing
    time.sleep(0.5)
    after = get_ima_count()
    actual_new = after - before

    return created, actual_new, elapsed


def cleanup(paths):
    """Remove generated files."""
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass
    try:
        os.rmdir("/tmp/ima_bench_baseline")
    except OSError:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="IMA Baseline Generator for Incremental Attestation Benchmark"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--target", type=int,
                       help="Target IMA entry count (will generate enough to reach this)")
    group.add_argument("--delta", type=int,
                       help="Generate exactly this many NEW entries")
    group.add_argument("--status", action="store_true",
                       help="Just print current IMA count and exit")

    parser.add_argument("--no-cleanup", action="store_true",
                        help="Don't clean up generated files")
    parser.add_argument("--label", type=str, default="bench",
                        help="Batch label for filenames")

    args = parser.parse_args()

    current = get_ima_count()

    if args.status:
        print(f"Current IMA entry count: {current:,}")
        return

    if args.target is not None:
        if current >= args.target:
            print(f"✓ IMA count is already {current:,} (target: {args.target:,})")
            print(f"  Note: IMA entries persist until reboot. "
                  f"Reboot to reset the count.")
            return

        needed = args.target - current
        print("=" * 60)
        print(f"Generating IMA Baseline")
        print("=" * 60)
        print(f"  Current IMA count:  {current:,}")
        print(f"  Target IMA count:   {args.target:,}")
        print(f"  Entries to generate: {needed:,}")
        print()

        paths, actual, elapsed_ms = generate_entries(needed, args.label)

        final = get_ima_count()
        print(f"\n  Final IMA count:   {final:,}")
        print(f"  New entries:       {actual:,} (requested {needed:,})")
        print(f"  Time:              {elapsed_ms/1000:.1f}s")

        if final >= args.target:
            print(f"  ✓ Target reached!")
        else:
            print(f"  ⚠ Target not fully reached ({final:,} < {args.target:,})")

        if not args.no_cleanup:
            print("  Cleaning up temp files...")
            cleanup(paths)
            print("  Done.")

    elif args.delta is not None:
        print("=" * 60)
        print(f"Generating {args.delta:,} New IMA Entries")
        print("=" * 60)
        print(f"  Current IMA count: {current:,}")
        print()

        paths, actual, elapsed_ms = generate_entries(args.delta, args.label)

        final = get_ima_count()
        print(f"\n  Final IMA count:   {final:,}")
        print(f"  New entries:       {actual:,}")
        print(f"  Time:              {elapsed_ms/1000:.1f}s")

        if not args.no_cleanup:
            print("  Cleaning up temp files...")
            cleanup(paths)
            print("  Done.")

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
