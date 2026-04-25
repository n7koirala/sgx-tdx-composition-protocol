#!/usr/bin/env python3
"""Generate file and exec activity on a CVM to expand the IMA event log."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import time
from pathlib import Path


def write_executable_script(path: Path, index: int) -> None:
    payload = "\n".join(
        [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            f"echo ima-entry-{index} >/tmp/vordr-ima-{index}.txt",
            f"sha256sum /tmp/vordr-ima-{index}.txt >/tmp/vordr-ima-{index}.sha256",
            f"cat /tmp/vordr-ima-{index}.txt >/dev/null",
        ]
    )
    path.write_text(payload + "\n", encoding="utf-8")
    path.chmod(0o755)


def main() -> None:
    parser = argparse.ArgumentParser(description="Create executable/file activity for IMA measurement")
    parser.add_argument("--count", type=int, default=250, help="Number of unique scripts to create and execute")
    parser.add_argument(
        "--workdir",
        default=f"/tmp/vordr-ima-{time.strftime('%Y%m%d-%H%M%S')}",
        help="Directory to place generated workload artifacts",
    )
    parser.add_argument(
        "--keep-files",
        action="store_true",
        help="Keep the generated scripts and data instead of removing the workdir at the end",
    )
    args = parser.parse_args()

    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    print(f"Generating {args.count} IMA workload events in {workdir}")
    start = time.perf_counter()
    digests: list[str] = []
    for index in range(args.count):
        script_path = workdir / f"ima_probe_{index:05d}.sh"
        write_executable_script(script_path, index)
        subprocess.run([str(script_path)], check=True, cwd=str(workdir))
        digests.append(hashlib.sha256(script_path.read_bytes()).hexdigest())

    elapsed_ms = (time.perf_counter() - start) * 1000.0
    print(f"Completed {args.count} script executions in {elapsed_ms:.1f} ms")
    print("IMA guidance:")
    print("  1. On the TDX machine, read the resulting IMA log via the attestation server or /sys/kernel/security/ima/ascii_runtime_measurements")
    print("  2. Use this after starting the TDX attestation server so the next WEN refresh captures the larger log")

    if args.keep_files:
        print(f"Artifacts kept in {workdir}")
    else:
        shutil.rmtree(workdir, ignore_errors=True)
        print(f"Removed temporary workload directory {workdir}")


if __name__ == "__main__":
    main()
