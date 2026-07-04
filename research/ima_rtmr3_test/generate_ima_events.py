#!/usr/bin/env python3
"""
Generate controlled IMA events for the IMA -> RTMR[3] test.

This creates unique executable scripts under /tmp and executes them.  On the
GCP CVM image used by this project, the active IMA policy has measured these
execs in earlier experiments.  If your policy differs, the script reports the
before/after runtime_measurements_count so you can see whether entries were
actually added.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import time

from ima_rtmr3_common import read_ima_count


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate IMA entries")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--label", default="rtmr3")
    parser.add_argument("--dir", default="/tmp/ima_rtmr3_events")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    os.makedirs(args.dir, exist_ok=True)

    before = read_ima_count()
    created = []
    start = time.perf_counter()

    for i in range(args.count):
        path = os.path.join(args.dir, f"{args.label}_{time.time_ns()}_{i}.sh")
        with open(path, "w", encoding="utf-8") as f:
            f.write("#!/usr/bin/env bash\n")
            f.write(f"# label={args.label} index={i} time={time.time_ns()}\n")
            f.write("printf 'ima-rtmr3-event\\n' >/dev/null\n")
        os.chmod(path, 0o755)
        subprocess.run([path], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        created.append(path)

    elapsed_ms = (time.perf_counter() - start) * 1000.0
    time.sleep(0.3)
    after = read_ima_count()

    if not args.keep:
        for path in created:
            try:
                os.unlink(path)
            except OSError:
                pass

    print(f"requested={args.count}")
    print(f"ima_count_before={before}")
    print(f"ima_count_after={after}")
    if before >= 0 and after >= 0:
        print(f"ima_count_delta={after - before}")
    print(f"elapsed_ms={elapsed_ms:.1f}")


if __name__ == "__main__":
    main()
