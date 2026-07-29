#!/usr/bin/env python3
"""
Update injector for the LLM-workload evaluation.

Fires two realistic package-install events during the measurement window
to exercise the "with-updates" interleaving with periodic ASP updates:

    t =  120s: apt-get install -y $APT_PKG
    t =  300s: pip install --no-deps --target /tmp/pipcache $PIP_PKG

Both are small packages chosen to produce a visible but not overwhelming
IMA burst (~a few hundred entries each via dpkg + elf loads).

Two modes:

  --via-asp   : Send the commands through commissioning_phase/asp_client
                run-commands (realistic — signed, audited path).  This
                requires the SGX controller to be running and the ASP
                key material to be present.

  --via-ssh   : Execute directly over ssh (for dev / baseline runs
                where the controller isn't up).  Needs --ssh-host and
                --ssh-key-file.

Usage:
    python3 update_injector.py \\
        --start-at-epoch 1714000000 \\
        --via-ssh --ssh-host 10.0.0.5 --ssh-key-file id_rsa \\
        --out updates.csv
"""

import argparse
import csv
import os
import subprocess
import sys
import time

DEFAULT_APT_PKG = "sl"            # ~200 KB, a handful of elf loads
DEFAULT_PIP_PKG = "wheel"         # pure-python, trivial network cost
DEFAULT_T_APT = 120.0
DEFAULT_T_PIP = 300.0


def run_ssh(ssh_host, ssh_key, ssh_user, command, timeout=120):
    cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-i", ssh_key,
        f"{ssh_user}@{ssh_host}",
        command,
    ]
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        ok = r.returncode == 0
        return ok, round((time.time() - t0) * 1000, 1), r.stdout[-2000:], r.stderr[-2000:]
    except subprocess.TimeoutExpired:
        return False, round((time.time() - t0) * 1000, 1), "", "TIMEOUT"


def run_asp(cvm_id, command, timeout=180):
    # Uses commissioning_phase.asp_client as a module so it picks up the
    # repo-local ASP private key + controller config.
    cmd = [
        "python3", "-m", "commissioning_phase.asp_client",
        "--action", "run-commands",
        "--cvm-id", cvm_id,
        "--command", command,
    ]
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout,
                           cwd=os.path.abspath(os.path.join(
                               os.path.dirname(__file__), "..", "..")))
        ok = r.returncode == 0
        return ok, round((time.time() - t0) * 1000, 1), r.stdout[-2000:], r.stderr[-2000:]
    except subprocess.TimeoutExpired:
        return False, round((time.time() - t0) * 1000, 1), "", "TIMEOUT"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start-at-epoch", type=float, required=True,
                    help="Reference t0 (epoch) for scheduling offsets")
    ap.add_argument("--t-apt-sec", type=float, default=DEFAULT_T_APT)
    ap.add_argument("--t-pip-sec", type=float, default=DEFAULT_T_PIP)
    ap.add_argument("--apt-pkg", default=DEFAULT_APT_PKG)
    ap.add_argument("--pip-pkg", default=DEFAULT_PIP_PKG)
    ap.add_argument("--out", required=True)

    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--via-ssh", action="store_true")
    src.add_argument("--via-asp", action="store_true")

    ap.add_argument("--ssh-host")
    ap.add_argument("--ssh-user", default="nkoirala")
    ap.add_argument("--ssh-key-file")
    ap.add_argument("--cvm-id")

    args = ap.parse_args()

    if args.via_ssh and not (args.ssh_host and args.ssh_key_file):
        print("--via-ssh needs --ssh-host and --ssh-key-file", file=sys.stderr)
        sys.exit(2)
    if args.via_asp and not args.cvm_id:
        print("--via-asp needs --cvm-id", file=sys.stderr)
        sys.exit(2)

    schedule = [
        ("apt_install", args.t_apt_sec,
         f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {args.apt_pkg}"),
        ("pip_install", args.t_pip_sec,
         f"pip3 install --no-deps --target /tmp/pipcache {args.pip_pkg}"),
    ]

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["event", "scheduled_offset_sec", "ts_epoch",
                    "elapsed_ms", "ok", "stderr_tail"])

        for name, offset, cmd in schedule:
            fire_at = args.start_at_epoch + offset
            delay = fire_at - time.time()
            if delay > 0:
                time.sleep(delay)
            ts = time.time()

            if args.via_ssh:
                ok, ms, _, err = run_ssh(
                    args.ssh_host, args.ssh_key_file,
                    args.ssh_user, cmd)
            else:
                ok, ms, _, err = run_asp(args.cvm_id, cmd)

            w.writerow([name, offset, round(ts, 6), ms, ok, err.strip()[:500]])
            fh.flush()
            print(f"[update] {name} t={offset:.0f}s ok={ok} elapsed={ms:.0f}ms",
                  flush=True)

    print(f"[update] done → {args.out}")


if __name__ == "__main__":
    main()
