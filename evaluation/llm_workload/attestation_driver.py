#!/usr/bin/env python3
"""
Attestation driver for the LLM-workload evaluation.

Runs on the load-generator / subscriber VM. Every T seconds it fires one
incremental attestation round against the CVM agent, threading the PCR-10
state forward so the subscriber maintains a rolling view of the log.

Emits one CSV row per round to attest.csv:
    round_idx, t_start_epoch, t_end_epoch, delta_n, ima_data_kb,
    t_total_ms, t_response_ms, t_server_ima_read_ms, t_server_quote_ms,
    t_quote_verify_ms, t_ima_verify_ms, pcr_match, runtime_verdict

The very first round (round_idx=0) does a full replay from offset 0 to
establish the baseline; every subsequent round is incremental (Δn only).

Usage:
    python3 attestation_driver.py \\
        --tdx-host 10.0.0.5 --tdx-port 8443 \\
        --epoch-sec 30 --duration-sec 360 \\
        --ca-cert certs/ca.crt --no-verify \\
        --out attest.csv
"""

import argparse
import csv
import os
import sys
import time

# Pick up run_attestation_round + ZERO_PCR_SHA1 from the incremental
# microbenchmark module.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(_REPO_ROOT, 'research', 'incremental_attestation'))
sys.path.insert(0, os.path.join(_REPO_ROOT, 'research', 'sgx-tdx-attestation'))

from benchmark_incremental import run_attestation_round  # noqa: E402
from ima_pcr_verify import ZERO_PCR_SHA1                  # noqa: E402
from common.protocol import DEFAULT_PORT, METHOD_DCAP     # noqa: E402


FIELDNAMES = [
    "round_idx", "t_start_epoch", "t_end_epoch",
    "ima_offset_sent", "ima_entries_received", "ima_total_count",
    "delta_n", "ima_data_kb",
    "t_total_ms", "t_connect_ms", "t_request_ms", "t_response_ms",
    "t_server_ima_read_ms", "t_server_quote_ms",
    "t_quote_verify_ms", "t_ima_verify_ms",
    "pcr_match", "runtime_verdict", "boot_verdict",
]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tdx-host", required=True)
    ap.add_argument("--tdx-port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--epoch-sec", type=float, required=True,
                    help="Seconds between attestation rounds")
    ap.add_argument("--duration-sec", type=float, required=True,
                    help="How long to keep driving attestation (wall clock)")
    ap.add_argument("--method", default=METHOD_DCAP)
    ap.add_argument("--no-verify", action="store_true")
    ap.add_argument("--ca-cert", default=None)
    ap.add_argument("--out", required=True, help="Output CSV path")
    ap.add_argument("--start-at-epoch", type=float, default=None,
                    help="Absolute epoch ts to align first round (for cross-run sync)")
    args = ap.parse_args()

    verify_cert = not args.no_verify
    pcr_state = ZERO_PCR_SHA1
    current_offset = 0
    round_idx = 0

    # Optional alignment so the attestation timeline lines up with the
    # workload's measurement window across runs.
    if args.start_at_epoch is not None:
        delay = args.start_at_epoch - time.time()
        if delay > 0:
            time.sleep(delay)

    t_wall_start = time.time()
    t_deadline = t_wall_start + args.duration_sec

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        w.writeheader()

        next_fire = t_wall_start
        while time.time() < t_deadline:
            # Sleep until the next scheduled fire. Skipped if we're late.
            now = time.time()
            if now < next_fire:
                time.sleep(next_fire - now)

            t_start = time.time()
            try:
                res = run_attestation_round(
                    args.tdx_host, args.tdx_port, verify_cert, args.ca_cert,
                    ima_offset=current_offset,
                    read_mode="optimized",
                    method=args.method,
                    verbose=False,
                    prev_pcr_state=pcr_state,
                )
            except Exception as e:
                # Log a stub row so we can see dropped rounds in the timeline.
                print(f"[attest] round {round_idx} failed: {e}", file=sys.stderr)
                w.writerow({
                    "round_idx": round_idx,
                    "t_start_epoch": round(t_start, 6),
                    "t_end_epoch": round(time.time(), 6),
                    "ima_offset_sent": current_offset,
                    "ima_entries_received": 0,
                    "ima_total_count": 0,
                    "delta_n": 0,
                    "ima_data_kb": 0,
                    "t_total_ms": "",
                    "t_connect_ms": "",
                    "t_request_ms": "",
                    "t_response_ms": "",
                    "t_server_ima_read_ms": "",
                    "t_server_quote_ms": "",
                    "t_quote_verify_ms": "",
                    "t_ima_verify_ms": "",
                    "pcr_match": False,
                    "runtime_verdict": f"ERROR:{type(e).__name__}",
                    "boot_verdict": "ERROR",
                })
                fh.flush()
                round_idx += 1
                next_fire = t_wall_start + round_idx * args.epoch_sec
                continue

            t_end = time.time()

            delta_n = res["ima_entries_received"]
            pcr_state = res["new_pcr_state"]
            res.pop("new_pcr_state", None)

            row = {
                "round_idx": round_idx,
                "t_start_epoch": round(t_start, 6),
                "t_end_epoch": round(t_end, 6),
                "ima_offset_sent": current_offset,
                "ima_entries_received": delta_n,
                "ima_total_count": res["ima_total_count"],
                "delta_n": delta_n,
                "ima_data_kb": res["ima_data_kb"],
                "t_total_ms": res["t_total_ms"],
                "t_connect_ms": res["t_connect_ms"],
                "t_request_ms": res["t_request_ms"],
                "t_response_ms": res["t_response_ms"],
                "t_server_ima_read_ms": res["t_server_ima_read_ms"],
                "t_server_quote_ms": res["t_server_quote_ms"],
                "t_quote_verify_ms": res["t_quote_verify_ms"],
                "t_ima_verify_ms": res["t_ima_verify_ms"],
                "pcr_match": res["pcr_match"],
                "runtime_verdict": res["runtime_verdict"],
                "boot_verdict": res["boot_verdict"],
            }
            w.writerow(row)
            fh.flush()

            # Advance offset so the next round is incremental.
            if res["ima_total_count"] > current_offset:
                current_offset = res["ima_total_count"]

            print(f"[attest] round {round_idx} "
                  f"Δn={delta_n} t_total={res['t_total_ms']:.1f}ms "
                  f"srv_read={res['t_server_ima_read_ms']:.1f}ms "
                  f"pcr={'OK' if res['pcr_match'] else 'MISMATCH'}",
                  flush=True)

            round_idx += 1
            next_fire = t_wall_start + round_idx * args.epoch_sec

    print(f"[attest] done: {round_idx} rounds in "
          f"{time.time() - t_wall_start:.1f}s → {args.out}")


if __name__ == "__main__":
    main()
