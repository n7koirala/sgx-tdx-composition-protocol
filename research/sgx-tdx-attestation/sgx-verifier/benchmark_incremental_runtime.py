#!/usr/bin/env python3
"""Measure persistent-FD extraction and rolling WEN verification by round."""

import argparse
import csv
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import DEFAULT_PORT, METHOD_DCAP
from sgx_tdx_verifier import SGXTDXVerifier


FIELDS = [
    "round",
    "ok",
    "verification_mode",
    "total_ima_entries",
    "wire_ima_entries",
    "agent_delta_entries",
    "fd_generation",
    "fast_path",
    "binary_bytes_read",
    "ascii_bytes_read",
    "count_check_ms",
    "binary_read_ms",
    "ascii_read_ms",
    "parse_ms",
    "agent_sync_ms",
    "wen_verification_ms",
    "checkpoint_sealed",
    "checkpoint_generation",
]


def row_from_result(round_number, result):
    details = result.runtime_details or {}
    stream = details.get("agent_stream", {})
    checkpoint = details.get("checkpoint", {})
    return {
        "round": round_number,
        "ok": result.verified and result.ima_verified,
        "verification_mode": details.get("verification_mode", ""),
        "total_ima_entries": details.get("ima_entries", 0),
        "wire_ima_entries": details.get("wire_ima_entries", 0),
        "agent_delta_entries": stream.get("delta_entries", 0),
        "fd_generation": stream.get("fd_generation", 0),
        "fast_path": stream.get("fast_path", False),
        "binary_bytes_read": stream.get("binary_bytes_read", 0),
        "ascii_bytes_read": stream.get("ascii_bytes_read", 0),
        "count_check_ms": stream.get("count_check_ms", 0.0),
        "binary_read_ms": stream.get("binary_read_ms", 0.0),
        "ascii_read_ms": stream.get("ascii_read_ms", 0.0),
        "parse_ms": stream.get("parse_ms", 0.0),
        "agent_sync_ms": stream.get("total_ms", 0.0),
        "wen_verification_ms": result.verification_time_ms,
        "checkpoint_sealed": checkpoint.get("sealed", False),
        "checkpoint_generation": checkpoint.get("generation", 0),
    }


def print_row(row):
    print(
        f"round={row['round']:02d} ok={row['ok']} "
        f"mode={row['verification_mode']} total={row['total_ima_entries']:,} "
        f"wire={row['wire_ima_entries']:,} delta={row['agent_delta_entries']:,} "
        f"fd_gen={row['fd_generation']} fast={row['fast_path']} "
        f"pseudo_bytes={row['binary_bytes_read'] + row['ascii_bytes_read']:,} "
        f"agent_sync={float(row['agent_sync_ms']):.3f}ms "
        f"wen_total={float(row['wen_verification_ms']):.3f}ms "
        f"sealed={row['checkpoint_sealed']} "
        f"ckpt_gen={row['checkpoint_generation']}"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tdx-host", required=True)
    parser.add_argument("--tdx-port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--ca-cert")
    parser.add_argument("--client-cert")
    parser.add_argument("--client-key")
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--expected-rtmr3-base", default="auto")
    parser.add_argument("--checkpoint-file")
    parser.add_argument("--reset-checkpoint", action="store_true")
    parser.add_argument("--reset-cvm-stream", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()

    verifier = SGXTDXVerifier(
        tdx_host=args.tdx_host,
        tdx_port=args.tdx_port,
        ca_cert=args.ca_cert,
        verify_cert=not args.no_verify,
        client_cert=args.client_cert,
        client_key=args.client_key,
        method=METHOD_DCAP,
        verbose=False,
        expected_rtmr3_base=args.expected_rtmr3_base,
        checkpoint_file=args.checkpoint_file,
        checkpoint_namespace="incremental-benchmark",
        reset_checkpoint=args.reset_checkpoint,
        reset_cvm_stream=args.reset_cvm_stream,
    )

    rows = []
    for round_number in range(1, args.rounds + 1):
        result = verifier.attest_tdx()
        row = row_from_result(round_number, result)
        rows.append(row)
        print_row(row)
        if not row["ok"]:
            print(f"error={result.error}")
            return 1
        if round_number < args.rounds:
            time.sleep(args.interval)

    if args.output:
        with open(args.output, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
