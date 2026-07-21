#!/usr/bin/env python3
"""Run the Protocol 1.2 vTPM/RTMR3 incremental-attestation matrix.

The same driver runs either inside Gramine SGX or as ordinary Python. It
establishes a fresh verifier checkpoint at each nominal baseline, prompts for
a controlled CVM-side IMA update, performs the complete composed-evidence
verification, and writes one chart-compatible CSV row per measured round.

The non_optimized mode requests a CVM descriptor reset before every measured
round. That control retains delta-only communication and WEN replay while
forcing the CVM to reopen and validate the complete binary and ASCII streams.
"""

import argparse
import csv
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import DEFAULT_PORT, METHOD_DCAP, PROTOCOL_VERSION
from sgx_tdx_verifier import SGXTDXVerifier


DEFAULT_BASELINES = [10000, 50000, 100000, 200000]
DEFAULT_DELTAS = [100, 500, 1000, 5000, 10000, 15000]

FIELDS = [
    "protocol_version",
    "environment",
    "baseline_N",
    "baseline_actual",
    "delta_n",
    "delta_actual",
    "mode",
    "read_mode",
    "repeat",
    "ima_offset_sent",
    "ima_entries_received",
    "ima_total_count",
    "ima_data_kb",
    "response_json_kb",
    "t_connect_ms",
    "t_request_ms",
    "t_response_ms",
    "t_server_ima_read_ms",
    "t_server_quote_ms",
    "t_vtpm_quote_ms",
    "t_rtmr_extend_ms",
    "t_quote_verify_ms",
    "t_ima_verify_ms",
    "t_checkpoint_commit_ms",
    "t_total_ms",
    "verification_mode",
    "fd_generation",
    "fast_path",
    "binary_bytes_read",
    "ascii_bytes_read",
    "agent_delta_entries",
    "wire_start_index",
    "checkpoint_generation",
    "checkpoint_sealed",
    "boot_verdict",
    "runtime_verdict",
    "pcr_match",
    "rtmr3_match",
    "vtpm_signature_ok",
    "vtpm_nonce_ok",
    "ak_bind_consistent",
    "ak_cert_ok",
    "golden_policy_ok",
    "overall_ok",
    "post_quote_drift",
]


def comma_ints(value):
    return [int(part.strip()) for part in value.split(",") if part.strip()]


def is_sgx():
    return os.path.exists("/dev/attestation")


def mode_label(mode, in_sgx):
    if mode == "non_optimized":
        return "Non-Optimized"
    return "Optimized (SGX)" if in_sgx else "Optimized (Python)"


def require_success(result, context):
    if not (result.verified and result.ima_verified):
        raise RuntimeError(
            f"{context} failed: verdict={result.verdict}, "
            f"runtime={result.runtime_verdict}, error={result.error}"
        )


def result_row(
    result,
    *,
    environment,
    label,
    read_mode,
    baseline_target,
    baseline_actual,
    delta_requested,
    prior_count,
    repeat,
):
    details = result.runtime_details or {}
    timing = details.get("timing", {})
    stream = details.get("stream", {})
    agent_stream = details.get("agent_stream", {})
    agent_timing = details.get("agent_timing", {})
    checkpoint = details.get("checkpoint", {})
    snapshot = details.get("snapshot", {})
    checks = result.runtime_checks or {}

    total_count = int(details.get("ima_entries", result.ima_entry_count or 0))
    wire_entries = int(details.get("wire_ima_entries", 0))
    wire_bytes = int(stream.get("wire_binary_bytes", 0)) + int(
        stream.get("wire_ascii_bytes", 0)
    )

    return {
        "protocol_version": PROTOCOL_VERSION,
        "environment": environment,
        "baseline_N": baseline_target,
        "baseline_actual": baseline_actual,
        "delta_n": delta_requested,
        "delta_actual": total_count - prior_count,
        "mode": label,
        "read_mode": read_mode,
        "repeat": repeat,
        "ima_offset_sent": prior_count,
        "ima_entries_received": wire_entries,
        "ima_total_count": total_count,
        "ima_data_kb": round(wire_bytes / 1024.0, 3),
        "response_json_kb": round(
            float(timing.get("response_json_bytes", 0)) / 1024.0, 3
        ),
        "t_connect_ms": timing.get("tls_connect_ms", 0.0),
        "t_request_ms": timing.get("request_send_ms", 0.0),
        "t_response_ms": timing.get("response_receive_ms", 0.0),
        "t_server_ima_read_ms": agent_timing.get(
            "ima_extraction_ms", agent_stream.get("total_ms", 0.0)
        ),
        "t_server_quote_ms": agent_timing.get("tdx_quote_ms", 0.0),
        "t_vtpm_quote_ms": agent_timing.get("vtpm_quote_ms", 0.0),
        "t_rtmr_extend_ms": agent_timing.get("rtmr_extend_ms", 0.0),
        "t_quote_verify_ms": timing.get("dcap_verify_ms", 0.0),
        "t_ima_verify_ms": timing.get("runtime_verify_ms", 0.0),
        "t_checkpoint_commit_ms": timing.get("checkpoint_commit_ms", 0.0),
        "t_total_ms": result.verification_time_ms,
        "verification_mode": details.get("verification_mode", ""),
        "fd_generation": agent_stream.get("fd_generation", 0),
        "fast_path": agent_stream.get("fast_path", False),
        "binary_bytes_read": agent_stream.get("binary_bytes_read", 0),
        "ascii_bytes_read": agent_stream.get("ascii_bytes_read", 0),
        "agent_delta_entries": agent_stream.get("delta_entries", 0),
        "wire_start_index": stream.get("requested_start_index", prior_count),
        "checkpoint_generation": checkpoint.get("generation", 0),
        "checkpoint_sealed": checkpoint.get("sealed", False),
        "boot_verdict": result.verdict,
        "runtime_verdict": result.runtime_verdict,
        "pcr_match": bool(
            checks.get("pcr10_signed_prefix")
            and checks.get("pcr10_prefix_count")
        ),
        "rtmr3_match": bool(
            checks.get("rtmr3_replay") and checks.get("rtmr3_metadata")
        ),
        "vtpm_signature_ok": bool(checks.get("vtpm_signature")),
        "vtpm_nonce_ok": bool(checks.get("vtpm_nonce")),
        "ak_bind_consistent": bool(checks.get("ak_bind_consistent")),
        "ak_cert_ok": bool(details.get("ak_cert_binds_ak", False)),
        "golden_policy_ok": bool(checks.get("golden_boot_policy")),
        "overall_ok": bool(result.verified and result.ima_verified),
        "post_quote_drift": snapshot.get("post_quote_drift", 0),
    }


def build_verifier(args, baseline, reset_checkpoint):
    namespace = (
        f"protocol-1.2-matrix|{args.mode}|N={baseline}|"
        f"{'sgx' if is_sgx() else 'python'}"
    )
    return SGXTDXVerifier(
        tdx_host=args.tdx_host,
        tdx_port=args.tdx_port,
        ca_cert=args.ca_cert,
        verify_cert=not args.no_verify,
        client_cert=args.client_cert,
        client_key=args.client_key,
        method=METHOD_DCAP,
        verbose=args.verbose,
        expected_rtmr3_base=args.expected_rtmr3_base,
        golden_file=args.golden_file,
        require_golden=args.require_golden,
        require_ak_cert=args.require_ak_cert,
        checkpoint_namespace=namespace,
        enable_sealed_checkpoint=not args.no_sealed_checkpoint,
        reset_checkpoint=reset_checkpoint,
    )


def write_header(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        csv.DictWriter(handle, fieldnames=FIELDS).writeheader()


def append_row(path, row):
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writerow(row)
        handle.flush()


def prompt(message, command, non_interactive):
    print()
    print(message)
    print(f"  CVM command: {command}")
    if not non_interactive:
        input("  Press Enter after the CVM command completes... ")


def print_dry_run(args, label):
    print("Protocol 1.2 matrix dry run")
    print(f"  mode:      {label}")
    print(f"  baselines: {args.baselines}")
    print(f"  deltas:    {args.deltas}")
    print(f"  repeats:   {args.repeats}")
    print(f"  rows:      {len(args.baselines) * len(args.deltas) * args.repeats}")
    print("  Each baseline performs one unrecorded full checkpoint round.")
    print("  Each measured row verifies DCAP + vTPM + AK/RTMR3 + PCR-10.")


def main():
    parser = argparse.ArgumentParser(
        description="Protocol 1.2 vTPM/RTMR3 paper-figure benchmark"
    )
    parser.add_argument("--tdx-host", required=True)
    parser.add_argument("--tdx-port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--mode", choices=("non_optimized", "optimized"), required=True
    )
    parser.add_argument(
        "--baselines",
        type=comma_ints,
        default=DEFAULT_BASELINES,
        help="Comma-separated nominal baseline sizes",
    )
    parser.add_argument(
        "--deltas",
        type=comma_ints,
        default=DEFAULT_DELTAS,
        help="Comma-separated nominal update sizes",
    )
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--output", required=True)
    parser.add_argument("--ca-cert")
    parser.add_argument("--client-cert")
    parser.add_argument("--client-key")
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--expected-rtmr3-base", default="auto")
    parser.add_argument("--golden-file")
    parser.add_argument("--require-golden", action="store_true")
    parser.add_argument("--require-ak-cert", action="store_true")
    parser.add_argument("--no-sealed-checkpoint", action="store_true")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.repeats < 1:
        parser.error("--repeats must be at least 1")

    in_sgx = is_sgx()
    environment = "sgx" if in_sgx else "python"
    label = mode_label(args.mode, in_sgx)
    read_mode = (
        "reopen-reparse" if args.mode == "non_optimized" else "persistent-fd"
    )

    if args.dry_run:
        print_dry_run(args, label)
        return 0

    output = Path(args.output)
    write_header(output)

    print("=" * 78)
    print("Protocol 1.2 vTPM/RTMR3 Incremental Attestation Matrix")
    print("=" * 78)
    print(f"Mode:        {label}")
    print(f"Environment: {environment}")
    print(f"Target:      {args.tdx_host}:{args.tdx_port}")
    print(f"Output:      {output}")
    print("Baseline rounds are not written to the result CSV.")

    rows = 0
    for baseline in args.baselines:
        prompt(
            f"Prepare nominal IMA baseline N={baseline:,}.",
            "sudo python3 ../../incremental_attestation/"
            f"generate_ima_baseline.py --target {baseline}",
            args.non_interactive,
        )

        verifier = build_verifier(args, baseline, reset_checkpoint=True)
        baseline_result = verifier.attest_tdx()
        require_success(baseline_result, f"baseline N={baseline}")
        baseline_actual = int(
            baseline_result.runtime_details.get(
                "ima_entries", baseline_result.ima_entry_count
            )
        )
        current_count = baseline_actual
        print(
            f"  Baseline checkpoint established at {baseline_actual:,} entries "
            f"({baseline_result.verification_time_ms:.1f} ms)."
        )

        for delta in args.deltas:
            for repeat in range(1, args.repeats + 1):
                prompt(
                    f"Generate update delta={delta:,} for N={baseline:,}, "
                    f"repeat={repeat}.",
                    "sudo python3 generate_ima_entries.py "
                    f"--count {delta} --label n{baseline}-d{delta}-r{repeat}",
                    args.non_interactive,
                )

                if args.mode == "non_optimized":
                    verifier._stream_action = "reset"

                prior_count = current_count
                result = verifier.attest_tdx()
                require_success(
                    result,
                    f"N={baseline}, delta={delta}, repeat={repeat}",
                )
                row = result_row(
                    result,
                    environment=environment,
                    label=label,
                    read_mode=read_mode,
                    baseline_target=baseline,
                    baseline_actual=baseline_actual,
                    delta_requested=delta,
                    prior_count=prior_count,
                    repeat=repeat,
                )
                append_row(output, row)
                rows += 1
                current_count = int(row["ima_total_count"])
                print(
                    f"  row={rows:02d} total={row['t_total_ms']:.1f} ms, "
                    f"verify={float(row['t_ima_verify_ms']):.1f} ms, "
                    f"wire={int(row['ima_entries_received']):,}, "
                    f"actual-delta={int(row['delta_actual']):,}, "
                    f"fd-gen={row['fd_generation']}, ok={row['overall_ok']}"
                )

    print(f"Wrote {rows} measured rows to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

