#!/usr/bin/env python3
"""
Incremental Attestation Microbenchmark — Main Orchestrator

Drives the full experimental matrix for the incremental attestation
microbenchmark, comparing three approaches:

  1. Non-Optimized Incremental:
     CVM agent reopens IMA fd each epoch, seeks to offset → O(N + Δn)

  2. Optimized Incremental (SGX):
     CVM agent keeps IMA fd open, verifier runs inside SGX enclave → O(Δn)

  3. Optimized Incremental (Python):
     Same as #2 but verifier is plain Python (no SGX overhead) → O(Δn)

Experimental Matrix:
    N  (baseline IMA entries): 10K, 50K, 100K, 200K
    Δn (new entries per epoch): 100, 500, 1000, 5000, 10000, 15000

For each (N, Δn, mode) combination, the script:
  1. Prompts user to generate Δn entries on CVM
  2. Connects to CVM attestation agent via TLS
  3. Sends attestation request with appropriate mode + offset
  4. Receives response (TDX quote + IMA delta + PCR10 + timing)
  5. Verifies DCAP quote and IMA entries
  6. Records per-phase timing breakdown
  7. Repeats K times for statistical confidence

Usage:
    # Run non-optimized mode:
    python3 benchmark_incremental.py --tdx-host <IP> --mode non_optimized

    # Run optimized mode (will be run via Gramine-SGX or as Python):
    python3 benchmark_incremental.py --tdx-host <IP> --mode optimized

    # Run all modes sequentially:
    python3 benchmark_incremental.py --tdx-host <IP> --mode all

    # Custom matrix:
    python3 benchmark_incremental.py --tdx-host <IP> \\
        --baselines 10000,50000 --deltas 100,1000,10000 --repeats 5

    # Dry run (print matrix without connecting):
    python3 benchmark_incremental.py --tdx-host <IP> --dry-run
"""

import argparse
import base64
import csv
import json
import os
import socket
import ssl
import statistics
import sys
import time

# Add parent directory for common module, and own directory for ima_pcr_verify
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', 'sgx-tdx-attestation'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common.protocol import (
    AttestationRequest, AttestationResponse,
    generate_nonce, verify_dcap_quote,
    create_tls_context_client, send_message, receive_message,
    DEFAULT_PORT, METHOD_DCAP, MESSAGE_DELIMITER
)

# Merged IMA integrity check + PCR-10 SHA-1 extend-chain replay.
from ima_pcr_verify import verify_ima_log_with_replay, ZERO_PCR_SHA1


# ─── Gramine Enclave Startup Time ────────────────────────────────────────────
# Record the time at module load. In SGX mode, Gramine loads and measures
# all trusted files before Python starts, so the wall-clock difference
# between process start and this point represents enclave startup overhead.

_PROCESS_START_NS = time.time_ns()
_MODULE_LOAD_TIME = time.perf_counter()

try:
    # On Linux, read process start time from /proc for accurate measurement
    with open('/proc/self/stat', 'r') as f:
        fields = f.read().split()
        # Field 22 is starttime in clock ticks
        _starttime_ticks = int(fields[21])
        _clk_tck = os.sysconf('SC_CLK_TCK')
        # This gives us the relative starttime; we'll measure wall-clock instead
except Exception:
    pass


# ─── Constants ───────────────────────────────────────────────────────────────

DEFAULT_BASELINES = [10000, 50000, 100000, 200000]
DEFAULT_DELTAS = [100, 500, 1000, 5000, 10000, 15000]
DEFAULT_REPEATS = 3


# ─── Single Attestation Round ───────────────────────────────────────────────

def run_attestation_round(tdx_host, tdx_port, verify_cert, ca_cert,
                          ima_offset=0, read_mode="optimized",
                          method=METHOD_DCAP, verbose=False,
                          prev_pcr_state=ZERO_PCR_SHA1):
    """
    Run a single attestation round against the CVM agent.

    Args:
        tdx_host: CVM agent hostname/IP
        tdx_port: CVM agent port
        verify_cert: Whether to verify TLS cert
        ca_cert: CA certificate path
        ima_offset: Number of IMA entries already verified
        read_mode: "non_optimized" or "optimized"
        method: Attestation method (dcap or ita)
        prev_pcr_state: 20-byte SHA-1 PCR-10 state carried from the prior
                        round (ZERO_PCR_SHA1 for the first/baseline round).

    Returns:
        dict with detailed per-phase timing plus:
          - 'new_pcr_state': 20-byte bytes to thread into the next round
          - 'pcr_match': bool
    """
    result = {}
    t_total_start = time.perf_counter()

    nonce = generate_nonce()

    # TLS connect
    t0 = time.perf_counter()
    tls_context = create_tls_context_client(
        ca_cert_file=ca_cert, verify=verify_cert
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(120)
    tls_sock = tls_context.wrap_socket(sock, server_hostname=tdx_host)
    tls_sock.connect((tdx_host, tdx_port))
    result['t_connect_ms'] = round((time.perf_counter() - t0) * 1000, 3)

    try:
        # Build request with read_mode extension
        t0 = time.perf_counter()
        request = AttestationRequest(
            nonce=nonce,
            attestation_method=method,
            ima_offset=ima_offset,
        )
        # Add read_mode as extension field
        req_dict = json.loads(request.to_json())
        req_dict["read_mode"] = read_mode
        req_json = json.dumps(req_dict)

        data = req_json.encode('utf-8') + MESSAGE_DELIMITER
        tls_sock.sendall(data)
        result['t_request_ms'] = round((time.perf_counter() - t0) * 1000, 3)

        # Receive response
        t0 = time.perf_counter()
        response_json = receive_message(tls_sock)
        result['t_response_ms'] = round((time.perf_counter() - t0) * 1000, 3)

        # Parse response
        resp_dict = json.loads(response_json)
        response = AttestationResponse.from_json(response_json)

        # Extract server-side timing
        server_timing = resp_dict.get("_server_timing", {})
        result['t_server_ima_read_ms'] = server_timing.get('t_ima_read_ms', 0)
        result['t_server_quote_ms'] = server_timing.get('t_quote_ms', 0)
        result['server_read_mode'] = server_timing.get('read_mode', 'unknown')

        # DCAP quote verification
        t0 = time.perf_counter()
        if response.raw_quote:
            quote_bytes = base64.b64decode(response.raw_quote)
            quote_result = verify_dcap_quote(quote_bytes, nonce, debug=False)
            result['boot_verdict'] = quote_result.verdict
        else:
            result['boot_verdict'] = 'N/A'
        result['t_quote_verify_ms'] = round((time.perf_counter() - t0) * 1000, 3)

        # IMA verification + PCR-10 extend-chain replay (merged single pass).
        t0 = time.perf_counter()
        ima_entries = 0
        ima_data_bytes = 0
        runtime_verdict = 'IMA_UNAVAILABLE'
        new_pcr_state = prev_pcr_state
        pcr_match = False

        if response.ima_log and response.pcr10:
            ima_log_text = base64.b64decode(response.ima_log).decode('utf-8')
            ima_data_bytes = len(response.ima_log)
            vr = verify_ima_log_with_replay(
                ima_log_text, response.pcr10,
                prev_pcr_state=prev_pcr_state, debug=False,
            )
            ima_entries = vr.entry_count
            new_pcr_state = vr.new_pcr_state
            pcr_match = vr.pcr_match
            if vr.ok:
                runtime_verdict = 'CLEAN'
            elif vr.tampered > 0:
                runtime_verdict = 'VIOLATION'
            elif not vr.pcr_match:
                runtime_verdict = 'PCR_MISMATCH'
            else:
                runtime_verdict = 'VIOLATION'
        elif response.ima_entry_count > 0 and not response.ima_log:
            ima_entries = 0
            runtime_verdict = 'CLEAN_NO_DELTA'

        result['t_ima_verify_ms'] = round((time.perf_counter() - t0) * 1000, 3)

        result['ima_entries_received'] = ima_entries
        result['ima_total_count'] = response.ima_entry_count
        result['ima_data_kb'] = round(ima_data_bytes / 1024, 1)
        result['runtime_verdict'] = runtime_verdict
        result['pcr_match'] = pcr_match
        result['new_pcr_state'] = new_pcr_state

    finally:
        tls_sock.close()

    result['t_total_ms'] = round((time.perf_counter() - t_total_start) * 1000, 3)
    return result


def send_control_request(tdx_host, tdx_port, verify_cert, ca_cert,
                         request_type, **kwargs):
    """
    Send a control request to the CVM agent (e.g., generate delta, reset fd).

    Args:
        tdx_host: CVM agent hostname/IP
        tdx_port: CVM agent port
        verify_cert: Whether to verify TLS cert
        ca_cert: CA certificate path
        request_type: "generate_delta" or "reset_fd"
        **kwargs: Additional fields for the control request

    Returns:
        dict with the agent's response
    """
    tls_context = create_tls_context_client(
        ca_cert_file=ca_cert, verify=verify_cert
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(300)  # Delta generation can take a while
    tls_sock = tls_context.wrap_socket(sock, server_hostname=tdx_host)
    tls_sock.connect((tdx_host, tdx_port))

    try:
        req = {"request_type": "control", "action": request_type}
        req.update(kwargs)
        data = json.dumps(req).encode('utf-8') + MESSAGE_DELIMITER
        tls_sock.sendall(data)

        response_json = receive_message(tls_sock)
        return json.loads(response_json)
    finally:
        tls_sock.close()


def request_delta_generation(tdx_host, tdx_port, verify_cert, ca_cert, count):
    """
    Ask the CVM agent to generate `count` new IMA entries.
    This creates fresh delta entries for proper benchmark repetition.
    """
    return send_control_request(
        tdx_host, tdx_port, verify_cert, ca_cert,
        request_type="generate_delta", count=count
    )


def request_fd_reset(tdx_host, tdx_port, verify_cert, ca_cert, target_offset):
    """
    Ask the CVM agent to close its persistent IMA fd and reopen it
    at the target offset. This is NOT timed as part of the attestation
    measurement — it's setup for the next repeat.
    """
    return send_control_request(
        tdx_host, tdx_port, verify_cert, ca_cert,
        request_type="reset_fd", target_offset=target_offset
    )


# ─── Benchmark Runner ────────────────────────────────────────────────────────

def run_benchmark_for_mode(mode_label, read_mode, tdx_host, tdx_port,
                           verify_cert, ca_cert, baselines, deltas,
                           repeats, method, verbose, output_csv):
    """
    Run the full benchmark matrix for one mode.

    For each baseline N:
      - Prompt user to ensure IMA log has N entries
      - For each delta Δn:
        - Prompt user to generate Δn new entries on CVM
        - Run `repeats` attestation rounds
        - Record timing for each

    Args:
        mode_label: Display label for this mode
        read_mode: "non_optimized" or "optimized"
        ...

    Returns:
        list of result dicts
    """
    all_results = []

    # For optimized mode, force repeats=1 to avoid accumulating extra IMA
    # entries (each repeat generates Δn new entries, which can push the
    # total past the next baseline target). Non-optimized reopens the fd
    # each time and doesn't generate new entries, so repeats are fine.
    if read_mode == "optimized" and repeats > 1:
        print(f"\n  ⚠ Optimized mode: forcing repeats=1 (each repeat generates")
        print(f"    new IMA entries that would exceed subsequent baselines)")
        repeats = 1

    print(f"\n{'═' * 80}")
    print(f"  MODE: {mode_label}")
    print(f"  Read Mode: {read_mode}")
    print(f"  Baselines: {baselines}")
    print(f"  Deltas: {deltas}")
    print(f"  Repeats: {repeats}")
    print(f"{'═' * 80}")

    for N in baselines:
        print(f"\n{'─' * 80}")
        print(f"  BASELINE N = {N:,}")
        print(f"{'─' * 80}")

        # Fresh PCR-10 replay state per baseline N.  The baseline
        # attestation replays the full N-entry log starting from zero;
        # subsequent delta rounds extend that state incrementally.
        pcr_state = ZERO_PCR_SHA1

        # Prompt user to ensure CVM has N entries
        print(f"\n  >>> Ensure CVM IMA log has {N:,} entries.")
        print(f"  >>> On CVM: sudo python3 generate_ima_baseline.py --target {N}")
        input(f"  >>> Press Enter when ready... ")

        # Do an initial full attestation to establish baseline
        print(f"\n  Initial full attestation (establishing baseline)...")
        try:
            baseline_result = run_attestation_round(
                tdx_host, tdx_port, verify_cert, ca_cert,
                ima_offset=0, read_mode="optimized",
                method=method, verbose=verbose,
                prev_pcr_state=pcr_state,
            )
            verified_count = baseline_result['ima_total_count']
            pcr_state = baseline_result['new_pcr_state']
            print(f"  ✓ Baseline: {verified_count:,} entries, "
                  f"{baseline_result['t_total_ms']:.0f}ms total, "
                  f"{baseline_result['ima_data_kb']:.0f} KB, "
                  f"pcr_match={baseline_result['pcr_match']}")
        except Exception as e:
            print(f"  ✗ Baseline attestation failed: {e}")
            print(f"  Skipping this baseline N={N:,}")
            continue

        # For non-optimized mode, we need to track current offset
        # but the server will reopen fd each time
        current_offset = verified_count

        for dn in deltas:
            print(f"\n  ── Δn = {dn:,} (N={N:,}) ──")

            # Generate initial delta entries (manual step)
            print(f"\n  >>> Generate {dn:,} new entries on CVM:")
            print(f"  >>> sudo python3 generate_ima_baseline.py --delta {dn}")
            input(f"  >>> Press Enter when done... ")

            # Run repeats
            round_results = []
            for rep in range(1, repeats + 1):
                try:
                    # ── For optimized mode, repeats 2+ need fresh state ──
                    if read_mode == "optimized" and rep > 1:
                        print(f"    [Setup] Generating {dn:,} fresh delta entries "
                              f"for repeat {rep}...")
                        gen_result = request_delta_generation(
                            tdx_host, tdx_port, verify_cert, ca_cert, dn
                        )
                        gen_actual = gen_result.get('generated', 0)
                        gen_total = gen_result.get('total_ima_count', 0)
                        print(f"    [Setup] Generated {gen_actual:,} entries "
                              f"(total={gen_total:,}, "
                              f"{gen_result.get('elapsed_ms', 0):.0f}ms)")

                        # Reset the agent's persistent fd to the current
                        # offset so the next read picks up ONLY the new
                        # delta entries (not the ones from previous repeats)
                        reset_result = request_fd_reset(
                            tdx_host, tdx_port, verify_cert, ca_cert,
                            target_offset=current_offset
                        )
                        print(f"    [Setup] Fd reset to {reset_result.get('fd_position', 0):,} "
                              f"({reset_result.get('elapsed_ms', 0):.1f}ms)")

                    res = run_attestation_round(
                        tdx_host, tdx_port, verify_cert, ca_cert,
                        ima_offset=current_offset,
                        read_mode=read_mode,
                        method=method,
                        verbose=verbose,
                        prev_pcr_state=pcr_state,
                    )

                    res['baseline_N'] = N
                    res['delta_n'] = dn
                    res['mode'] = mode_label
                    res['read_mode'] = read_mode
                    res['repeat'] = rep
                    res['ima_offset_sent'] = current_offset

                    # Thread the PCR state forward for the next round, then
                    # drop the raw bytes from the serialised result.
                    pcr_state = res['new_pcr_state']
                    res.pop('new_pcr_state', None)

                    round_results.append(res)

                    # Print per-round summary
                    print(f"    Rep {rep}/{repeats}: "
                          f"total={res['t_total_ms']:.0f}ms, "
                          f"server_read={res['t_server_ima_read_ms']:.1f}ms, "
                          f"response={res['t_response_ms']:.0f}ms, "
                          f"ima_verify={res['t_ima_verify_ms']:.1f}ms, "
                          f"entries={res['ima_entries_received']:,}, "
                          f"{res['ima_data_kb']:.0f}KB, "
                          f"pcr={'OK' if res['pcr_match'] else 'MISMATCH'}")

                    # For optimized mode: update offset AFTER EACH repeat
                    # so the next repeat's fd reset goes to the right position.
                    # Without this, rep 2 reads 2×Δn and rep 3 reads 3×Δn
                    # because the fd resets to the original N every time.
                    if read_mode == "optimized":
                        if res['ima_total_count'] > current_offset:
                            current_offset = res['ima_total_count']

                except Exception as e:
                    print(f"    Rep {rep}/{repeats}: ✗ Error: {e}")

            if round_results:
                # For non-optimized: update offset after all rounds
                # (fd reopens each time, so offset doesn't affect reads)
                last = round_results[-1]
                if last['ima_total_count'] > current_offset:
                    current_offset = last['ima_total_count']

                # Print summary for this (N, Δn) combination
                totals = [r['t_total_ms'] for r in round_results]
                mean_total = statistics.mean(totals)
                std_total = statistics.stdev(totals) if len(totals) > 1 else 0
                print(f"    → Mean: {mean_total:.0f}ms (±{std_total:.1f}ms)")

                all_results.extend(round_results)

    return all_results


def write_csv(results, output_path):
    """Write results to CSV."""
    if not results:
        print("  No results to write.")
        return

    fieldnames = list(results[0].keys())
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"\n  Results saved to: {output_path}")


def print_summary(all_results):
    """Print a summary table of results."""
    if not all_results:
        return

    print(f"\n{'═' * 100}")
    print("SUMMARY")
    print(f"{'═' * 100}")

    # Group by (mode, N, Δn)
    groups = {}
    for r in all_results:
        key = (r['mode'], r['baseline_N'], r['delta_n'])
        if key not in groups:
            groups[key] = []
        groups[key].append(r)

    # Print header
    print(f"\n{'Mode':<28} | {'N':>8} | {'Δn':>7} | "
          f"{'Total ms':>10} | {'Srv Read':>10} | {'Response':>10} | "
          f"{'IMA-V ms':>10} | {'Data KB':>8} | {'Entries':>8}")
    print("-" * 125)

    for (mode, N, dn), results in sorted(groups.items()):
        totals = [r['t_total_ms'] for r in results]
        srv_reads = [r['t_server_ima_read_ms'] for r in results]
        responses = [r['t_response_ms'] for r in results]
        ima_vs = [r['t_ima_verify_ms'] for r in results]
        data_kbs = [r['ima_data_kb'] for r in results]
        entries = [r['ima_entries_received'] for r in results]

        mean_total = statistics.mean(totals)
        std_total = statistics.stdev(totals) if len(totals) > 1 else 0
        mean_srv = statistics.mean(srv_reads)
        mean_resp = statistics.mean(responses)
        mean_ima = statistics.mean(ima_vs)
        mean_data = statistics.mean(data_kbs)
        mean_ent = statistics.mean(entries)

        print(f"{mode:<28} | {N:>8,} | {dn:>7,} | "
              f"{mean_total:>8.0f}±{std_total:<3.0f} | "
              f"{mean_srv:>10.1f} | {mean_resp:>10.0f} | "
              f"{mean_ima:>10.1f} | {mean_data:>8.0f} | {mean_ent:>8.0f}")


def print_latex_table(all_results):
    """Print a LaTeX table of results."""
    if not all_results:
        return

    # Group by (mode, N, Δn)
    groups = {}
    for r in all_results:
        key = (r['mode'], r['baseline_N'], r['delta_n'])
        if key not in groups:
            groups[key] = []
        groups[key].append(r)

    print(f"\n{'─' * 80}")
    print("LaTeX Table:")
    print(f"{'─' * 80}")

    print(r"\begin{tabular}{llrrrrrr}")
    print(r"\toprule")
    print(r"\textbf{Mode} & \textbf{N} & \textbf{$\Delta n$} & "
          r"\textbf{Total (ms)} & \textbf{Srv Read (ms)} & "
          r"\textbf{IMA-V (ms)} & \textbf{Data (KB)} & \textbf{Entries} \\")
    print(r"\midrule")

    for (mode, N, dn), results in sorted(groups.items()):
        totals = [r['t_total_ms'] for r in results]
        srv_reads = [r['t_server_ima_read_ms'] for r in results]
        ima_vs = [r['t_ima_verify_ms'] for r in results]
        data_kbs = [r['ima_data_kb'] for r in results]
        entries = [r['ima_entries_received'] for r in results]

        mean_total = statistics.mean(totals)
        mean_srv = statistics.mean(srv_reads)
        mean_ima = statistics.mean(ima_vs)
        mean_data = statistics.mean(data_kbs)
        mean_ent = statistics.mean(entries)

        # Shorten mode name for LaTeX
        mode_short = mode.replace("Non-Optimized", "Non-Opt")\
                        .replace("Optimized (SGX)", "Opt-SGX")\
                        .replace("Optimized (Python)", "Opt-Py")

        print(f"{mode_short} & {N:,} & {dn:,} & "
              f"{mean_total:,.0f} & {mean_srv:,.1f} & "
              f"{mean_ima:,.1f} & {mean_data:,.0f} & {mean_ent:,.0f} \\\\")

    print(r"\bottomrule")
    print(r"\end{tabular}")


def dry_run(baselines, deltas, repeats, modes):
    """Print the experiment matrix without running anything."""
    total_combinations = len(baselines) * len(deltas) * repeats * len(modes)
    total_manual_steps = len(baselines) * (1 + len(deltas)) * len(modes)

    print(f"\n{'═' * 60}")
    print(f"DRY RUN — Experiment Matrix")
    print(f"{'═' * 60}")
    print(f"  Baselines (N):     {baselines}")
    print(f"  Deltas (Δn):       {deltas}")
    print(f"  Repeats:           {repeats}")
    print(f"  Modes:             {modes}")
    print(f"  Total combinations: {total_combinations}")
    print(f"  Manual steps:      {total_manual_steps}")
    print()

    for mode in modes:
        print(f"\n  ── {mode} ──")
        for N in baselines:
            print(f"    N={N:>7,}: ", end="")
            for dn in deltas:
                print(f"Δ{dn:,} ", end="")
            print(f"  ({len(deltas) * repeats} rounds)")

    est_time_per_round_sec = 2  # ~2s per attestation round
    est_manual_sec = 30  # ~30s per manual step
    est_total_min = (total_combinations * est_time_per_round_sec +
                     total_manual_steps * est_manual_sec) / 60

    print(f"\n  Estimated time: ~{est_total_min:.0f} minutes")
    print(f"  (assuming {est_time_per_round_sec}s/round + "
          f"{est_manual_sec}s/manual step)")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Incremental Attestation Microbenchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument("--tdx-host", required=True,
                        help="CVM attestation agent hostname/IP")
    parser.add_argument("--tdx-port", type=int, default=DEFAULT_PORT,
                        help=f"CVM agent port (default: {DEFAULT_PORT})")
    parser.add_argument("--method", default=METHOD_DCAP,
                        help=f"Attestation method (default: {METHOD_DCAP})")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip TLS certificate verification")
    parser.add_argument("--ca-cert", default=None,
                        help="CA certificate for TLS")

    parser.add_argument("--baselines", type=str,
                        default=",".join(str(n) for n in DEFAULT_BASELINES),
                        help=f"Comma-separated baseline N values "
                             f"(default: {DEFAULT_BASELINES})")
    parser.add_argument("--deltas", type=str,
                        default=",".join(str(d) for d in DEFAULT_DELTAS),
                        help=f"Comma-separated delta Δn values "
                             f"(default: {DEFAULT_DELTAS})")
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS,
                        help=f"Repeats per (N, Δn) combination "
                             f"(default: {DEFAULT_REPEATS})")

    parser.add_argument("--mode", choices=["non_optimized", "optimized", "all"],
                        default="all",
                        help="Which mode to benchmark (default: all)")

    parser.add_argument("--output", default=None,
                        help="Output CSV file (default: results_<mode>.csv)")

    parser.add_argument("--dry-run", action="store_true",
                        help="Print experiment matrix without running")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()

    baselines = [int(x) for x in args.baselines.split(',')]
    deltas = [int(x) for x in args.deltas.split(',')]
    verify_cert = not args.no_verify

    # Determine which modes to run
    if args.mode == "all":
        modes = ["Non-Optimized", "Optimized (Python)"]
        read_modes = ["non_optimized", "optimized"]
    elif args.mode == "non_optimized":
        modes = ["Non-Optimized"]
        read_modes = ["non_optimized"]
    else:
        modes = ["Optimized (Python)"]
        read_modes = ["optimized"]

    if args.dry_run:
        dry_run(baselines, deltas, args.repeats, modes)
        return

    # Print experiment header
    print("=" * 80)
    print("Incremental Attestation Microbenchmark")
    print("=" * 80)
    print(f"  CVM Agent:   {args.tdx_host}:{args.tdx_port}")
    print(f"  Method:      {args.method}")
    print(f"  Baselines:   {baselines}")
    print(f"  Deltas:      {deltas}")
    print(f"  Repeats:     {args.repeats}")
    print(f"  Modes:       {modes}")

    # Check if running inside SGX enclave
    in_enclave = os.path.exists("/dev/attestation")
    if in_enclave:
        enclave_startup_ms = round((_MODULE_LOAD_TIME) * 1000, 1)  # Time from process start
        print(f"  Environment: SGX Enclave (Gramine)")
        print(f"  Enclave load: ~{enclave_startup_ms:.0f}ms (Python module init)")
        # Override mode label if inside enclave
        modes = ["Optimized (SGX)"]
        read_modes = ["optimized"]
    else:
        enclave_startup_ms = 0
        print(f"  Environment: Python (no SGX)")

    all_results = []

    for mode_label, read_mode in zip(modes, read_modes):
        results = run_benchmark_for_mode(
            mode_label=mode_label,
            read_mode=read_mode,
            tdx_host=args.tdx_host,
            tdx_port=args.tdx_port,
            verify_cert=verify_cert,
            ca_cert=args.ca_cert,
            baselines=baselines,
            deltas=deltas,
            repeats=args.repeats,
            method=args.method,
            verbose=args.verbose,
            output_csv=args.output,
        )
        all_results.extend(results)

    # Output
    print_summary(all_results)
    print_latex_table(all_results)

    # Save CSV
    output_path = args.output
    if output_path is None:
        output_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f"results_{args.mode}.csv"
        )

    # Inside SGX enclave, /benchmark is read-only (trusted_files).
    # Write to /tmp first, then print instructions to copy out.
    if in_enclave and output_path.startswith('/benchmark'):
        tmp_output = '/tmp/' + os.path.basename(output_path)
        write_csv(all_results, tmp_output)
        print(f"\n  ⚠ Inside enclave: results written to {tmp_output}")
        print(f"  Copy from host: the file is at the tmpfs mount.")
        # Also try writing to the allowed_files path
        try:
            write_csv(all_results, output_path)
        except PermissionError:
            print(f"  (Could not write to {output_path} - use allowed_files mount)")
    else:
        write_csv(all_results, output_path)

    print(f"\n{'═' * 80}")
    print(f"  Benchmark complete. {len(all_results)} data points collected.")
    print(f"{'═' * 80}")


if __name__ == "__main__":
    main()
