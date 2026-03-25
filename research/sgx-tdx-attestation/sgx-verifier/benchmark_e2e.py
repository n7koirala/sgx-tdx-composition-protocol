#!/usr/bin/env python3
"""
End-to-End IMA Attestation Benchmark

Runs on the SGX verifier side and drives multiple attestation rounds against
a live TDX attestation server, comparing full-replay vs incremental strategies.

Full Replay:    Every round sends ima_offset=0 → server re-reads entire IMA log
Incremental:    First round ima_offset=0, subsequent rounds ima_offset=<last_count>
                → server sends only delta entries via persistent fd

Measures per round:
  - t_connect_ms:      TLS handshake time
  - t_request_ms:      Time to send request
  - t_response_ms:     Time to receive response (includes server-side processing)
  - t_ima_verify_ms:   SHA-1 per-entry verification on verifier side
  - t_total_ms:        Full round-trip
  - ima_entries:       Number of IMA entries in response
  - ima_data_kb:       IMA log data size in response

Usage:
    python3 benchmark_e2e.py --tdx-host <IP> --tdx-port 8443 --strategy full
    python3 benchmark_e2e.py --tdx-host <IP> --tdx-port 8443 --strategy incremental
    python3 benchmark_e2e.py --tdx-host <IP> --tdx-port 8443 --strategy both
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

# Add parent directory for common module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import (
    AttestationRequest, AttestationResponse, VerificationResult,
    generate_nonce, verify_dcap_quote, verify_ima_log,
    create_tls_context_client, send_message, receive_message,
    DEFAULT_PORT, METHOD_DCAP
)


def run_attestation_round(tdx_host, tdx_port, method, verify_cert, ca_cert,
                          ima_offset=0, verbose=False):
    """
    Run a single attestation round and return detailed timing.

    Args:
        ima_offset: 0 = full replay, >0 = incremental (skip first N entries)

    Returns:
        dict with timing breakdown and IMA stats
    """
    result = {}
    t_total_start = time.perf_counter()

    # Generate nonce
    nonce = generate_nonce()

    # TLS connect
    t_conn_start = time.perf_counter()
    tls_context = create_tls_context_client(
        ca_cert_file=ca_cert, verify=verify_cert
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(60)
    tls_sock = tls_context.wrap_socket(sock, server_hostname=tdx_host)
    tls_sock.connect((tdx_host, tdx_port))
    t_conn_end = time.perf_counter()
    result['t_connect_ms'] = round((t_conn_end - t_conn_start) * 1000, 1)

    try:
        # Send request
        t_req_start = time.perf_counter()
        request = AttestationRequest(
            nonce=nonce,
            attestation_method=method,
            ima_offset=ima_offset
        )
        send_message(tls_sock, request.to_json())
        t_req_end = time.perf_counter()
        result['t_request_ms'] = round((t_req_end - t_req_start) * 1000, 1)

        # Receive response (includes server processing + network transfer)
        t_resp_start = time.perf_counter()
        response_json = receive_message(tls_sock)
        t_resp_end = time.perf_counter()
        result['t_response_ms'] = round((t_resp_end - t_resp_start) * 1000, 1)

        response = AttestationResponse.from_json(response_json)

        # Quote verification
        t_quote_start = time.perf_counter()
        if response.raw_quote:
            quote_bytes = base64.b64decode(response.raw_quote)
            quote_result = verify_dcap_quote(quote_bytes, nonce, debug=False)
            result['boot_verdict'] = quote_result.verdict
        else:
            result['boot_verdict'] = 'N/A'
        t_quote_end = time.perf_counter()
        result['t_quote_verify_ms'] = round((t_quote_end - t_quote_start) * 1000, 1)

        # IMA verification
        t_ima_start = time.perf_counter()
        ima_entries = 0
        ima_data_bytes = 0
        runtime_verdict = 'IMA_UNAVAILABLE'

        if response.ima_log and response.pcr10:
            ima_log_text = base64.b64decode(response.ima_log).decode('utf-8')
            ima_data_bytes = len(response.ima_log)
            ima_valid, ima_count, ima_msg = verify_ima_log(
                ima_log_text, response.pcr10, debug=False
            )
            ima_entries = ima_count
            runtime_verdict = 'CLEAN' if ima_valid else 'VIOLATION'
        elif response.ima_entry_count > 0 and not response.ima_log:
            # Incremental round with no new entries
            ima_entries = 0
            runtime_verdict = 'CLEAN_NO_DELTA'

        t_ima_end = time.perf_counter()
        result['t_ima_verify_ms'] = round((t_ima_end - t_ima_start) * 1000, 1)

        result['ima_entries'] = ima_entries
        result['ima_total_count'] = response.ima_entry_count
        result['ima_data_kb'] = round(ima_data_bytes / 1024, 1)
        result['runtime_verdict'] = runtime_verdict

    finally:
        tls_sock.close()

    t_total_end = time.perf_counter()
    result['t_total_ms'] = round((t_total_end - t_total_start) * 1000, 1)

    return result


def run_strategy(strategy, tdx_host, tdx_port, method, verify_cert, ca_cert,
                 rounds, verbose):
    """Run a full benchmark for one strategy (full or incremental)."""
    print(f"\n{'─' * 80}")
    print(f"  Strategy: {strategy.upper()}")
    print(f"{'─' * 80}")

    print(f"\n{'Rnd':>3} | {'IMA Ent':>8} | {'Data KB':>8} | {'Connect':>8} | "
          f"{'Response':>9} | {'QuoteV':>7} | {'IMA V':>7} | {'Total':>9} | Verdict")
    print("-" * 95)

    results = []
    verified_count = 0  # For incremental: tracks verified entries

    for r in range(1, rounds + 1):
        if strategy == 'full':
            offset = 0
        else:  # incremental
            offset = verified_count

        res = run_attestation_round(
            tdx_host, tdx_port, method, verify_cert, ca_cert,
            ima_offset=offset, verbose=verbose
        )
        res['round'] = r
        res['strategy'] = strategy
        res['ima_offset_sent'] = offset

        # Update verified_count for incremental
        if strategy == 'incremental' and res['ima_total_count'] > 0:
            verified_count = res['ima_total_count']

        results.append(res)

        print(f"{r:>3} | {res['ima_entries']:>8,} | {res['ima_data_kb']:>8.1f} | "
              f"{res['t_connect_ms']:>7.0f}ms | {res['t_response_ms']:>8.0f}ms | "
              f"{res['t_quote_verify_ms']:>6.0f}ms | {res['t_ima_verify_ms']:>6.0f}ms | "
              f"{res['t_total_ms']:>8.0f}ms | {res['runtime_verdict']}")

    return results


def print_summary(full_results, inc_results):
    """Print comparison summary."""
    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print(f"{'=' * 80}")

    for label, results in [("Full Replay", full_results), ("Incremental", inc_results)]:
        if not results:
            continue

        # Skip round 1 for incremental (it's the same as full replay)
        if label == "Incremental" and len(results) > 1:
            steady = results[1:]  # rounds 2+ are steady state
        else:
            steady = results

        totals = [r['t_total_ms'] for r in steady]
        responses = [r['t_response_ms'] for r in steady]
        ima_data = [r['ima_data_kb'] for r in steady]
        ima_entries = [r['ima_entries'] for r in steady]

        print(f"\n  {label} (rounds {2 if label == 'Incremental' and len(results) > 1 else 1}-{len(results)}):")
        print(f"    Total time:    {statistics.mean(totals):>9.1f} ms  (±{statistics.stdev(totals):.1f})" if len(totals) > 1 else f"    Total time:    {totals[0]:>9.1f} ms")
        print(f"    Response time: {statistics.mean(responses):>9.1f} ms  (server + network)")
        print(f"    IMA data:      {statistics.mean(ima_data):>9.1f} KB")
        print(f"    IMA entries:   {statistics.mean(ima_entries):>9.0f}")

    if full_results and inc_results and len(inc_results) > 1:
        full_mean = statistics.mean(r['t_total_ms'] for r in full_results)
        inc_mean = statistics.mean(r['t_total_ms'] for r in inc_results[1:])
        speedup = full_mean / inc_mean if inc_mean > 0 else float('inf')

        full_data = statistics.mean(r['ima_data_kb'] for r in full_results)
        inc_data = statistics.mean(r['ima_data_kb'] for r in inc_results[1:])
        data_reduction = (1 - inc_data / full_data) * 100 if full_data > 0 else 0

        print(f"\n  Comparison (steady-state incremental vs full replay):")
        print(f"    Speedup:        {speedup:>8.1f}x")
        print(f"    Data reduction: {data_reduction:>8.1f}%")


def write_csv(all_results, output_path):
    """Write results to CSV."""
    if not all_results:
        return
    fieldnames = list(all_results[0].keys())
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_results)
    print(f"\n  Results saved to: {output_path}")


def print_latex(full_results, inc_results):
    """Print LaTeX table."""
    print(f"\n{'─' * 80}")
    print("LaTeX snippet:")
    print(f"{'─' * 80}")

    print(r"\begin{tabular}{lrrrrr}")
    print(r"\toprule")
    print(r"\textbf{Strategy} & \textbf{Entries} & \textbf{Data (KB)} & "
          r"\textbf{Response (ms)} & \textbf{Total (ms)} & \textbf{Speedup} \\")
    print(r"\midrule")

    if full_results:
        fr = full_results
        f_ent = statistics.mean(r['ima_entries'] for r in fr)
        f_data = statistics.mean(r['ima_data_kb'] for r in fr)
        f_resp = statistics.mean(r['t_response_ms'] for r in fr)
        f_total = statistics.mean(r['t_total_ms'] for r in fr)
        print(f"Full Replay & {f_ent:,.0f} & {f_data:,.1f} & "
              f"{f_resp:,.1f} & {f_total:,.1f} & $1\\times$ \\\\")

    if inc_results and len(inc_results) > 1:
        ir = inc_results[1:]  # steady state
        i_ent = statistics.mean(r['ima_entries'] for r in ir)
        i_data = statistics.mean(r['ima_data_kb'] for r in ir)
        i_resp = statistics.mean(r['t_response_ms'] for r in ir)
        i_total = statistics.mean(r['t_total_ms'] for r in ir)
        speedup = f_total / i_total if i_total > 0 else 0
        print(f"Incremental & {i_ent:,.0f} & {i_data:,.1f} & "
              f"{i_resp:,.1f} & {i_total:,.1f} & ${speedup:,.0f}\\times$ \\\\")

    print(r"\bottomrule")
    print(r"\end{tabular}")


def main():
    parser = argparse.ArgumentParser(
        description="End-to-End IMA Attestation Benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run both strategies (recommended):
  python3 benchmark_e2e.py --tdx-host 146.148.46.72 --tdx-port 8443 --strategy both

  # Just full replay:
  python3 benchmark_e2e.py --tdx-host 146.148.46.72 --tdx-port 8443 --strategy full

  # More rounds for tighter confidence intervals:
  python3 benchmark_e2e.py --tdx-host 146.148.46.72 --tdx-port 8443 --rounds 20
"""
    )

    parser.add_argument("--tdx-host", required=True, help="TDX server IP/hostname")
    parser.add_argument("--tdx-port", type=int, default=DEFAULT_PORT, help="TDX server port")
    parser.add_argument("--method", default=METHOD_DCAP, help="Attestation method (default: dcap)")
    parser.add_argument("--strategy", choices=['full', 'incremental', 'both'], default='both',
                        help="Benchmark strategy (default: both)")
    parser.add_argument("--rounds", type=int, default=10,
                        help="Attestation rounds per strategy (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Skip TLS cert verification")
    parser.add_argument("--ca-cert", help="CA certificate for TLS")
    parser.add_argument("--output", default="/tmp/benchmark_e2e_results.csv", help="Output CSV file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    print("=" * 80)
    print("End-to-End IMA Attestation Benchmark")
    print("=" * 80)
    print(f"  TDX Server:  {args.tdx_host}:{args.tdx_port}")
    print(f"  Method:      {args.method}")
    print(f"  Strategy:    {args.strategy}")
    print(f"  Rounds:      {args.rounds}")
    print(f"  Output:      {args.output}")

    verify_cert = not args.no_verify
    all_results = []
    full_results = []
    inc_results = []

    if args.strategy in ('full', 'both'):
        full_results = run_strategy(
            'full', args.tdx_host, args.tdx_port, args.method,
            verify_cert, args.ca_cert, args.rounds, args.verbose
        )
        all_results.extend(full_results)

    if args.strategy in ('incremental', 'both'):
        inc_results = run_strategy(
            'incremental', args.tdx_host, args.tdx_port, args.method,
            verify_cert, args.ca_cert, args.rounds, args.verbose
        )
        all_results.extend(inc_results)

    # Output
    print_summary(full_results, inc_results)
    write_csv(all_results, args.output)
    if full_results and inc_results:
        print_latex(full_results, inc_results)

    print(f"\n{'=' * 80}")


if __name__ == "__main__":
    main()
