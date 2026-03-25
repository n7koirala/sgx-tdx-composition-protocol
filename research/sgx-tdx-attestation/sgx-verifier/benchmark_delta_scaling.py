#!/usr/bin/env python3
"""
IMA Delta Scaling Benchmark (SGX verifier side)

Drives a sweep of attestation rounds with varying delta sizes.
For each delta size (e.g., 100, 500, 1000, 5000, 10000):
  1. Tells the TDX server to generate N new IMA entries
  2. Runs ONE incremental attestation round
  3. Records timing and entry counts

Requires:
  - TDX server running with --enable-ima (and benchmark helper endpoint)
  - OR: manually run generate_ima_entries.py on CVM between rounds

Mode 1 (Manual): Run generate_ima_entries.py on CVM, then run this script
Mode 2 (Auto):   This script drives everything via SSH (requires SSH access)

Usage:
    # Manual mode (run generate_ima_entries.py on CVM first):
    python3 benchmark_delta_scaling.py --tdx-host 146.148.46.72 --no-verify \\
        --deltas 0,100,500,1000,5000,10000

    # Just measure current state (no new entries):
    python3 benchmark_delta_scaling.py --tdx-host 146.148.46.72 --no-verify --deltas 0
"""

import argparse
import base64
import csv
import json
import os
import socket
import ssl
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import (
    AttestationRequest, AttestationResponse, VerificationResult,
    generate_nonce, verify_dcap_quote, verify_ima_log,
    create_tls_context_client, send_message, receive_message,
    DEFAULT_PORT, METHOD_DCAP
)


def attest_once(tdx_host, tdx_port, method, verify_cert, ca_cert, ima_offset=0):
    """Run a single attestation round with detailed per-phase timing."""
    result = {}
    t_start = time.perf_counter()

    nonce = generate_nonce()

    # TLS connect
    t0 = time.perf_counter()
    ctx = create_tls_context_client(ca_cert_file=ca_cert, verify=verify_cert)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(120)
    tls = ctx.wrap_socket(sock, server_hostname=tdx_host)
    tls.connect((tdx_host, tdx_port))
    result['t_connect_ms'] = round((time.perf_counter() - t0) * 1000, 1)

    try:
        # Send request
        t0 = time.perf_counter()
        req = AttestationRequest(nonce=nonce, attestation_method=method, ima_offset=ima_offset)
        send_message(tls, req.to_json())
        result['t_request_ms'] = round((time.perf_counter() - t0) * 1000, 1)

        # Receive response
        t0 = time.perf_counter()
        resp_json = receive_message(tls)
        result['t_response_ms'] = round((time.perf_counter() - t0) * 1000, 1)
        resp = AttestationResponse.from_json(resp_json)

        # DCAP quote verify
        t0 = time.perf_counter()
        if resp.raw_quote:
            qb = base64.b64decode(resp.raw_quote)
            verify_dcap_quote(qb, nonce, debug=False)
        result['t_quote_ms'] = round((time.perf_counter() - t0) * 1000, 1)

        # IMA verify
        t0 = time.perf_counter()
        ima_entries = 0
        ima_data_bytes = 0
        if resp.ima_log:
            ima_text = base64.b64decode(resp.ima_log).decode('utf-8')
            ima_data_bytes = len(resp.ima_log)
            _, ima_entries, _ = verify_ima_log(ima_text, resp.pcr10, debug=False)
        result['t_ima_verify_ms'] = round((time.perf_counter() - t0) * 1000, 1)

        result['ima_entries_received'] = ima_entries
        result['ima_total_count'] = resp.ima_entry_count
        result['ima_data_kb'] = round(ima_data_bytes / 1024, 1)

    finally:
        tls.close()

    result['t_total_ms'] = round((time.perf_counter() - t_start) * 1000, 1)
    return result


def main():
    parser = argparse.ArgumentParser(description="IMA Delta Scaling Benchmark")
    parser.add_argument("--tdx-host", required=True)
    parser.add_argument("--tdx-port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--method", default=METHOD_DCAP)
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--ca-cert", default=None)
    parser.add_argument("--output", default="/tmp/benchmark_delta_scaling.csv")
    parser.add_argument("--deltas", default="0",
                        help="Comma-separated delta sizes to test (default: 0). "
                             "Run generate_ima_entries.py on CVM before each non-zero delta.")

    args = parser.parse_args()
    deltas = [int(x) for x in args.deltas.split(',')]
    verify_cert = not args.no_verify

    print("=" * 80)
    print("IMA Delta Scaling Benchmark")
    print("=" * 80)
    print(f"  Server:  {args.tdx_host}:{args.tdx_port}")
    print(f"  Deltas:  {deltas}")
    print()

    # First, do an initial full replay to establish the baseline
    print("Step 1: Initial full attestation (baseline)...")
    baseline = attest_once(args.tdx_host, args.tdx_port, args.method,
                           verify_cert, args.ca_cert, ima_offset=0)
    verified_count = baseline['ima_total_count']
    print(f"  Baseline: {verified_count:,} entries, "
          f"{baseline['t_total_ms']:.0f}ms total, "
          f"{baseline['ima_data_kb']:.0f} KB")

    # Now run incremental for each delta
    print(f"\nStep 2: Incremental attestation for each delta")
    print(f"  (Generate entries on CVM BEFORE each step)")
    print()

    all_results = [{'delta_requested': 'baseline_full', 'ima_offset_sent': 0, **baseline}]

    print(f"{'Delta':>8} | {'Entries':>8} | {'Data KB':>8} | "
          f"{'Response':>9} | {'IMA V':>7} | {'Total':>9}")
    print("-" * 70)

    # Print baseline
    print(f"{'FULL':>8} | {baseline['ima_entries_received']:>8,} | "
          f"{baseline['ima_data_kb']:>8.1f} | {baseline['t_response_ms']:>8.0f}ms | "
          f"{baseline['t_ima_verify_ms']:>6.0f}ms | {baseline['t_total_ms']:>8.0f}ms")

    for delta in deltas:
        if delta > 0:
            print(f"\n  >>> Generate {delta} entries on CVM now:")
            print(f"  >>> sudo python3 generate_ima_entries.py --count {delta} --label d{delta}")
            input("  >>> Press Enter when done... ")

        res = attest_once(args.tdx_host, args.tdx_port, args.method,
                          verify_cert, args.ca_cert, ima_offset=verified_count)

        # Update verified count
        if res['ima_total_count'] > 0:
            verified_count = res['ima_total_count']

        res['delta_requested'] = delta
        res['ima_offset_sent'] = verified_count - (res['ima_entries_received'] or 0)
        all_results.append(res)

        print(f"{delta:>8} | {res['ima_entries_received']:>8,} | "
              f"{res['ima_data_kb']:>8.1f} | {res['t_response_ms']:>8.0f}ms | "
              f"{res['t_ima_verify_ms']:>6.0f}ms | {res['t_total_ms']:>8.0f}ms")

    # Save CSV
    fieldnames = list(all_results[0].keys())
    with open(args.output, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(all_results)
    print(f"\n  Results saved to: {args.output}")

    # Summary
    print(f"\n{'=' * 80}")
    print("SCALING SUMMARY")
    print(f"{'=' * 80}")
    print(f"  Full replay baseline: {baseline['t_total_ms']:,.0f} ms "
          f"({baseline['ima_entries_received']:,} entries, {baseline['ima_data_kb']:,.0f} KB)")
    for r in all_results[1:]:
        delta = r['delta_requested']
        speedup = baseline['t_total_ms'] / r['t_total_ms'] if r['t_total_ms'] > 0 else 0
        print(f"  Δ={delta:>6}: {r['t_total_ms']:>8,.0f} ms "
              f"({r['ima_entries_received']:>6,} entries, {r['ima_data_kb']:>8.1f} KB) "
              f"→ {speedup:>6.0f}x speedup")


if __name__ == "__main__":
    main()
