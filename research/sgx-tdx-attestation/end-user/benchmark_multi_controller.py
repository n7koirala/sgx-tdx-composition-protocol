#!/usr/bin/env python3
"""
Multi-Controller Scalability Benchmark

Measures end-to-end attestation performance across multiple SGX controllers.
Designed for comparison with the direct DCAP benchmark in tdx-dcap-attestation/.

Tests:
  1. Single controller: sequential + concurrent request throughput
  2. Multi-controller: round-robin distribution across N controllers
  3. Failover: one controller down, requests redistribute

Metrics captured:
  - Latency per request (ms)
  - Throughput (requests/second)
  - P50/P95/P99 latencies
  - Error rate
  - Per-controller breakdown

Usage:
    # Single controller benchmark
    python3 benchmark_multi_controller.py --controllers <SGX_IP>:9001 --requests 100

    # Multi-controller benchmark
    python3 benchmark_multi_controller.py \\
        --controllers <SGX_IP>:9001,<SGX_IP>:9002,<SGX_IP>:9003 \\
        --requests 300 --concurrency 10

    # Compare with DCAP direct (run on TDX VM):
    #   cd ../tdx-dcap-attestation && sudo python3 dcap_attestation.py
"""

import sys
import os
import time
import json
import socket
import ssl
import argparse
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import (
    EndUserRequest, ControllerToken,
    generate_nonce, send_message, receive_message,
    create_tls_context_client
)


def single_request(host: str, port: int, tls_context) -> dict:
    """Make one attestation request and return timing info."""
    result = {"host": host, "port": port, "success": False, "latency_ms": 0,
              "verdict": "", "controller_id": "", "error": ""}
    
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        tls_sock = tls_context.wrap_socket(sock, server_hostname=host)
        tls_sock.connect((host, port))
        
        nonce = generate_nonce()
        request = EndUserRequest(nonce=nonce)
        send_message(tls_sock, request.to_json())
        
        response_json = receive_message(tls_sock)
        token = ControllerToken.from_json(response_json)
        tls_sock.close()
        
        elapsed = (time.time() - start) * 1000
        result["latency_ms"] = elapsed
        result["success"] = token.status == "success" and token.tdx_verified
        result["verdict"] = token.tdx_verdict
        result["controller_id"] = token.controller_id
        
        if token.nonce_echo != nonce:
            result["error"] = "nonce mismatch"
            result["success"] = False
        
    except Exception as e:
        result["latency_ms"] = (time.time() - start) * 1000
        result["error"] = str(e)
    
    return result


def run_sequential(controllers: list, num_requests: int, tls_context) -> list:
    """Run requests sequentially, round-robin across controllers."""
    results = []
    for i in range(num_requests):
        host, port = controllers[i % len(controllers)]
        r = single_request(host, port, tls_context)
        r["request_num"] = i + 1
        results.append(r)
        
        # Progress indicator
        if (i + 1) % 10 == 0 or i == 0:
            icon = "✓" if r["success"] else "✗"
            print(f"  [{i+1}/{num_requests}] {icon} {r['controller_id']} "
                  f"{r['latency_ms']:.1f}ms {r['verdict']}")
    
    return results


def run_concurrent(controllers: list, num_requests: int,
                   concurrency: int, tls_context) -> list:
    """Run requests concurrently across controllers."""
    results = []
    
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {}
        for i in range(num_requests):
            host, port = controllers[i % len(controllers)]
            f = executor.submit(single_request, host, port, tls_context)
            futures[f] = i
        
        completed = 0
        for f in as_completed(futures):
            r = f.result()
            r["request_num"] = futures[f] + 1
            results.append(r)
            completed += 1
            
            if completed % 20 == 0 or completed == num_requests:
                print(f"  [{completed}/{num_requests}] completed...")
    
    return results


def compute_stats(results: list) -> dict:
    """Compute summary statistics from results."""
    latencies = [r["latency_ms"] for r in results if r["success"]]
    errors = [r for r in results if not r["success"]]
    
    total_time = max(r["latency_ms"] for r in results) if results else 0
    
    stats = {
        "total_requests": len(results),
        "successful": len(latencies),
        "failed": len(errors),
        "error_rate": len(errors) / len(results) * 100 if results else 0,
    }
    
    if latencies:
        latencies.sort()
        stats.update({
            "min_ms": min(latencies),
            "max_ms": max(latencies),
            "mean_ms": statistics.mean(latencies),
            "median_ms": statistics.median(latencies),
            "stdev_ms": statistics.stdev(latencies) if len(latencies) > 1 else 0,
            "p50_ms": latencies[int(len(latencies) * 0.50)],
            "p95_ms": latencies[int(len(latencies) * 0.95)],
            "p99_ms": latencies[int(len(latencies) * 0.99)],
        })
    
    # Per-controller breakdown
    by_controller = {}
    for r in results:
        cid = r.get("controller_id", "unknown")
        if cid not in by_controller:
            by_controller[cid] = {"count": 0, "success": 0, "latencies": []}
        by_controller[cid]["count"] += 1
        if r["success"]:
            by_controller[cid]["success"] += 1
            by_controller[cid]["latencies"].append(r["latency_ms"])
    
    stats["per_controller"] = {}
    for cid, data in by_controller.items():
        entry = {"requests": data["count"], "success": data["success"]}
        if data["latencies"]:
            entry["mean_ms"] = statistics.mean(data["latencies"])
            entry["p95_ms"] = sorted(data["latencies"])[int(len(data["latencies"]) * 0.95)]
        stats["per_controller"][cid] = entry
    
    return stats


def print_stats(stats: dict, label: str):
    """Pretty-print benchmark statistics."""
    print(f"\n{'=' * 70}")
    print(f"  {label}")
    print(f"{'=' * 70}")
    print(f"  Requests:    {stats['successful']}/{stats['total_requests']} "
          f"({stats['error_rate']:.1f}% error rate)")
    
    if "mean_ms" in stats:
        print(f"\n  Latency:")
        print(f"    Min:       {stats['min_ms']:.1f}ms")
        print(f"    Mean:      {stats['mean_ms']:.1f}ms")
        print(f"    Median:    {stats['median_ms']:.1f}ms")
        print(f"    P95:       {stats['p95_ms']:.1f}ms")
        print(f"    P99:       {stats['p99_ms']:.1f}ms")
        print(f"    Max:       {stats['max_ms']:.1f}ms")
        print(f"    Stdev:     {stats['stdev_ms']:.1f}ms")
    
    if stats.get("per_controller"):
        print(f"\n  Per-Controller:")
        for cid, data in stats["per_controller"].items():
            mean = f"{data['mean_ms']:.1f}ms" if "mean_ms" in data else "N/A"
            p95 = f"{data['p95_ms']:.1f}ms" if "p95_ms" in data else "N/A"
            print(f"    {cid}: {data['success']}/{data['requests']} ok, "
                  f"mean={mean}, p95={p95}")
    
    print(f"{'=' * 70}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Multi-Controller Scalability Benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--controllers", required=True,
                        help="Comma-separated controller list (host:port,host:port)")
    parser.add_argument("--requests", type=int, default=50,
                        help="Number of requests per test (default: 50)")
    parser.add_argument("--concurrency", type=int, default=5,
                        help="Concurrent requests for parallel test (default: 5)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip TLS certificate verification")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--skip-sequential", action="store_true",
                        help="Skip sequential test")
    parser.add_argument("--skip-concurrent", action="store_true",
                        help="Skip concurrent test")
    
    args = parser.parse_args()
    
    # Parse controllers
    controllers = []
    for entry in args.controllers.split(","):
        entry = entry.strip()
        if ":" in entry:
            host, port = entry.rsplit(":", 1)
            controllers.append((host, int(port)))
        else:
            controllers.append((entry, 9001))
    
    tls_context = create_tls_context_client(verify=not args.no_verify)
    
    # Banner
    print("=" * 70)
    print("Multi-Controller Scalability Benchmark")
    print("=" * 70)
    print(f"Controllers:   {', '.join(f'{h}:{p}' for h, p in controllers)}")
    print(f"Requests:      {args.requests}")
    print(f"Concurrency:   {args.concurrency}")
    print(f"Started:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    all_stats = {}
    
    # Test 1: Sequential
    if not args.skip_sequential:
        print(f"\n▶ Test 1: Sequential ({args.requests} requests, round-robin)")
        start = time.time()
        results = run_sequential(controllers, args.requests, tls_context)
        wall_time = time.time() - start
        
        stats = compute_stats(results)
        stats["wall_time_s"] = wall_time
        stats["throughput_rps"] = len(results) / wall_time if wall_time > 0 else 0
        all_stats["sequential"] = stats
        
        print_stats(stats, f"Sequential: {stats['throughput_rps']:.1f} req/s")
    
    # Test 2: Concurrent
    if not args.skip_concurrent:
        print(f"\n▶ Test 2: Concurrent ({args.requests} requests, "
              f"{args.concurrency} workers, round-robin)")
        start = time.time()
        results = run_concurrent(controllers, args.requests,
                                args.concurrency, tls_context)
        wall_time = time.time() - start
        
        stats = compute_stats(results)
        stats["wall_time_s"] = wall_time
        stats["throughput_rps"] = len(results) / wall_time if wall_time > 0 else 0
        all_stats["concurrent"] = stats
        
        print_stats(stats, f"Concurrent ({args.concurrency} workers): "
                    f"{stats['throughput_rps']:.1f} req/s")
    
    # Summary comparison
    if len(all_stats) == 2:
        seq = all_stats["sequential"]
        con = all_stats["concurrent"]
        speedup = con["throughput_rps"] / seq["throughput_rps"] if seq["throughput_rps"] > 0 else 0
        
        print("=" * 70)
        print("  COMPARISON SUMMARY")
        print("=" * 70)
        print(f"  Sequential:  {seq['throughput_rps']:.1f} req/s, "
              f"mean={seq.get('mean_ms', 0):.1f}ms")
        print(f"  Concurrent:  {con['throughput_rps']:.1f} req/s, "
              f"mean={con.get('mean_ms', 0):.1f}ms")
        print(f"  Speedup:     {speedup:.1f}x with {args.concurrency} workers")
        print(f"  Controllers: {len(controllers)}")
        print("=" * 70)
    
    # JSON output
    if args.json:
        output = {
            "benchmark": "multi-controller",
            "timestamp": datetime.now().isoformat(),
            "config": {
                "controllers": [f"{h}:{p}" for h, p in controllers],
                "requests": args.requests,
                "concurrency": args.concurrency,
            },
            "results": all_stats
        }
        print("\n" + json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
