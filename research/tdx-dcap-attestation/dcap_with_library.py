#!/usr/bin/env python3
"""
TDX DCAP Attestation with Intel Libraries + Scalability Benchmark

Uses Intel's DCAP user-space packages (libtdx-attest, libsgx-dcap-quote-verify)
via ctypes for quote generation and verification, AND the kernel configfs-tsm
and our pure-Python implementation for comparison.

Usage:
    # Check if DCAP libraries are installed
    python3 dcap_with_library.py --check

    # Run single attestation with DCAP library
    sudo python3 dcap_with_library.py --attest

    # Run scalability benchmark (N attestations, multiple methods)
    sudo python3 dcap_with_library.py --benchmark --count 100

    # Run concurrent benchmark (multiple threads)
    sudo python3 dcap_with_library.py --benchmark --count 100 --threads 4
"""

import os
import sys
import ctypes
import ctypes.util
import time
import json
import secrets
import hashlib
import statistics
import argparse
import threading
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import our existing modules
from quote_generator import (
    generate_report_data, generate_quote_configfs, generate_tdreport_ioctl,
    is_configfs_available, is_ioctl_available, TDX_REPORTDATA_LEN
)
from quote_parser import parse_quote
from dcap_verifier import verify_quote
from collateral_fetcher import fetch_collateral, DEFAULT_CACHE_DIR


# ─── Intel DCAP Library Wrappers (ctypes) ─────────────────────────────────────

class TDXAttestLibrary:
    """
    Wrapper for Intel's libtdx_attest.so — TDX quote generation library.

    This is the official Intel user-space library for generating TDX quotes.
    It communicates with the QGS daemon to produce signed quotes.

    Functions:
        tdx_att_get_quote(report_data, quote_buf, quote_size, flags)
        tdx_att_free_quote(quote_buf)
    """

    def __init__(self):
        self.lib = None
        self._load()

    def _load(self):
        """Load the libtdx_attest shared library."""
        lib_paths = [
            "libtdx_attest.so",
            "libtdx_attest.so.1",
            ctypes.util.find_library("tdx_attest"),
        ]

        for path in lib_paths:
            if path is None:
                continue
            try:
                self.lib = ctypes.CDLL(path)
                break
            except OSError:
                continue

        if self.lib is None:
            raise ImportError(
                "libtdx_attest.so not found. Install with:\n"
                "  sudo bash install_dcap_packages.sh"
            )

        # Define function signatures
        # int tdx_att_get_quote(
        #     const tdx_report_data_t *p_report_data,
        #     const tdx_uuid_t *p_att_key_id_list,
        #     uint32_t list_size,
        #     tdx_uuid_t *p_att_key_id,
        #     uint8_t **pp_quote,
        #     uint32_t *p_quote_size,
        #     uint32_t flags
        # )
        self.lib.tdx_att_get_quote.restype = ctypes.c_int
        self.lib.tdx_att_get_quote.argtypes = [
            ctypes.c_void_p,   # report_data (64 bytes)
            ctypes.c_void_p,   # att_key_id_list (can be NULL)
            ctypes.c_uint32,   # list_size
            ctypes.c_void_p,   # att_key_id (out, can be NULL)
            ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),  # pp_quote (out)
            ctypes.POINTER(ctypes.c_uint32),  # p_quote_size (out)
            ctypes.c_uint32,   # flags
        ]

        # void tdx_att_free_quote(uint8_t *p_quote)
        self.lib.tdx_att_free_quote.restype = None
        self.lib.tdx_att_free_quote.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
        ]

    def get_quote(self, report_data: bytes) -> bytes:
        """
        Generate a TDX quote using Intel's library.

        Args:
            report_data: 64-byte report data (nonce)

        Returns:
            Raw binary quote bytes
        """
        if len(report_data) != 64:
            raise ValueError(f"report_data must be 64 bytes, got {len(report_data)}")

        # Create report_data buffer
        rd_buf = (ctypes.c_uint8 * 64)(*report_data)

        # Output pointers
        pp_quote = ctypes.POINTER(ctypes.c_uint8)()
        quote_size = ctypes.c_uint32(0)

        # Call tdx_att_get_quote
        ret = self.lib.tdx_att_get_quote(
            ctypes.byref(rd_buf),   # report_data
            None,                    # att_key_id_list (NULL = default)
            0,                       # list_size
            None,                    # att_key_id out (NULL)
            ctypes.byref(pp_quote),  # pp_quote out
            ctypes.byref(quote_size), # p_quote_size out
            0,                       # flags
        )

        if ret != 0:
            raise RuntimeError(f"tdx_att_get_quote failed with error code: {ret} (0x{ret:08x})")

        # Copy quote bytes
        size = quote_size.value
        quote_bytes = bytes(pp_quote[:size])

        # Free the quote buffer
        self.lib.tdx_att_free_quote(pp_quote)

        return quote_bytes

    @property
    def available(self) -> bool:
        return self.lib is not None


class DCAPQuoteVerifyLibrary:
    """
    Wrapper for Intel's libsgx_dcap_quoteverify.so — Quote verification library.

    Functions:
        sgx_qv_verify_quote(quote, quote_size, ...)
        tee_verify_quote(quote, quote_size, ...)
    """

    def __init__(self):
        self.lib = None
        self._load()

    def _load(self):
        """Load the libsgx_dcap_quoteverify shared library."""
        lib_paths = [
            "libsgx_dcap_quoteverify.so",
            "libsgx_dcap_quoteverify.so.1",
            ctypes.util.find_library("sgx_dcap_quoteverify"),
        ]

        for path in lib_paths:
            if path is None:
                continue
            try:
                self.lib = ctypes.CDLL(path)
                break
            except OSError:
                continue

        if self.lib is None:
            raise ImportError(
                "libsgx_dcap_quoteverify.so not found. Install with:\n"
                "  sudo bash install_dcap_packages.sh"
            )

    @property
    def available(self) -> bool:
        return self.lib is not None


# ─── Check Available Methods ──────────────────────────────────────────────────

def check_available_methods() -> Dict[str, bool]:
    """Check which attestation methods are available."""
    methods = {}

    # Method 1: configfs-tsm (kernel)
    methods["configfs-tsm"] = is_configfs_available()

    # Method 2: ioctl (kernel, report only)
    methods["ioctl"] = is_ioctl_available()

    # Method 3: libtdx_attest (Intel DCAP library)
    try:
        lib = TDXAttestLibrary()
        methods["libtdx_attest"] = True
    except ImportError:
        methods["libtdx_attest"] = False

    # Method 4: libsgx_dcap_quoteverify (Intel DCAP verification)
    try:
        lib = DCAPQuoteVerifyLibrary()
        methods["libsgx_dcap_quoteverify"] = True
    except ImportError:
        methods["libsgx_dcap_quoteverify"] = False

    # Method 5: ITA (Intel Trust Authority via trustauthority-cli)
    methods["ita (trustauthority-cli)"] = shutil.which("trustauthority-cli") is not None

    return methods


# ─── Single Attestation ──────────────────────────────────────────────────────

def single_attestation_configfs(report_data: bytes) -> Tuple[float, int]:
    """Single attestation using configfs-tsm. Returns (time_ms, quote_size)."""
    start = time.perf_counter()
    quote = generate_quote_configfs(report_data, timeout=30.0)
    elapsed = (time.perf_counter() - start) * 1000
    return elapsed, len(quote.raw_quote)


def single_attestation_libtdx(lib: TDXAttestLibrary, report_data: bytes) -> Tuple[float, int]:
    """Single attestation using libtdx_attest. Returns (time_ms, quote_size)."""
    start = time.perf_counter()
    quote = lib.get_quote(report_data)
    elapsed = (time.perf_counter() - start) * 1000
    return elapsed, len(quote)


def single_attestation_ioctl(report_data: bytes) -> Tuple[float, int]:
    """Single TDREPORT generation using ioctl. Returns (time_ms, report_size)."""
    start = time.perf_counter()
    report = generate_tdreport_ioctl(report_data)
    elapsed = (time.perf_counter() - start) * 1000
    return elapsed, 1024


def single_verification_python(quote_bytes: bytes, collateral, report_data: bytes) -> Tuple[float, str]:
    """Single verification using our Python verifier. Returns (time_ms, verdict)."""
    start = time.perf_counter()
    result = verify_quote(quote_bytes, collateral, report_data)
    elapsed = (time.perf_counter() - start) * 1000
    return elapsed, result.verdict


def single_attestation_ita(config_path: str) -> Tuple[float, int]:
    """
    Single attestation using Intel Trust Authority (trustauthority-cli).
    Returns (time_ms, token_size_bytes).

    This calls `trustauthority-cli token --tdx` which:
      1. Generates a TDX quote locally
      2. Sends it to Intel Trust Authority cloud
      3. Returns a signed JWT token

    The returned time includes all three phases (local + network + cloud).
    """
    start = time.perf_counter()
    result = subprocess.run(
        ["sudo", "trustauthority-cli", "token", "--tdx", "-c", config_path],
        capture_output=True,
        text=True,
        timeout=120,
    )
    elapsed = (time.perf_counter() - start) * 1000

    # JWT tokens start with "eyJ" (base64 of '{"')
    if "eyJ" in result.stdout:
        # Extract the token (last non-empty line)
        lines = result.stdout.strip().split('\n')
        token = lines[-1].strip()
        return elapsed, len(token)
    else:
        error_msg = result.stderr.strip()[:200] if result.stderr else "Unknown error"
        raise RuntimeError(f"ITA attestation failed: {error_msg}")


# ─── Scalability Benchmark ────────────────────────────────────────────────────

@dataclass
class BenchmarkResult:
    """Results from a scalability benchmark run."""
    method: str
    total_count: int
    successful: int
    failed: int
    thread_count: int
    times_ms: List[float] = field(default_factory=list)

    @property
    def mean_ms(self) -> float:
        return statistics.mean(self.times_ms) if self.times_ms else 0

    @property
    def median_ms(self) -> float:
        return statistics.median(self.times_ms) if self.times_ms else 0

    @property
    def stddev_ms(self) -> float:
        return statistics.stdev(self.times_ms) if len(self.times_ms) > 1 else 0

    @property
    def min_ms(self) -> float:
        return min(self.times_ms) if self.times_ms else 0

    @property
    def max_ms(self) -> float:
        return max(self.times_ms) if self.times_ms else 0

    @property
    def p99_ms(self) -> float:
        if not self.times_ms:
            return 0
        sorted_times = sorted(self.times_ms)
        idx = int(len(sorted_times) * 0.99)
        return sorted_times[min(idx, len(sorted_times) - 1)]

    @property
    def total_time_s(self) -> float:
        return sum(self.times_ms) / 1000

    @property
    def throughput(self) -> float:
        """Attestations per second."""
        if self.total_time_s == 0:
            return 0
        # For threaded benchmarks, use wall-clock time
        return self.successful / (self.total_time_s / self.thread_count)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "count": self.total_count,
            "successful": self.successful,
            "failed": self.failed,
            "threads": self.thread_count,
            "mean_ms": round(self.mean_ms, 2),
            "median_ms": round(self.median_ms, 2),
            "stddev_ms": round(self.stddev_ms, 2),
            "min_ms": round(self.min_ms, 2),
            "max_ms": round(self.max_ms, 2),
            "p99_ms": round(self.p99_ms, 2),
            "throughput_per_sec": round(self.throughput, 1),
            "total_time_s": round(self.total_time_s, 2),
        }


def run_benchmark(method: str,
                  count: int,
                  threads: int = 1,
                  verbose: bool = False,
                  ita_config: str = None,
                  ita_delay: float = 0.5) -> BenchmarkResult:
    """
    Run a scalability benchmark for a given attestation method.

    Args:
        method: "configfs", "libtdx_attest", "ioctl", "verify_python", "ita"
        count: Number of attestations to perform
        threads: Number of concurrent threads
        verbose: Print progress
        ita_config: Path to ITA config file (for method="ita")
        ita_delay: Seconds to sleep between ITA requests (rate limiting)

    Returns:
        BenchmarkResult with timing statistics
    """
    result = BenchmarkResult(
        method=method,
        total_count=count,
        successful=0,
        failed=0,
        thread_count=threads,
    )

    # Prepare method-specific resources
    tdx_lib = None
    collateral = None
    sample_quote = None

    if method == "libtdx_attest":
        try:
            tdx_lib = TDXAttestLibrary()
        except ImportError as e:
            print(f"  ✗ {e}")
            result.failed = count
            return result

    if method == "verify_python":
        # Need a quote + collateral for verification benchmark
        if verbose:
            print("  Generating sample quote for verification benchmark...")
        rd = generate_report_data()
        try:
            quote_obj, _ = generate_quote_configfs(rd, timeout=30.0), None
            sample_quote = quote_obj.raw_quote
        except Exception:
            # Fall back to generating report
            print("  ⚠ Cannot generate full quote, skipping verification benchmark")
            result.failed = count
            return result

        collateral = fetch_collateral("00806F050000", verbose=False)

    # ─── Worker function ──────────────────────────────────────────────────
    lock = threading.Lock()

    def worker(task_id: int) -> Optional[float]:
        """Perform one attestation and return time in ms."""
        try:
            rd = generate_report_data()

            if method == "configfs":
                t, _ = single_attestation_configfs(rd)
            elif method == "libtdx_attest":
                t, _ = single_attestation_libtdx(tdx_lib, rd)
            elif method == "ioctl":
                t, _ = single_attestation_ioctl(rd)
            elif method == "verify_python":
                t, _ = single_verification_python(sample_quote, collateral, None)
            elif method == "ita":
                t, _ = single_attestation_ita(ita_config)
            else:
                raise ValueError(f"Unknown method: {method}")

            return t

        except Exception as e:
            if verbose:
                print(f"  ✗ Task {task_id} failed: {e}")
            return None

    # ─── Run benchmark ────────────────────────────────────────────────────
    wall_start = time.perf_counter()

    if threads == 1:
        # Sequential execution
        for i in range(count):
            t = worker(i)
            if t is not None:
                result.times_ms.append(t)
                result.successful += 1
            else:
                result.failed += 1

            if verbose and (i + 1) % max(1, count // 10) == 0:
                print(f"  Progress: {i + 1}/{count} "
                      f"(avg: {result.mean_ms:.1f}ms)")

            # Rate-limit ITA requests to avoid API throttling
            if method == "ita" and ita_delay > 0 and i < count - 1:
                time.sleep(ita_delay)
    else:
        # Concurrent execution
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(worker, i): i for i in range(count)}

            completed = 0
            for future in as_completed(futures):
                t = future.result()
                if t is not None:
                    with lock:
                        result.times_ms.append(t)
                        result.successful += 1
                else:
                    with lock:
                        result.failed += 1

                completed += 1
                if verbose and completed % max(1, count // 10) == 0:
                    print(f"  Progress: {completed}/{count}")

    wall_elapsed = time.perf_counter() - wall_start

    # For concurrent benchmarks, override throughput calculation with wall-clock
    if threads > 1:
        result._wall_time_s = wall_elapsed

    return result


def print_benchmark_result(result: BenchmarkResult):
    """Print benchmark results."""
    print(f"\n  {result.method}:")
    print(f"    Successful:  {result.successful}/{result.total_count}")
    if result.failed > 0:
        print(f"    Failed:      {result.failed}")
    print(f"    Threads:     {result.thread_count}")
    print(f"    Mean:        {result.mean_ms:.2f} ms")
    print(f"    Median:      {result.median_ms:.2f} ms")
    print(f"    Std Dev:     {result.stddev_ms:.2f} ms")
    print(f"    Min:         {result.min_ms:.2f} ms")
    print(f"    Max:         {result.max_ms:.2f} ms")
    print(f"    P99:         {result.p99_ms:.2f} ms")
    print(f"    Throughput:  {result.throughput:.1f} attestations/sec")

    if hasattr(result, '_wall_time_s'):
        wall_thru = result.successful / result._wall_time_s
        print(f"    Wall-clock:  {result._wall_time_s:.2f}s "
              f"({wall_thru:.1f} att/sec)")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="TDX DCAP Attestation with Intel Libraries + Benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--check", action="store_true",
                        help="Check available attestation methods")
    parser.add_argument("--attest", action="store_true",
                        help="Run single attestation with best available method")
    parser.add_argument("--benchmark", action="store_true",
                        help="Run scalability benchmark")
    parser.add_argument("--count", "-n", type=int, default=50,
                        help="Number of attestations for benchmark (default: 50)")
    parser.add_argument("--threads", "-t", type=int, default=1,
                        help="Number of concurrent threads (default: 1)")
    parser.add_argument("--methods", type=str, default="all",
                        help="Comma-separated methods: configfs,libtdx_attest,ioctl,verify_python,ita,all")
    parser.add_argument("--ita-config", type=str,
                        default=os.path.expanduser("~/config.json"),
                        help="Path to Intel Trust Authority config file (default: ~/config.json)")
    parser.add_argument("--ita-delay", type=float, default=0.5,
                        help="Seconds to sleep between ITA requests to avoid throttling (default: 0.5)")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Save results to file")

    args = parser.parse_args()

    # ─── Check mode ───────────────────────────────────────────────────────
    if args.check:
        print("=" * 60)
        print("Available Attestation Methods")
        print("=" * 60)

        methods = check_available_methods()
        for name, available in methods.items():
            status = "✓ Available" if available else "✗ Not installed"
            print(f"  {name:30s} {status}")

        if not methods.get("libtdx_attest"):
            print(f"\n  To install Intel DCAP libraries:")
            print(f"  sudo bash install_dcap_packages.sh")

        return

    # ─── Single attestation mode ──────────────────────────────────────────
    if args.attest:
        print("=" * 60)
        print("Single DCAP Attestation")
        print("=" * 60)

        rd = generate_report_data()
        methods = check_available_methods()

        # Try libtdx_attest first, then configfs
        if methods.get("libtdx_attest"):
            print("\n  Using: libtdx_attest (Intel DCAP library)")
            lib = TDXAttestLibrary()
            t, size = single_attestation_libtdx(lib, rd)
            print(f"  ✓ Quote generated: {size} bytes in {t:.1f}ms")

            # Parse
            quote = parse_quote(lib.get_quote(rd))
            print(f"  MRTD: {quote.body.mrtd.hex()}")

        elif methods.get("configfs-tsm"):
            print("\n  Using: configfs-tsm (kernel)")
            t, size = single_attestation_configfs(rd)
            print(f"  ✓ Quote generated: {size} bytes in {t:.1f}ms")

        else:
            print("\n  Using: ioctl (TDREPORT only)")
            t, size = single_attestation_ioctl(rd)
            print(f"  ✓ TDREPORT generated: {size} bytes in {t:.1f}ms")

        return

    # ─── Benchmark mode ──────────────────────────────────────────────────
    if args.benchmark:
        print("=" * 60)
        print("TDX DCAP Scalability Benchmark")
        print("=" * 60)
        print(f"  Count:   {args.count} attestations per method")
        print(f"  Threads: {args.threads}")

        available = check_available_methods()
        print(f"\n  Available methods:")
        for name, avail in available.items():
            print(f"    {'✓' if avail else '✗'} {name}")

        # Determine which methods to benchmark
        if args.methods == "all":
            methods_to_test = []
            if available.get("configfs-tsm"):
                methods_to_test.append("configfs")
            if available.get("libtdx_attest"):
                methods_to_test.append("libtdx_attest")
            if available.get("ioctl"):
                methods_to_test.append("ioctl")
            # Always include verification benchmark if we can generate quotes
            if available.get("configfs-tsm") or available.get("libtdx_attest"):
                methods_to_test.append("verify_python")
            if available.get("ita (trustauthority-cli)"):
                methods_to_test.append("ita")
        else:
            methods_to_test = [m.strip() for m in args.methods.split(",")]

        print(f"\n  Running benchmarks: {', '.join(methods_to_test)}")

        # Warmup
        print(f"\n  Warming up...")
        rd = generate_report_data()
        if available.get("configfs-tsm"):
            try:
                single_attestation_configfs(rd)
            except Exception:
                pass

        results = []
        for method in methods_to_test:
            print(f"\n{'─' * 60}")
            print(f"  Benchmarking: {method} ({args.count} attestations, {args.threads} threads)")
            print(f"{'─' * 60}")

            # ITA must run single-threaded (subprocess + rate limiting)
            method_threads = 1 if method == "ita" else args.threads
            if method == "ita" and args.threads > 1:
                print(f"  (ITA forced to 1 thread — subprocess-based, rate-limited)")

            bench = run_benchmark(
                method=method,
                count=args.count,
                threads=method_threads,
                verbose=args.verbose,
                ita_config=args.ita_config,
                ita_delay=args.ita_delay,
            )
            results.append(bench)
            print_benchmark_result(bench)

        # Summary
        print(f"\n{'=' * 60}")
        print("SUMMARY")
        print(f"{'=' * 60}")
        print(f"\n  {'Method':<25s} {'Mean':>8s} {'Median':>8s} {'P99':>8s} {'Thru/s':>8s}")
        print(f"  {'─' * 57}")
        for r in results:
            print(f"  {r.method:<25s} {r.mean_ms:>7.1f}ms {r.median_ms:>7.1f}ms "
                  f"{r.p99_ms:>7.1f}ms {r.throughput:>7.1f}")

        # JSON output
        if args.json or args.output:
            data = {
                "benchmark": {
                    "count": args.count,
                    "threads": args.threads,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "host": os.uname().nodename,
                    "kernel": os.uname().release,
                },
                "results": [r.to_dict() for r in results],
            }

            if args.json:
                print(f"\n{json.dumps(data, indent=2)}")

            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(data, f, indent=2)
                print(f"\n  Results saved to: {args.output}")

        return

    # Default: show help
    parser.print_help()


if __name__ == "__main__":
    main()
