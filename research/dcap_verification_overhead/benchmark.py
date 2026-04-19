#!/usr/bin/env python3
"""
DCAP Verification Overhead Microbenchmark.

Runs N consecutive verifications of a pre-captured TDX quote against
pre-cached DCAP collateral, measuring per-iteration latency.  Reports
two verifier implementations:

  "simple"  — ECDSA-P256 signature + nonce binding  (what the existing
              paper `t_quote_verify_ms` measures)
  "full"    — ECDSA + PCK cert chain + CRL + TCB evaluation + nonce
              (full DCAP pipeline, the real thing a production
              subscriber should perform)

Runs in two environments without code change:
  • native Python                  → results_python.csv
  • Gramine-SGX enclave           → results_sgx.csv  (auto-detected)

All inputs are loaded from ./inputs/ (populated by prepare_inputs.py).
The measurement loop performs zero I/O beyond what the verifier does
internally against in-memory collateral — there is no network, no
disk I/O in the critical path, no CVM interaction.
"""

import argparse
import csv
import json
import os
import pickle
import statistics
import sys
import time

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
RESEARCH_DIR = os.path.dirname(THIS_DIR)

# Inside Gramine these paths are remounted via the manifest; the relative
# structure is preserved so these sys.path entries resolve correctly.
sys.path.insert(0, os.path.join(RESEARCH_DIR, "sgx-tdx-attestation"))
sys.path.insert(0, os.path.join(RESEARCH_DIR, "tdx-dcap-attestation"))

from common.protocol import verify_dcap_quote as simple_verify_quote
from dcap_verifier import verify_quote as full_verify_quote


INPUTS_DIR = os.path.join(THIS_DIR, "inputs")
QUOTE_PATH = os.path.join(INPUTS_DIR, "sample_quote.bin")
NONCE_PATH = os.path.join(INPUTS_DIR, "sample_nonce.txt")
COLLATERAL_PATH = os.path.join(INPUTS_DIR, "collateral.pkl")


def detect_mode():
    """Detect whether we're running inside Gramine-SGX."""
    if os.path.exists("/dev/attestation"):
        return "sgx"
    return "python"


def load_inputs():
    with open(QUOTE_PATH, "rb") as f:
        quote_bytes = f.read()
    nonce = None
    if os.path.exists(NONCE_PATH):
        with open(NONCE_PATH) as f:
            nonce = f.read().strip() or None
    with open(COLLATERAL_PATH, "rb") as f:
        collateral = pickle.load(f)
    return quote_bytes, nonce, collateral


def run_simple(quote_bytes, nonce, _collateral):
    t0 = time.perf_counter_ns()
    result = simple_verify_quote(quote_bytes, nonce, debug=False)
    dt_ns = time.perf_counter_ns() - t0
    return dt_ns, result.verdict


def run_full(quote_bytes, _nonce, collateral):
    t0 = time.perf_counter_ns()
    result = full_verify_quote(quote_bytes, collateral, verbose=False)
    dt_ns = time.perf_counter_ns() - t0
    verdict = "TRUSTED" if result.verified else ("FAILED" if result.errors else "UNKNOWN")
    return dt_ns, verdict


def warmup(fn, quote_bytes, nonce, collateral, iters):
    for _ in range(iters):
        fn(quote_bytes, nonce, collateral)


def bench(fn, label, quote_bytes, nonce, collateral, iters):
    print(f"\n── {label}: {iters} iterations ──")
    rows = []
    verdicts = {}
    for i in range(iters):
        dt_ns, verdict = fn(quote_bytes, nonce, collateral)
        verdicts[verdict] = verdicts.get(verdict, 0) + 1
        rows.append((i + 1, label, dt_ns / 1000.0, verdict))
        if (i + 1) % max(1, iters // 10) == 0:
            print(f"  … {i+1}/{iters}  last={dt_ns/1000.0:.1f} µs")

    times_us = [r[2] for r in rows]
    print(f"  min    {min(times_us):>9.2f} µs")
    print(f"  p50    {statistics.median(times_us):>9.2f} µs")
    print(f"  mean   {statistics.mean(times_us):>9.2f} µs  "
          f"(± {statistics.stdev(times_us):>.2f})")
    print(f"  p95    {sorted(times_us)[int(0.95*len(times_us))]:>9.2f} µs")
    print(f"  p99    {sorted(times_us)[int(0.99*len(times_us))]:>9.2f} µs")
    print(f"  max    {max(times_us):>9.2f} µs")
    print(f"  verdicts: {verdicts}")
    return rows


def write_csv(rows, mode, out_path):
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["iteration", "verifier", "t_verify_us", "verdict", "mode"])
        for iter_n, verifier, t_us, verdict in rows:
            w.writerow([iter_n, verifier, f"{t_us:.3f}", verdict, mode])
    print(f"\n  wrote {out_path}  ({len(rows)} rows)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=1000,
                    help="Measured iterations per verifier (default 1000)")
    ap.add_argument("--warmup", type=int, default=50,
                    help="Warmup iterations discarded before measurement")
    ap.add_argument("--mode", choices=["auto", "python", "sgx"], default="auto")
    ap.add_argument("--skip-simple", action="store_true")
    ap.add_argument("--skip-full", action="store_true")
    ap.add_argument("--output", default=None,
                    help="Output CSV path (default: results_<mode>.csv in cwd)")
    args = ap.parse_args()

    mode = detect_mode() if args.mode == "auto" else args.mode
    print("=" * 72)
    print(f"  DCAP Verification Overhead Microbenchmark")
    print(f"  Mode        : {mode.upper()}")
    print(f"  Iterations  : {args.iters} measured  (+ {args.warmup} warmup)")
    print(f"  Inputs dir  : {INPUTS_DIR}")
    print("=" * 72)

    if not os.path.exists(QUOTE_PATH) or not os.path.exists(COLLATERAL_PATH):
        sys.exit(
            "Inputs missing. Run prepare_inputs.py first:\n"
            "  python3 prepare_inputs.py --tdx-host <CVM_IP>"
        )

    quote_bytes, nonce, collateral = load_inputs()
    print(f"  quote       : {len(quote_bytes):,} bytes")
    print(f"  nonce       : {'<set>' if nonce else '<none>'}")
    print(f"  collateral  : FMSPC={collateral.fmspc}  cached={collateral.cached}")

    all_rows = []

    if not args.skip_simple:
        print("\n[warmup] simple verifier ...")
        warmup(run_simple, quote_bytes, nonce, collateral, args.warmup)
        all_rows += bench(run_simple, "simple",
                          quote_bytes, nonce, collateral, args.iters)

    if not args.skip_full:
        print("\n[warmup] full verifier ...")
        warmup(run_full, quote_bytes, nonce, collateral, args.warmup)
        all_rows += bench(run_full, "full",
                          quote_bytes, nonce, collateral, args.iters)

    out = args.output
    if out is None:
        out = os.path.join(THIS_DIR, f"results_{mode}.csv")
        # Inside Gramine, the script directory may be mounted as trusted
        # (read-only). Fall back to /tmp and print a copy-out hint.
        try:
            with open(out, "a"):
                pass
        except (PermissionError, OSError):
            out = f"/tmp/results_{mode}.csv"
            print(f"  (script dir read-only inside enclave — writing to {out})")
    write_csv(all_rows, mode, out)

    summary = {
        "mode": mode,
        "iters": args.iters,
        "warmup": args.warmup,
        "python_version": sys.version.split()[0],
        "in_enclave": mode == "sgx",
        "per_verifier": {},
    }
    for verifier in ("simple", "full"):
        times = [r[2] for r in all_rows if r[1] == verifier]
        if times:
            summary["per_verifier"][verifier] = {
                "n": len(times),
                "min_us": min(times),
                "mean_us": statistics.mean(times),
                "p50_us": statistics.median(times),
                "p95_us": sorted(times)[int(0.95 * len(times))],
                "p99_us": sorted(times)[int(0.99 * len(times))],
                "max_us": max(times),
                "std_us": statistics.stdev(times) if len(times) > 1 else 0.0,
            }
    summary_path = out.replace(".csv", "_summary.json")
    try:
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"  wrote {summary_path}")
    except (PermissionError, OSError):
        pass


if __name__ == "__main__":
    main()
