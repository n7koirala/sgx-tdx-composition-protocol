#!/usr/bin/env python3
"""
TDX DCAP Attestation — End-to-End Local Attestation

Performs complete TDX attestation without Intel Trust Authority:
  1. Generate TDX Quote (hardware)
  2. Parse binary quote
  3. Fetch verification collateral (Intel PCS, cached)
  4. Verify quote locally (signature, cert chain, TCB, CRL)
  5. Output detailed verification result

Usage:
    sudo python3 dcap_attestation.py [options]

Options:
    --report-data HEX    Custom report data (nonce) in hex
    --report-only        Only generate and display TDREPORT (no quote/verification)
    --method METHOD      Quote generation: auto, configfs, ioctl
    --cache-dir DIR      Collateral cache directory
    --force-refresh      Force re-fetch collateral from Intel PCS
    --save-quote FILE    Save raw quote to file
    --verbose            Verbose output
    --json               Output as JSON

Examples:
    # Full DCAP attestation with auto nonce
    sudo python3 dcap_attestation.py --verbose

    # With custom nonce
    sudo python3 dcap_attestation.py --report-data $(openssl rand -hex 32) --verbose

    # TDREPORT only (no QGS needed)
    sudo python3 dcap_attestation.py --report-only --verbose

    # Save quote for offline verification
    sudo python3 dcap_attestation.py --save-quote quote.bin --verbose
"""

import os
import sys
import json
import time
import secrets
import argparse
from datetime import datetime

# Import local modules
from quote_generator import (
    generate_quote, generate_report_data, generate_tdreport_ioctl,
    print_tdreport, is_configfs_available, is_ioctl_available,
    TDX_REPORTDATA_LEN
)
from quote_parser import parse_quote, print_parsed_quote
from collateral_fetcher import (
    fetch_collateral, extract_fmspc_from_pck_cert,
    DEFAULT_CACHE_DIR
)
from dcap_verifier import (
    verify_quote, print_verification_result
)


def print_banner():
    """Print startup banner."""
    print("=" * 70)
    print("TDX DCAP Attestation")
    print("Pure Local Verification — No Intel Trust Authority")
    print("=" * 70)
    print(f"  Time:     {datetime.now().isoformat()}")
    print(f"  Host:     {os.uname().nodename}")
    print(f"  Kernel:   {os.uname().release}")
    print(f"  ioctl:    {'✓' if is_ioctl_available() else '✗'} /dev/tdx_guest")
    print(f"  configfs: {'✓' if is_configfs_available() else '✗'} configfs-tsm")


def do_report_only(report_data: bytes, verbose: bool = False):
    """Generate and display a TDREPORT (no full quote needed)."""
    print("\n" + "-" * 70)
    print("MODE: TDREPORT Only (no QGS required)")
    print("-" * 70)

    print(f"\n  Generating TDREPORT via /dev/tdx_guest ioctl...")
    report = generate_tdreport_ioctl(report_data)

    print(f"  ✓ TDREPORT generated in {report.generation_time_ms:.1f}ms")
    print_tdreport(report.tdreport, verbose=verbose)

    print(f"\n  Note: TDREPORT is MAC-authenticated (platform-local only).")
    print(f"  For remote verification, a full TDX Quote is needed (requires QGS).")

    return report


def do_full_attestation(report_data: bytes,
                        method: str = "auto",
                        cache_dir: str = DEFAULT_CACHE_DIR,
                        force_refresh: bool = False,
                        save_quote: str = None,
                        verbose: bool = False,
                        as_json: bool = False):
    """Perform full DCAP attestation: quote generation + verification."""
    print("\n" + "-" * 70)
    print("MODE: Full DCAP Attestation")
    print("-" * 70)

    # ─── Step 1: Generate Quote ───────────────────────────────────────────
    print(f"\n  [Step 1] Generating TDX Quote...")
    print(f"           Report data: {report_data.hex()[:32]}...")
    print(f"           Method: {method}")

    quote_obj, report_obj = generate_quote(
        report_data=report_data,
        method=method,
        timeout=10.0
    )

    if quote_obj:
        quote_bytes = quote_obj.raw_quote
        print(f"           ✓ Full quote generated ({len(quote_bytes)} bytes, "
              f"{quote_obj.generation_time_ms:.1f}ms)")

        if save_quote:
            with open(save_quote, 'wb') as f:
                f.write(quote_bytes)
            print(f"           Saved to: {save_quote}")
    elif report_obj:
        print(f"           ⚠ Only TDREPORT available (no QGS for full quote)")
        print(f"           TDREPORT generated in {report_obj.generation_time_ms:.1f}ms")
        print_tdreport(report_obj.tdreport, verbose=verbose)

        print(f"\n  Cannot perform full DCAP verification without a Quote.")
        print(f"  To enable full quote generation, install QGS:")
        print(f"    sudo bash setup_dcap.sh")
        return report_obj

    # ─── Step 2: Parse Quote ──────────────────────────────────────────────
    print(f"\n  [Step 2] Parsing quote...")

    parsed = parse_quote(quote_bytes)

    if verbose:
        print_parsed_quote(parsed, verbose=True)
    else:
        print(f"           ✓ Quote parsed (v{parsed.header.version}, "
              f"{parsed.header.tee_type_str})")
        print(f"           MRTD: {parsed.body.mrtd.hex()}")

    # ─── Step 3: Extract FMSPC and Fetch Collateral ───────────────────────
    print(f"\n  [Step 3] Fetching verification collateral...")

    fmspc = None
    if parsed.pck_cert_chain_pem:
        fmspc = extract_fmspc_from_pck_cert(parsed.pck_cert_chain_pem)

    if fmspc:
        print(f"           FMSPC: {fmspc}")
    else:
        # Try common FMSPC values for GCP TDX
        fmspc = "00806F050000"
        print(f"           FMSPC: {fmspc} (default)")

    collateral = fetch_collateral(
        fmspc=fmspc,
        cache_dir=cache_dir,
        force_refresh=force_refresh,
        verbose=verbose,
    )

    print(f"           ✓ Collateral {'loaded from cache' if collateral.cached else 'fetched from Intel PCS'}")

    # ─── Step 4: Verify Quote ─────────────────────────────────────────────
    print(f"\n  [Step 4] Verifying quote (all local)...")

    result = verify_quote(
        quote_bytes=quote_bytes,
        collateral=collateral,
        expected_report_data=report_data,
        verbose=verbose,
    )

    result.fmspc = fmspc

    # ─── Output ───────────────────────────────────────────────────────────
    if as_json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_verification_result(result)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="TDX DCAP Attestation — Local Verification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument("--report-data", type=str, default=None,
                        help="Hex-encoded report data (nonce). Auto-generated if omitted.")
    parser.add_argument("--report-only", action="store_true",
                        help="Only generate TDREPORT (no quote, no verification)")
    parser.add_argument("--method", choices=["auto", "configfs", "ioctl"],
                        default="auto", help="Quote generation method")
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR,
                        help="Collateral cache directory")
    parser.add_argument("--force-refresh", action="store_true",
                        help="Force re-fetch collateral from Intel PCS")
    parser.add_argument("--save-quote", type=str, default=None,
                        help="Save raw quote to file")
    parser.add_argument("--verify-quote", type=str, default=None,
                        help="Verify an existing quote file (offline mode)")
    parser.add_argument("--fmspc", type=str, default=None,
                        help="FMSPC for collateral fetch (auto-detected if not set)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")

    args = parser.parse_args()

    print_banner()

    # Prepare report data
    if args.report_data:
        rd_bytes = bytes.fromhex(args.report_data)
        report_data = generate_report_data(rd_bytes)
    else:
        report_data = generate_report_data()

    # ─── Mode: Verify existing quote ──────────────────────────────────────
    if args.verify_quote:
        print(f"\n  Verifying existing quote: {args.verify_quote}")

        with open(args.verify_quote, 'rb') as f:
            quote_bytes = f.read()

        parsed = parse_quote(quote_bytes)
        if args.verbose:
            print_parsed_quote(parsed, verbose=True)

        fmspc = args.fmspc
        if not fmspc and parsed.pck_cert_chain_pem:
            fmspc = extract_fmspc_from_pck_cert(parsed.pck_cert_chain_pem)
        if not fmspc:
            fmspc = "00806F050000"

        collateral = fetch_collateral(
            fmspc=fmspc,
            cache_dir=args.cache_dir,
            force_refresh=args.force_refresh,
            verbose=args.verbose,
        )

        result = verify_quote(
            quote_bytes=quote_bytes,
            collateral=collateral,
            expected_report_data=None,  # Can't verify nonce for saved quotes
            verbose=args.verbose,
        )
        result.fmspc = fmspc

        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print_verification_result(result)

        sys.exit(0 if result.verdict == "TRUSTED" else 1)

    # ─── Mode: Report only ────────────────────────────────────────────────
    if args.report_only:
        do_report_only(report_data, verbose=args.verbose)
        sys.exit(0)

    # ─── Mode: Full attestation ───────────────────────────────────────────
    result = do_full_attestation(
        report_data=report_data,
        method=args.method,
        cache_dir=args.cache_dir,
        force_refresh=args.force_refresh,
        save_quote=args.save_quote,
        verbose=args.verbose,
        as_json=args.json,
    )

    # Exit code based on verdict
    if hasattr(result, 'verdict'):
        sys.exit(0 if result.verdict == "TRUSTED" else 1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
