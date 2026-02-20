#!/usr/bin/env python3
"""
TDX Quote Generator — Pure DCAP (No Intel Trust Authority)

Generates TDX quotes directly from hardware using two methods:
  1. configfs-tsm: /sys/kernel/config/tsm/report (full quote, needs QGS)
  2. ioctl: /dev/tdx_guest TDX_CMD_GET_REPORT0 (TDREPORT only, always available)

Usage:
    sudo python3 quote_generator.py [--report-data <hex_string>] [--method auto|configfs|ioctl]
"""

import os
import sys
import struct
import fcntl
import hashlib
import secrets
import time
import tempfile
from dataclasses import dataclass
from typing import Optional, Tuple


# ─── Constants from linux/tdx-guest.h ─────────────────────────────────────────

TDX_REPORTDATA_LEN = 64
TDX_REPORT_LEN = 1024

# ioctl number: _IOWR('T', 1, struct tdx_report_req)
# 'T' = 0x54, nr = 1, size = 64 + 1024 = 1088
# _IOWR = direction bits (read|write) = 0xC0000000 on x86_64
# Formula: direction(2) << 30 | size(14) << 16 | type(8) << 8 | nr(8)
_IOC_WRITE = 1
_IOC_READ = 2
_IOC_TYPE = ord('T')
_IOC_NR = 1
_IOC_SIZE = TDX_REPORTDATA_LEN + TDX_REPORT_LEN  # 1088

TDX_CMD_GET_REPORT0 = (
    ((_IOC_WRITE | _IOC_READ) << 30) |
    (_IOC_SIZE << 16) |
    (_IOC_TYPE << 8) |
    _IOC_NR
)

# Paths
TDX_GUEST_DEV = "/dev/tdx_guest"
CONFIGFS_TSM_REPORT = "/sys/kernel/config/tsm/report"


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class TDReport:
    """Parsed TDX TDREPORT structure (1024 bytes total)."""
    # Report MAC structure (256 bytes)
    report_type: bytes       # 4 bytes
    reserved1: bytes         # 12 bytes
    cpusvn: bytes            # 16 bytes - CPU SVN
    tee_tcb_info_hash: bytes # 48 bytes
    tee_info_hash: bytes     # 48 bytes
    report_data: bytes       # 64 bytes - user-supplied data (nonce)
    reserved2: bytes         # 32 bytes
    mac: bytes               # 32 bytes - MAC over report

    # TEE TCB Info (239 bytes)
    valid: bytes             # 8 bytes
    tee_tcb_svn: bytes       # 16 bytes
    mrseam: bytes            # 48 bytes - Measurement of SEAM module
    mrsigner_seam: bytes     # 48 bytes - Signer of SEAM module
    seam_attributes: bytes   # 8 bytes
    td_attributes: bytes     # 8 bytes
    xfam: bytes              # 8 bytes
    mrtd: bytes              # 48 bytes - Measurement of TD
    mrconfigid: bytes        # 48 bytes
    mrowner: bytes           # 48 bytes
    mrownerconfig: bytes     # 48 bytes
    rtmr0: bytes             # 48 bytes - Runtime measurement register 0
    rtmr1: bytes             # 48 bytes - Runtime measurement register 1
    rtmr2: bytes             # 48 bytes - Runtime measurement register 2
    rtmr3: bytes             # 48 bytes - Runtime measurement register 3
    servtd_hash: bytes       # 48 bytes

    raw: bytes = b""         # Full raw TDREPORT bytes


@dataclass
class TDXQuote:
    """Container for a generated TDX Quote."""
    raw_quote: bytes         # Full binary quote
    report_data_used: bytes  # The 64-byte report_data that was used
    method: str              # "configfs" or "ioctl"
    generation_time_ms: float


@dataclass
class GeneratedReport:
    """Container for a generated TDREPORT (ioctl method)."""
    tdreport: TDReport
    report_data_used: bytes
    generation_time_ms: float


# ─── TDREPORT Parser ──────────────────────────────────────────────────────────

def parse_tdreport(raw: bytes) -> TDReport:
    """
    Parse a 1024-byte TDREPORT into its constituent fields.

    Layout based on Intel TDX Module v1.5 ABI Specification:
      - REPORTMACSTRUCT: 256 bytes (offset 0)
      - TEE_TCB_INFO:    256 bytes (offset 256), including reserved padding
      - TDINFO:          512 bytes (offset 512)
    """
    if len(raw) < TDX_REPORT_LEN:
        raise ValueError(f"TDREPORT too short: {len(raw)} < {TDX_REPORT_LEN}")

    offset = 0

    def read(n):
        nonlocal offset
        data = raw[offset:offset + n]
        offset += n
        return data

    def skip(n):
        nonlocal offset
        offset += n

    # ─── REPORTMACSTRUCT (256 bytes, offset 0-255) ───────────────────────
    report_type = read(4)       # 0:   4 bytes
    reserved1 = read(12)        # 4:  12 bytes
    cpusvn = read(16)           # 16: 16 bytes
    tee_tcb_info_hash = read(48)# 32: 48 bytes
    tee_info_hash = read(48)    # 80: 48 bytes
    report_data = read(64)      # 128: 64 bytes
    reserved2 = read(32)        # 192: 32 bytes
    mac = read(32)              # 224: 32 bytes
    # Total: 256 bytes (offset now = 256)

    # ─── TEE_TCB_INFO (256 bytes, offset 256-511) ────────────────────────
    valid = read(8)             # 256:  8 bytes
    tee_tcb_svn = read(16)      # 264: 16 bytes
    mrseam = read(48)           # 280: 48 bytes
    mrsigner_seam = read(48)    # 328: 48 bytes
    seam_attributes = read(8)   # 376:  8 bytes
    skip(128)                   # 384: 128 bytes (TEE_TCB_SVN2 + reserved, pad to 512)
    # Total read: 128 + 128 = 256 bytes (offset now = 512)

    # ─── TDINFO (512 bytes, offset 512-1023) ─────────────────────────────
    td_attributes = read(8)     # 512:  8 bytes
    xfam = read(8)              # 520:  8 bytes
    mrtd = read(48)             # 528: 48 bytes
    mrconfigid = read(48)       # 576: 48 bytes
    mrowner = read(48)          # 624: 48 bytes
    mrownerconfig = read(48)    # 672: 48 bytes
    rtmr0 = read(48)            # 720: 48 bytes
    rtmr1 = read(48)            # 768: 48 bytes
    rtmr2 = read(48)            # 816: 48 bytes
    rtmr3 = read(48)            # 864: 48 bytes
    servtd_hash = read(48)      # 912: 48 bytes
    # Remaining 64 bytes are reserved (offset 960-1023)

    return TDReport(
        report_type=report_type,
        reserved1=reserved1,
        cpusvn=cpusvn,
        tee_tcb_info_hash=tee_tcb_info_hash,
        tee_info_hash=tee_info_hash,
        report_data=report_data,
        reserved2=reserved2,
        mac=mac,
        valid=valid,
        tee_tcb_svn=tee_tcb_svn,
        mrseam=mrseam,
        mrsigner_seam=mrsigner_seam,
        seam_attributes=seam_attributes,
        td_attributes=td_attributes,
        xfam=xfam,
        mrtd=mrtd,
        mrconfigid=mrconfigid,
        mrowner=mrowner,
        mrownerconfig=mrownerconfig,
        rtmr0=rtmr0,
        rtmr1=rtmr1,
        rtmr2=rtmr2,
        rtmr3=rtmr3,
        servtd_hash=servtd_hash,
        raw=raw,
    )


# ─── Quote Generation Methods ────────────────────────────────────────────────

def generate_report_data(nonce: Optional[bytes] = None) -> bytes:
    """
    Create 64-byte report_data from an optional nonce.

    If nonce is provided and <= 64 bytes, it's zero-padded to 64 bytes.
    If nonce is > 64 bytes, it's SHA-384 hashed and zero-padded to 64 bytes.
    If no nonce, generates 64 random bytes.
    """
    if nonce is None:
        return secrets.token_bytes(TDX_REPORTDATA_LEN)

    if len(nonce) <= TDX_REPORTDATA_LEN:
        return nonce.ljust(TDX_REPORTDATA_LEN, b'\x00')
    else:
        # Hash if too long
        h = hashlib.sha384(nonce).digest()
        return h.ljust(TDX_REPORTDATA_LEN, b'\x00')


def generate_tdreport_ioctl(report_data: bytes) -> GeneratedReport:
    """
    Generate a TDREPORT using the /dev/tdx_guest ioctl interface.

    This produces a TDREPORT (locally verifiable via MAC), NOT a remotely
    verifiable Quote. Useful for reading measurements without needing QGS.

    Requires root or appropriate device permissions.
    """
    if len(report_data) != TDX_REPORTDATA_LEN:
        raise ValueError(f"report_data must be {TDX_REPORTDATA_LEN} bytes, got {len(report_data)}")

    if not os.path.exists(TDX_GUEST_DEV):
        raise RuntimeError(f"TDX device not found: {TDX_GUEST_DEV}")

    # Prepare the struct: 64 bytes reportdata + 1024 bytes tdreport buffer
    req = bytearray(report_data + b'\x00' * TDX_REPORT_LEN)

    start = time.time()

    fd = os.open(TDX_GUEST_DEV, os.O_RDWR)
    try:
        # Perform ioctl
        fcntl.ioctl(fd, TDX_CMD_GET_REPORT0, req)
    finally:
        os.close(fd)

    elapsed_ms = (time.time() - start) * 1000

    # Extract TDREPORT from the response (after the 64-byte reportdata)
    tdreport_raw = bytes(req[TDX_REPORTDATA_LEN:])
    tdreport = parse_tdreport(tdreport_raw)

    return GeneratedReport(
        tdreport=tdreport,
        report_data_used=report_data,
        generation_time_ms=elapsed_ms,
    )


def generate_quote_configfs(report_data: bytes, timeout: float = 30.0) -> TDXQuote:
    """
    Generate a full TDX Quote using the configfs-tsm interface.

    This requires the QGS (Quote Generation Service) to be running on the host.
    The kernel's configfs-tsm module forwards the request to QGS, which uses
    the Quoting Enclave to sign the TDREPORT and produce a full Quote.

    Steps:
      1. mkdir /sys/kernel/config/tsm/report/<name>
      2. Write report_data to inblob
      3. Read the quote from outblob
      4. rmdir the report directory

    Requires root.
    """
    if len(report_data) != TDX_REPORTDATA_LEN:
        raise ValueError(f"report_data must be {TDX_REPORTDATA_LEN} bytes, got {len(report_data)}")

    if not os.path.isdir(CONFIGFS_TSM_REPORT):
        raise RuntimeError(f"configfs-tsm not available: {CONFIGFS_TSM_REPORT}")

    report_name = f"dcap_{os.getpid()}_{int(time.time() * 1000)}"
    report_dir = os.path.join(CONFIGFS_TSM_REPORT, report_name)

    start = time.time()

    try:
        # Create report directory
        os.makedirs(report_dir, exist_ok=False)

        # Write report_data (64 bytes) to inblob
        inblob_path = os.path.join(report_dir, "inblob")
        with open(inblob_path, 'wb') as f:
            f.write(report_data)

        # Read provider to confirm TDX
        provider_path = os.path.join(report_dir, "provider")
        try:
            with open(provider_path, 'r') as f:
                provider = f.read().strip()
            if provider and "tdx" not in provider.lower():
                print(f"  Warning: Provider is '{provider}', expected 'tdx_guest'")
        except (FileNotFoundError, PermissionError):
            pass

        # Read the quote from outblob (this blocks until QGS responds)
        outblob_path = os.path.join(report_dir, "outblob")

        # Use a non-blocking approach with timeout
        import signal

        def timeout_handler(signum, frame):
            raise TimeoutError(f"Quote generation timed out after {timeout}s (is QGS running?)")

        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(int(timeout))

        try:
            with open(outblob_path, 'rb') as f:
                quote_bytes = f.read()
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

        if not quote_bytes:
            raise RuntimeError("Empty quote received from configfs-tsm")

        elapsed_ms = (time.time() - start) * 1000

        return TDXQuote(
            raw_quote=quote_bytes,
            report_data_used=report_data,
            method="configfs",
            generation_time_ms=elapsed_ms,
        )

    finally:
        # Cleanup: remove the report directory
        try:
            os.rmdir(report_dir)
        except OSError:
            pass


def is_configfs_available() -> bool:
    """Check if configfs-tsm quote generation is available."""
    return os.path.isdir(CONFIGFS_TSM_REPORT)


def is_ioctl_available() -> bool:
    """Check if /dev/tdx_guest ioctl is available."""
    return os.path.exists(TDX_GUEST_DEV)


def generate_quote(report_data: Optional[bytes] = None,
                   method: str = "auto",
                   timeout: float = 10.0) -> Tuple[Optional[TDXQuote], Optional[GeneratedReport]]:
    """
    Generate a TDX quote or report using the best available method.

    Args:
        report_data: 64-byte report data (nonce). Auto-generated if None.
        method: "auto", "configfs", or "ioctl"
        timeout: Timeout for configfs-tsm quote generation

    Returns:
        Tuple of (TDXQuote or None, GeneratedReport or None)
        - If configfs works: (TDXQuote, None)
        - If falls back to ioctl: (None, GeneratedReport)
    """
    if report_data is None:
        report_data = generate_report_data()
    elif len(report_data) != TDX_REPORTDATA_LEN:
        report_data = generate_report_data(report_data)

    if method == "configfs" or (method == "auto" and is_configfs_available()):
        try:
            quote = generate_quote_configfs(report_data, timeout=timeout)
            return quote, None
        except (TimeoutError, RuntimeError) as e:
            if method == "configfs":
                raise
            print(f"  configfs-tsm failed ({e}), falling back to ioctl...")

    if method == "ioctl" or method == "auto":
        if not is_ioctl_available():
            raise RuntimeError("No TDX quote generation method available")
        report = generate_tdreport_ioctl(report_data)
        return None, report

    raise ValueError(f"Unknown method: {method}")


# ─── Display Helpers ──────────────────────────────────────────────────────────

def print_tdreport(report: TDReport, verbose: bool = False):
    """Print TDREPORT in a human-readable format."""
    print("\n" + "=" * 70)
    print("TDX TDREPORT")
    print("=" * 70)

    print(f"\n  Measurements:")
    print(f"    MRTD:          {report.mrtd.hex()}")
    print(f"    RTMR[0]:       {report.rtmr0.hex()}")
    print(f"    RTMR[1]:       {report.rtmr1.hex()}")
    print(f"    RTMR[2]:       {report.rtmr2.hex()}")
    print(f"    RTMR[3]:       {report.rtmr3.hex()}")

    print(f"\n  Security:")
    print(f"    Report Data:   {report.report_data.hex()[:64]}...")
    print(f"    CPUSVN:        {report.cpusvn.hex()}")
    print(f"    TEE TCB SVN:   {report.tee_tcb_svn.hex()}")

    # Parse TD attributes
    attr_val = int.from_bytes(report.td_attributes, 'little')
    is_debug = bool(attr_val & 1)
    print(f"\n  Attributes:")
    print(f"    TD Attributes: {report.td_attributes.hex()} (debug={is_debug})")
    print(f"    XFAM:          {report.xfam.hex()}")

    if verbose:
        print(f"\n  SEAM:")
        print(f"    MRSEAM:            {report.mrseam.hex()}")
        print(f"    MRSIGNER_SEAM:     {report.mrsigner_seam.hex()}")
        print(f"    SEAM Attributes:   {report.seam_attributes.hex()}")
        print(f"\n  Configuration:")
        print(f"    MRCONFIGID:        {report.mrconfigid.hex()}")
        print(f"    MROWNER:           {report.mrowner.hex()}")
        print(f"    MROWNERCONFIG:     {report.mrownerconfig.hex()}")
        print(f"    SERVTD Hash:       {report.servtd_hash.hex()}")
        print(f"    MAC:               {report.mac.hex()}")

    print("=" * 70)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="TDX Quote/Report Generator (DCAP)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--report-data", type=str, default=None,
                        help="Hex-encoded report data (nonce). Auto-generated if omitted.")
    parser.add_argument("--method", choices=["auto", "configfs", "ioctl"],
                        default="auto", help="Quote generation method")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Timeout for configfs-tsm (seconds)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--save-quote", type=str, default=None,
                        help="Save raw quote to file")
    parser.add_argument("--save-report", type=str, default=None,
                        help="Save raw TDREPORT to file")

    args = parser.parse_args()

    print("=" * 70)
    print("TDX DCAP Quote/Report Generator")
    print("=" * 70)

    # Check available methods
    print(f"\n  Available methods:")
    print(f"    /dev/tdx_guest (ioctl):     {'✓' if is_ioctl_available() else '✗'}")
    print(f"    configfs-tsm:               {'✓' if is_configfs_available() else '✗'}")

    # Prepare report data
    if args.report_data:
        rd = bytes.fromhex(args.report_data)
        report_data = generate_report_data(rd)
    else:
        report_data = generate_report_data()

    print(f"\n  Report data:  {report_data.hex()[:32]}...")
    print(f"  Method:       {args.method}")

    # Generate
    print(f"\n  Generating...")
    try:
        quote, report = generate_quote(
            report_data=report_data,
            method=args.method,
            timeout=args.timeout
        )
    except Exception as e:
        print(f"\n  ✗ Error: {e}")
        sys.exit(1)

    if quote:
        print(f"\n  ✓ Full TDX Quote generated ({len(quote.raw_quote)} bytes, "
              f"{quote.generation_time_ms:.1f}ms)")
        print(f"    Method: {quote.method}")
        if args.save_quote:
            with open(args.save_quote, 'wb') as f:
                f.write(quote.raw_quote)
            print(f"    Saved to: {args.save_quote}")

    if report:
        print(f"\n  ✓ TDREPORT generated ({TDX_REPORT_LEN} bytes, "
              f"{report.generation_time_ms:.1f}ms)")
        print(f"    Note: TDREPORT is NOT remotely verifiable (no QGS/QE signature)")
        print_tdreport(report.tdreport, verbose=args.verbose)
        if args.save_report:
            with open(args.save_report, 'wb') as f:
                f.write(report.tdreport.raw)
            print(f"    Saved to: {args.save_report}")


if __name__ == "__main__":
    main()
