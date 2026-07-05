#!/usr/bin/env python3
"""
WEN-side verifier for the isolated IMA -> RTMR[3] anchoring experiment.

The verifier connects to cvm_rtmr3_agent.py, receives a nonce-bound TDX quote
plus the binary IMA log, then checks:

  1. DCAP quote signature and nonce binding.
  2. MRTD and RTMR[0..2] against an optional golden file.
  3. Replayed IMA binary log -> expected RTMR[3] against quoted RTMR[3].
  4. Replayed IMA binary log -> PCR-10 SHA-1 against the CVM vTPM PCR value.

The default RTMR[3] base mode is "auto", which uses the base RTMR[3] value
reported by the test agent at startup.  That validates the mechanics even if
the current CVM already had RTMR[3] extended by an earlier probe.  For a strict
security test, boot a fresh CVM and pass --expected-rtmr3-base zero or a known
48-byte golden base.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from typing import Dict, Tuple

sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sgx-tdx-attestation"),
)

from common.protocol import (  # type: ignore
    DEFAULT_PORT,
    METHOD_DCAP,
    create_tls_context_client,
    generate_nonce,
    parse_dcap_quote,
    receive_message,
    send_message,
    verify_dcap_quote,
)

from ima_rtmr3_common import (
    ZERO_RTMR_SHA384,
    hex_to_48,
    load_json_file,
    binary_ascii_template_hash_match,
    count_ascii_ima_entries,
    parse_ima_binary_log,
    find_pcr10_sha256_prefix,
    replay_pcr10_sha1,
    replay_pcr10_sha1_ascii,
    replay_pcr10_sha256_binary,
    replay_rtmr3,
    write_json_file,
)
from vtpm_quote import verify_pcr10_quote, rtmr_extend


TEST_PROTOCOL_VERSION = "ima-rtmr3-test-v1"


def request_attestation(
    host: str,
    port: int,
    verify_cert: bool,
    ca_cert: str | None,
    timeout: float,
) -> Tuple[str, dict, float]:
    nonce = generate_nonce()
    ctx = create_tls_context_client(ca_cert_file=ca_cert, verify=verify_cert)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    tls = ctx.wrap_socket(sock, server_hostname=host)

    t0 = time.perf_counter()
    tls.connect((host, port))
    try:
        send_message(
            tls,
            json.dumps(
                {
                    "action": "attest",
                    "protocol": TEST_PROTOCOL_VERSION,
                    "nonce": nonce,
                }
            ),
        )
        response_json = receive_message(tls)
    finally:
        tls.close()

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return nonce, json.loads(response_json), elapsed_ms


def resolve_rtmr3_base(mode: str, response: dict) -> Tuple[bytes, str]:
    mode = mode.strip().lower()
    if mode == "auto":
        base_hex = response.get("anchor", {}).get("rtmr3_base_before_start", "")
        if not base_hex:
            raise ValueError("agent response did not include rtmr3_base_before_start")
        return hex_to_48(base_hex), "agent-reported startup base"
    if mode == "zero":
        return ZERO_RTMR_SHA384, "zero"
    return hex_to_48(mode), "explicit CLI value"


def compare_golden(info, golden: Dict[str, str]) -> Tuple[bool, list]:
    checks = []
    ok = True
    for key in ("mrtd", "rtmr0", "rtmr1", "rtmr2"):
        expected = golden.get(key)
        actual = getattr(info, key)
        if not expected:
            checks.append((key, "SKIP", actual, "missing in golden file"))
            continue
        matched = expected.lower() == actual.lower()
        ok = ok and matched
        checks.append((key, "OK" if matched else "MISMATCH", actual, expected))
    return ok, checks


def save_golden(path: str, info, rtmr3_base_hex: str) -> None:
    data = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "note": "Golden boot values for ima_rtmr3_test. RTMR3 base is test-specific.",
        "mrtd": info.mrtd,
        "rtmr0": info.rtmr0,
        "rtmr1": info.rtmr1,
        "rtmr2": info.rtmr2,
        "rtmr3_base": rtmr3_base_hex,
    }
    write_json_file(path, data)


def short(value: str, chars: int = 24) -> str:
    if not value:
        return "<empty>"
    if len(value) <= chars:
        return value
    return value[:chars] + "..."


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WEN verifier for IMA -> RTMR[3] test protocol",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--tdx-host", required=True)
    parser.add_argument("--tdx-port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--ca-cert")
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument(
        "--expected-rtmr3-base",
        default="auto",
        help="'auto', 'zero', or an explicit 96-hex-char SHA-384 RTMR base",
    )
    parser.add_argument("--golden-file", help="JSON with expected mrtd/rtmr0/rtmr1/rtmr2")
    parser.add_argument("--save-golden", help="Write observed mrtd/rtmr0/rtmr1/rtmr2 to JSON")
    parser.add_argument("--require-golden", action="store_true")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable summary")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    verify_cert = not args.no_verify

    nonce, response, elapsed_ms = request_attestation(
        args.tdx_host,
        args.tdx_port,
        verify_cert=verify_cert,
        ca_cert=args.ca_cert,
        timeout=args.timeout,
    )

    if response.get("status") != "success":
        print(json.dumps(response, indent=2))
        sys.exit(2)

    quote_bytes = base64.b64decode(response["raw_quote"])
    quote_result = verify_dcap_quote(quote_bytes, nonce, debug=args.verbose)
    quote_info = parse_dcap_quote(quote_bytes)

    ima_blob = base64.b64decode(response["ima_binary_log_b64"])
    entries = parse_ima_binary_log(ima_blob)
    ima_ascii_b64 = response.get("ima_ascii_log_b64", "")
    ima_ascii_log = (
        base64.b64decode(ima_ascii_b64).decode("utf-8", errors="replace")
        if ima_ascii_b64 else ""
    )
    ascii_entry_count = count_ascii_ima_entries(ima_ascii_log) if ima_ascii_log else 0
    binary_ascii_count_match = bool(ima_ascii_log) and ascii_entry_count == len(entries)
    binary_ascii_hash_match = (
        binary_ascii_template_hash_match(entries, ima_ascii_log)
        if ima_ascii_log else False
    )

    rtmr3_base, rtmr3_base_source = resolve_rtmr3_base(
        args.expected_rtmr3_base,
        response,
    )

    nonce_bytes = base64.b64decode(nonce)
    vtpm = verify_pcr10_quote(response, nonce_bytes)
    anchor = response.get("anchor", {})
    anchor_ak_sha384 = anchor.get("ak_pub_sha384", "").strip().lower()
    ak_bind_consistent = vtpm.ak_sha384 == anchor_ak_sha384

    ak_digest = bytes.fromhex(vtpm.ak_sha384)
    base_after_ak = rtmr_extend(rtmr3_base, ak_digest)
    reported_after_ak = anchor.get("rtmr3_after_ak_bind", "").strip().lower()
    ak_bind_rtmr3_match = bool(reported_after_ak) and reported_after_ak == base_after_ak.hex()

    expected_rtmr3 = replay_rtmr3(entries, base=base_after_ak).hex()
    quoted_rtmr3 = quote_info.rtmr3.lower()
    rtmr3_match = expected_rtmr3 == quoted_rtmr3

    pcr_sha1_source = "ascii" if ima_ascii_log else "binary"
    pcr_sha1_result = (
        replay_pcr10_sha1_ascii(ima_ascii_log)
        if ima_ascii_log else replay_pcr10_sha1(entries)
    )
    claimed_pcr10_sha1 = response.get("pcr10_sha1", "").strip().lower()
    pcr10_sha1_match = bool(claimed_pcr10_sha1) and pcr_sha1_result.pcr_hex == claimed_pcr10_sha1

    pcr_sha256_result = replay_pcr10_sha256_binary(entries)
    claimed_pcr10_sha256 = response.get("pcr10_sha256", "").strip().lower()
    pcr10_sha256_match = bool(claimed_pcr10_sha256) and pcr_sha256_result.pcr_hex == claimed_pcr10_sha256

    quoted_pcr10 = vtpm.quoted_pcr10
    pcr10_prefix_count, pcr10_prefix_result = find_pcr10_sha256_prefix(
        entries,
        quoted_pcr10,
    )
    reported_prefix_count = response.get("snapshot", {}).get("vtpm_ima_prefix_entries")
    pcr10_prefix_count_match = (
        reported_prefix_count is None
        or reported_prefix_count == pcr10_prefix_count
    )
    replayed_pcr10 = (
        pcr10_prefix_result.pcr_hex
        if pcr10_prefix_count is not None else pcr_sha256_result.pcr_hex
    )
    pcr10_signed_match = vtpm.ok and pcr10_prefix_count is not None
    pcr10_match = pcr10_signed_match
    pcr_source = (
        f"vtpm/sha256-prefix/{pcr10_prefix_count}"
        if pcr10_signed_match else "none"
    )

    golden_loaded = False
    golden_ok = True
    golden_checks = []
    if args.golden_file:
        golden = load_json_file(args.golden_file)
        golden_loaded = True
        golden_ok, golden_checks = compare_golden(quote_info, golden)
    elif args.require_golden:
        golden_ok = False

    if args.save_golden:
        save_golden(args.save_golden, quote_info, rtmr3_base.hex())

    quote_ok = bool(quote_result.verified)
    snapshot = response.get("snapshot", {})
    snapshot_ok = bool(snapshot.get("consistent", True))
    count_stable = bool(snapshot.get("count_stable", snapshot_ok))
    post_quote_drift = int(snapshot.get("post_quote_drift", 0) or 0)
    overall_ok = (
        quote_ok
        and rtmr3_match
        and pcr10_signed_match
        and pcr10_prefix_count_match
        and ak_bind_consistent
        and vtpm.cert_binds_ak
        and golden_ok
        and snapshot_ok
        and binary_ascii_count_match
    )

    summary = {
        "ok": overall_ok,
        "quote_ok": quote_ok,
        "quote_verdict": quote_result.verdict,
        "rtmr3_match": rtmr3_match,
        "pcr10_match": pcr10_match,
        "snapshot_consistent": snapshot_ok,
        "snapshot_count_stable": count_stable,
        "snapshot_post_quote_drift": post_quote_drift,
        "snapshot": snapshot,
        "golden_ok": golden_ok,
        "golden_loaded": golden_loaded,
        "ima_entries": len(entries),
        "ima_ascii_entries": ascii_entry_count,
        "binary_ascii_count_match": binary_ascii_count_match,
        "binary_ascii_hash_match": binary_ascii_hash_match,
        "ima_count_kernel": response.get("ima_count_kernel"),
        "anchored_count": response.get("anchor", {}).get("anchored_count"),
        "rtmr3_base_source": rtmr3_base_source,
        "rtmr3_base": rtmr3_base.hex(),
        "expected_rtmr3": expected_rtmr3,
        "quoted_rtmr3": quoted_rtmr3,
        "agent_rtmr3_current": response.get("anchor", {}).get("rtmr3_current", ""),
        "pcr10_source": pcr_source,
        "pcr10_signed_match": pcr10_signed_match,
        "vtpm_signature_ok": vtpm.signature_ok,
        "vtpm_nonce_ok": vtpm.nonce_ok,
        "vtpm_cert_binds_ak": vtpm.cert_binds_ak,
        "vtpm_detail": vtpm.detail,
        "vtpm_quoted_pcr10_sha256": quoted_pcr10,
        "replayed_pcr10_sha256": replayed_pcr10,
        "pcr10_prefix_entries": pcr10_prefix_count,
        "reported_pcr10_prefix_entries": reported_prefix_count,
        "pcr10_prefix_count_match": pcr10_prefix_count_match,
        "full_replayed_pcr10_sha256": pcr_sha256_result.pcr_hex,
        "ak_pub_sha384": vtpm.ak_sha384,
        "anchor_ak_pub_sha384": anchor_ak_sha384,
        "ak_bind_consistent": ak_bind_consistent,
        "ak_bind_rtmr3_match": ak_bind_rtmr3_match,
        "rtmr3_after_ak_bind": base_after_ak.hex(),
        "agent_rtmr3_after_ak_bind": reported_after_ak,
        "pcr10_sha1_match_debug": pcr10_sha1_match,
        "expected_pcr10_sha1": pcr_sha1_result.pcr_hex,
        "claimed_pcr10_sha1": claimed_pcr10_sha1,
        "pcr10_sha256_match_debug": pcr10_sha256_match,
        "expected_pcr10_sha256": pcr_sha256_result.pcr_hex,
        "claimed_pcr10_sha256": claimed_pcr10_sha256,
        "pcr10_entries": pcr_sha1_result.entry_count,
        "pcr10_skipped": pcr_sha1_result.skipped_count,
        "mrtd": quote_info.mrtd,
        "rtmr0": quote_info.rtmr0,
        "rtmr1": quote_info.rtmr1,
        "rtmr2": quote_info.rtmr2,
        "elapsed_ms": round(elapsed_ms, 3),
        "server_timing": response.get("_server_timing", {}),
        "saved_golden": args.save_golden or "",
    }

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print("=" * 72)
        print("WEN IMA -> RTMR[3] Verification Result")
        print("=" * 72)
        print(f"Target:             {args.tdx_host}:{args.tdx_port}")
        print(f"Protocol:           {response.get('protocol')}")
        print(f"Quote verdict:      {quote_result.verdict}")
        print(f"Quote signature:    {'OK' if quote_result.signature_verified else 'FAIL'}")
        print(f"Nonce binding:      {'OK' if quote_result.nonce_verified else 'FAIL'}")
        print()
        print("Boot measurements:")
        print(f"  MRTD:             {short(quote_info.mrtd, 48)}")
        print(f"  RTMR[0]:          {short(quote_info.rtmr0, 48)}")
        print(f"  RTMR[1]:          {short(quote_info.rtmr1, 48)}")
        print(f"  RTMR[2]:          {short(quote_info.rtmr2, 48)}")
        if args.golden_file:
            print(f"  Golden file:      {args.golden_file}")
            for key, status, actual, expected in golden_checks:
                if status == "OK":
                    print(f"    {key}: OK")
                elif status == "SKIP":
                    print(f"    {key}: SKIP ({expected})")
                else:
                    print(f"    {key}: MISMATCH actual={short(actual)} expected={short(expected)}")
        elif args.require_golden:
            print("  Golden file:      MISSING (required)")
        else:
            print("  Golden file:      not provided; MRTD/RTMR0-2 are reported only")
        print()
        print("IMA -> RTMR[3] anchor:")
        print(f"  IMA entries:      {len(entries):,} binary, {ascii_entry_count:,} ASCII")
        print(f"  Binary/ASCII ct:  {'OK' if binary_ascii_count_match else 'MISMATCH'}")
        print(f"  Binary/ASCII dig: {'OK' if binary_ascii_hash_match else 'MISMATCH'}")
        print(f"  Agent anchored:   {summary['anchored_count']}")
        print(f"  RTMR3 base:       {short(rtmr3_base.hex(), 48)} ({rtmr3_base_source})")
        print(f"  AK SHA384:        {short(vtpm.ak_sha384, 48)}")
        print(f"  AK bind field:    {'OK' if ak_bind_consistent else 'MISMATCH'}")
        print(f"  After AK bind:    {short(base_after_ak.hex(), 48)}")
        print(f"  Agent after AK:   {short(reported_after_ak, 48)}")
        print(f"  AK RTMR step:     {'OK' if ak_bind_rtmr3_match else 'MISMATCH'}")
        print(f"  Expected RTMR3:   {short(expected_rtmr3, 48)}")
        print(f"  Quoted RTMR3:     {short(quoted_rtmr3, 48)}")
        print(f"  RTMR3 check:      {'OK' if rtmr3_match else 'MISMATCH'}")
        if snapshot:
            print(f"  Snapshot input:   {'OK' if snapshot_ok else 'MISMATCH'} "
                  f"(attempt={snapshot.get('attempt')}, "
                  f"entries={snapshot.get('ima_entries')}, "
                  f"before={snapshot.get('ima_count_before')}, "
                  f"after={snapshot.get('ima_count_after')})")
            if post_quote_drift:
                print(f"  Post-quote drift: {post_quote_drift} new IMA entr"
                      f"{'y' if post_quote_drift == 1 else 'ies'} after evidence capture")
        print()
        print("Signed vTPM PCR-10 quote:")
        print(f"  Quote bank:       {response.get('vtpm_quote_bank', '<missing>')}")
        print(f"  Signature/nonce:  {'OK' if vtpm.signature_ok and vtpm.nonce_ok else 'FAIL'}")
        print(f"  Cert binds AK:    {'OK' if vtpm.cert_binds_ak else 'FAIL'}")
        if vtpm.detail:
            print(f"  Detail:           {vtpm.detail}")
        print(f"  Quoted PCR10:     {quoted_pcr10 or '<missing>'}")
        print(f"  Replayed PCR10:   {replayed_pcr10}")
        print(f"  PCR10 prefix:     {pcr10_prefix_count if pcr10_prefix_count is not None else '<none>'} entries")
        if reported_prefix_count is not None:
            print(f"  Agent prefix:     {reported_prefix_count} entries "
                  f"({'OK' if pcr10_prefix_count_match else 'MISMATCH'})")
        print(f"  PCR10 signed:     {'OK' if pcr10_signed_match else 'MISMATCH'}")
        print()
        print("PCR-10 debug fields:")
        print(f"  PCR10 source:     {pcr_source}")
        print(f"  SHA-1 entries:    {pcr_sha1_result.entry_count:,} ({pcr_sha1_source})")
        print(f"  SHA-1 expected:   {pcr_sha1_result.pcr_hex}")
        print(f"  SHA-1 claimed:    {claimed_pcr10_sha1 or '<missing>'}")
        print(f"  SHA-1 check:      {'OK' if pcr10_sha1_match else 'MISMATCH'}")
        print(f"  SHA-256 expected: {pcr_sha256_result.pcr_hex}")
        print(f"  SHA-256 claimed:  {claimed_pcr10_sha256 or '<missing>'}")
        print(f"  SHA-256 check:    {'OK' if pcr10_sha256_match else 'MISMATCH'}")
        print(f"  PCR10 check:      {'OK' if pcr10_match else 'MISMATCH'}")
        print()
        if args.save_golden:
            print(f"Saved golden file:  {args.save_golden}")
        print(f"Overall:            {'OK' if overall_ok else 'FAIL'}")
        print("=" * 72)

    sys.exit(0 if overall_ok else 1)


if __name__ == "__main__":
    main()
