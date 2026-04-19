#!/usr/bin/env python3
"""
Step 1 of the DCAP Verification Overhead microbenchmark.

Run ONCE on a host that can reach:
  (a) the TDX CVM attestation agent (to obtain a real TDX quote), and
  (b) a PCCS endpoint or Intel PCS (to fetch verification collateral).

Outputs everything the benchmark needs to `inputs/`:
  - sample_quote.bin        Raw TDX quote bytes
  - sample_nonce.txt        Base64 nonce used when generating the quote
  - collateral/             Pickled CollateralBundle (TCB info, QE identity,
                            PCK CRL, root CA CRL, issuer chains)

After this script finishes, the benchmark itself reads only from disk and
requires NO network.
"""

import argparse
import base64
import os
import pickle
import socket
import ssl
import sys
import json
import time

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
RESEARCH_DIR = os.path.dirname(THIS_DIR)

sys.path.insert(0, os.path.join(RESEARCH_DIR, "sgx-tdx-attestation"))
sys.path.insert(0, os.path.join(RESEARCH_DIR, "tdx-dcap-attestation"))

from common.protocol import (
    AttestationRequest, AttestationResponse,
    generate_nonce, create_tls_context_client,
    send_message, receive_message,
    DEFAULT_PORT, METHOD_DCAP, MESSAGE_DELIMITER,
)
from quote_parser import parse_quote
from collateral_fetcher import fetch_collateral


INPUTS_DIR = os.path.join(THIS_DIR, "inputs")
QUOTE_PATH = os.path.join(INPUTS_DIR, "sample_quote.bin")
NONCE_PATH = os.path.join(INPUTS_DIR, "sample_nonce.txt")
COLLATERAL_PATH = os.path.join(INPUTS_DIR, "collateral.pkl")
METADATA_PATH = os.path.join(INPUTS_DIR, "metadata.json")


def fetch_quote_from_cvm(host, port, ca_cert, verify_cert):
    nonce = generate_nonce()
    ctx = create_tls_context_client(ca_cert_file=ca_cert, verify=verify_cert)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(60)
    tls = ctx.wrap_socket(sock, server_hostname=host)
    tls.connect((host, port))
    try:
        req = AttestationRequest(
            nonce=nonce, attestation_method=METHOD_DCAP, ima_offset=0,
        )
        payload = req.to_json().encode("utf-8") + MESSAGE_DELIMITER
        tls.sendall(payload)
        resp_json = receive_message(tls)
    finally:
        tls.close()

    resp = AttestationResponse.from_json(resp_json)
    if not resp.raw_quote:
        raise RuntimeError("CVM did not return raw_quote")
    quote_bytes = base64.b64decode(resp.raw_quote)
    return quote_bytes, nonce


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tdx-host", help="CVM attestation agent host")
    ap.add_argument("--tdx-port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--ca-cert", default=None)
    ap.add_argument("--no-verify", action="store_true")
    ap.add_argument("--quote-file",
                    help="Skip CVM fetch; use this pre-existing quote file")
    ap.add_argument("--force-refresh", action="store_true",
                    help="Re-fetch collateral even if cached")
    args = ap.parse_args()

    os.makedirs(INPUTS_DIR, exist_ok=True)

    if args.quote_file:
        print(f"[1/3] Reading quote from {args.quote_file} ...")
        with open(args.quote_file, "rb") as f:
            quote_bytes = f.read()
        nonce = None
    else:
        if not args.tdx_host:
            sys.exit("Need --tdx-host or --quote-file")
        print(f"[1/3] Fetching TDX quote from {args.tdx_host}:{args.tdx_port} ...")
        t0 = time.perf_counter()
        quote_bytes, nonce = fetch_quote_from_cvm(
            args.tdx_host, args.tdx_port, args.ca_cert, not args.no_verify,
        )
        print(f"      ✓ Got quote: {len(quote_bytes)} bytes "
              f"in {(time.perf_counter()-t0)*1000:.1f} ms")

    with open(QUOTE_PATH, "wb") as f:
        f.write(quote_bytes)
    if nonce:
        with open(NONCE_PATH, "w") as f:
            f.write(nonce)
    print(f"      → saved {QUOTE_PATH}")

    print("[2/3] Parsing quote to extract FMSPC ...")
    quote = parse_quote(quote_bytes)
    fmspc = quote.fmspc if hasattr(quote, "fmspc") else None
    if not fmspc:
        sig = quote.signature_data
        fmspc = sig.fmspc if hasattr(sig, "fmspc") else None
    if not fmspc:
        from quote_parser import extract_fmspc_from_pck_cert
        fmspc = extract_fmspc_from_pck_cert(quote.pck_cert_chain_pem)
    print(f"      ✓ FMSPC = {fmspc}")

    print(f"[3/3] Fetching collateral from PCS/PCCS for FMSPC={fmspc} ...")
    t0 = time.perf_counter()
    collateral = fetch_collateral(
        fmspc=fmspc, force_refresh=args.force_refresh, verbose=True,
    )
    fetch_ms = (time.perf_counter() - t0) * 1000
    print(f"      ✓ Collateral fetched/loaded in {fetch_ms:.1f} ms "
          f"(cached={collateral.cached})")

    with open(COLLATERAL_PATH, "wb") as f:
        pickle.dump(collateral, f)
    print(f"      → saved {COLLATERAL_PATH}")

    metadata = {
        "quote_bytes": len(quote_bytes),
        "fmspc": fmspc,
        "collateral_fetch_ms": fetch_ms,
        "collateral_cached": collateral.cached,
        "prepared_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)

    print("\nReady. Inputs dir:")
    for p in (QUOTE_PATH, NONCE_PATH, COLLATERAL_PATH, METADATA_PATH):
        if os.path.exists(p):
            print(f"  {os.path.relpath(p, THIS_DIR)}  ({os.path.getsize(p):,} bytes)")


if __name__ == "__main__":
    main()
