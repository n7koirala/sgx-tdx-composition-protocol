#!/usr/bin/env python3
"""
End-User Client for Multi-Controller Attestation

Connects to one (or more) SGX controllers to verify a TDX VM.
Supports automatic failover across multiple controllers.

Usage:
    # Single controller
    python3 end_user_client.py --controller-host <SGX_IP> --controller-port 9001

    # Multiple controllers (failover)
    python3 end_user_client.py --controllers <IP>:9001,<IP>:9002,<IP>:9003

    # JSON output
    python3 end_user_client.py --controller-host <IP> --controller-port 9001 --json
"""

import sys
import os
import socket
import ssl
import argparse
import json
import time
from datetime import datetime

# Add parent directory to path for common module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import (
    EndUserRequest, ControllerToken,
    generate_nonce, send_message, receive_message,
    create_tls_context_client, ProtocolError,
    PROTOCOL_VERSION
)


def verify_controller(host: str, port: int, ca_cert: str = None,
                      verify_cert: bool = True, verbose: bool = False) -> ControllerToken:
    """
    Connect to a single SGX controller and get a ControllerToken.
    
    Args:
        host: Controller hostname/IP
        port: Controller port
        ca_cert: CA certificate for TLS
        verify_cert: Whether to verify TLS cert
        verbose: Debug output
    
    Returns:
        ControllerToken from the controller
    """
    # Generate fresh nonce
    nonce = generate_nonce()
    if verbose:
        print(f"[DEBUG] Nonce: {nonce[:16]}...")
    
    # Create TLS connection
    tls_context = create_tls_context_client(
        ca_cert_file=ca_cert,
        verify=verify_cert
    )
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    tls_sock = tls_context.wrap_socket(sock, server_hostname=host)
    tls_sock.connect((host, port))
    
    if verbose:
        print(f"[DEBUG] Connected to {host}:{port}")
    
    try:
        # Send request
        request = EndUserRequest(nonce=nonce)
        send_message(tls_sock, request.to_json())
        
        # Receive token
        response_json = receive_message(tls_sock)
        token = ControllerToken.from_json(response_json)
        
        # Basic validation
        if token.nonce_echo != nonce:
            token.warnings.append("Nonce echo mismatch — possible relay attack")
        
        return token
    finally:
        tls_sock.close()


def try_controllers(controllers: list, ca_cert: str = None,
                    verify_cert: bool = True, verbose: bool = False) -> ControllerToken:
    """
    Try multiple controllers until one succeeds.
    
    Args:
        controllers: List of (host, port) tuples
        ca_cert, verify_cert, verbose: Passed to verify_controller
    
    Returns:
        ControllerToken from first successful controller
    """
    errors = []
    
    for i, (host, port) in enumerate(controllers):
        try:
            if verbose:
                print(f"\n[{i+1}/{len(controllers)}] Trying controller at {host}:{port}...")
            
            token = verify_controller(host, port, ca_cert, verify_cert, verbose)
            
            if len(controllers) > 1:
                print(f"  → Connected to controller #{i+1} ({host}:{port})")
            
            return token
            
        except Exception as e:
            errors.append(f"{host}:{port} — {e}")
            if verbose:
                print(f"  ✗ Failed: {e}")
    
    # All failed
    error_msg = "All controllers unreachable:\n" + "\n".join(f"  - {e}" for e in errors)
    return ControllerToken.error_response(error_msg)


def print_result(token: ControllerToken):
    """Print the verification result in a human-readable format."""
    print("\n" + "=" * 70)
    print("ATTESTATION RESULT")
    print("=" * 70)
    
    # Verdict
    if token.tdx_verdict == "TRUSTED":
        print(f"\n  ✓ Verdict: {token.tdx_verdict}")
    elif token.tdx_verdict == "UNTRUSTED":
        print(f"\n  ✗ Verdict: {token.tdx_verdict}")
    else:
        print(f"\n  ? Verdict: {token.tdx_verdict}")
    
    if token.error:
        print(f"  Error: {token.error}")
    
    # Controller info
    print(f"\n  Controller: {token.controller_id} (port {token.controller_port})")
    
    # Nonce binding
    nonce_ok = "✓" if token.nonce_echo else "✗"
    print(f"  Nonce bound:  {nonce_ok}")
    if token.nonce_hash:
        print(f"  Nonce hash:   {token.nonce_hash[:24]}...")
    
    # TDX info
    if token.tdx_mrtd:
        print(f"\n  TDX Machine:")
        print(f"    Method:     {token.tdx_attestation_method.upper()}")
        print(f"    MRTD:       {token.tdx_mrtd[:48]}...")
        print(f"    TCB Status: {token.tdx_tcb_status}")
        print(f"    Debuggable: {token.tdx_is_debuggable}")
        print(f"    Quote hash: {token.tdx_quote_hash}")
    
    # Freshness
    if token.tdx_verification_time > 0:
        staleness = time.time() - token.tdx_verification_time
        ts = datetime.fromtimestamp(token.tdx_verification_time).strftime("%H:%M:%S")
        print(f"\n  Freshness:")
        print(f"    Last verified: {ts} ({staleness:.1f}s ago)")
    
    # Warnings
    if token.warnings:
        print(f"\n  Warnings:")
        for w in token.warnings:
            print(f"    ⚠ {w}")
    
    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="End-User Client for Multi-Controller TDX Attestation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Controller target (single)
    parser.add_argument("--controller-host",
                        help="Controller hostname/IP (for single controller)")
    parser.add_argument("--controller-port", type=int, default=DEFAULT_CONTROLLER_PORT,
                        help=f"Controller port (default: {DEFAULT_CONTROLLER_PORT})")
    
    # Controller target (multiple, comma-separated)
    parser.add_argument("--controllers",
                        help="Comma-separated controller list, e.g. host1:9001,host2:9002")
    
    # TLS
    parser.add_argument("--ca-cert",
                        help="CA certificate for TLS verification")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip TLS certificate verification")
    
    # Output
    parser.add_argument("--json", action="store_true",
                        help="Output result as JSON")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Build controller list
    controllers = []
    
    if args.controllers:
        for entry in args.controllers.split(","):
            entry = entry.strip()
            if ":" in entry:
                host, port = entry.rsplit(":", 1)
                controllers.append((host, int(port)))
            else:
                controllers.append((entry, DEFAULT_CONTROLLER_PORT))
    elif args.controller_host:
        controllers.append((args.controller_host, args.controller_port))
    else:
        parser.error("Specify --controller-host or --controllers")
    
    # Resolve CA cert
    ca_cert = None
    if args.ca_cert:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        ca_cert = os.path.join(script_dir, args.ca_cert) if not os.path.isabs(args.ca_cert) else args.ca_cert
    
    # Banner
    print("=" * 70)
    print("End-User TDX Attestation Client")
    print("=" * 70)
    print(f"Controllers: {', '.join(f'{h}:{p}' for h, p in controllers)}")
    print(f"Protocol:    {PROTOCOL_VERSION}")
    print()
    
    # Try controllers
    start = time.time()
    
    if len(controllers) > 1:
        print(f"Trying {len(controllers)} controllers for fault tolerance...")
        token = try_controllers(controllers, ca_cert, not args.no_verify, args.verbose)
    else:
        host, port = controllers[0]
        print(f"Connecting to controller at {host}:{port}...")
        try:
            token = verify_controller(host, port, ca_cert, not args.no_verify, args.verbose)
        except Exception as e:
            token = ControllerToken.error_response(str(e))
    
    elapsed = (time.time() - start) * 1000
    
    # Output
    if args.json:
        result = token.to_dict()
        result["client_elapsed_ms"] = elapsed
        print(json.dumps(result, indent=2))
    else:
        print_result(token)
        print(f"  Client round-trip: {elapsed:.1f}ms\n")
    
    # Exit code
    sys.exit(0 if token.tdx_verdict == "TRUSTED" else 1)


# Import controller port default
from common.protocol import DEFAULT_PORT
DEFAULT_CONTROLLER_PORT = 9001


if __name__ == "__main__":
    main()
