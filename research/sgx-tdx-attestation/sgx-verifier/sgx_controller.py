#!/usr/bin/env python3
"""
SGX Multi-Controller — Scalable TDX Attestation Service

This program runs inside an SGX enclave and acts as one of N independent
controllers that verify a TDX VM. Each controller:

  1. Periodically re-attests the TDX VM (background thread)
  2. Caches the latest TDX verification result
  3. Listens for end-user attestation requests
  4. Returns a ControllerToken with cached TDX info + SGX identity

Multiple controllers provide:
  - High availability (no single point of failure)
  - Horizontal scalability (any controller can serve any end-user)
  - Independent verification (each controller verifies TDX independently)

Usage:
    python3 sgx_controller.py --port 9001 --tdx-host <TDX_IP> --method dcap \\
                              --controller-id ctrl-1 --refresh-interval 30

    # Run multiple controllers on different ports:
    python3 sgx_controller.py --port 9001 --tdx-host <IP> --controller-id ctrl-1 &
    python3 sgx_controller.py --port 9002 --tdx-host <IP> --controller-id ctrl-2 &
    python3 sgx_controller.py --port 9003 --tdx-host <IP> --controller-id ctrl-3 &
"""

import sys
import os
import socket
import ssl
import argparse
import json
import base64
import time
import hashlib
import threading
from datetime import datetime

# Add parent directory to path for common module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import (
    AttestationRequest, AttestationResponse, VerificationResult,
    EndUserRequest, ControllerToken,
    generate_nonce, verify_dcap_quote,
    create_tls_context_server, create_tls_context_client,
    send_message, receive_message,
    DEFAULT_PORT, PROTOCOL_VERSION, ProtocolError,
    METHOD_ITA, METHOD_DCAP, VALID_METHODS
)

# Reuse the verifier logic
from sgx_tdx_verifier import SGXTDXVerifier


# ─── Controller defaults ─────────────────────────────────────────────────────
DEFAULT_CONTROLLER_PORT = 9001
DEFAULT_REFRESH_INTERVAL = 30  # seconds


class SGXController:
    """
    SGX Enclave-based multi-controller for TDX attestation.
    
    Runs as a long-lived server that:
    1. Periodically verifies TDX in the background
    2. Caches verification results
    3. Serves end-user requests with cached TDX + SGX identity
    """
    
    def __init__(self, controller_id: str, port: int,
                 tdx_host: str, tdx_port: int,
                 method: str = METHOD_DCAP,
                 cert_file: str = None, key_file: str = None,
                 ca_cert: str = None, verify_tdx_cert: bool = True,
                 refresh_interval: int = DEFAULT_REFRESH_INTERVAL,
                 verbose: bool = False):
        self.controller_id = controller_id
        self.port = port
        self.tdx_host = tdx_host
        self.tdx_port = tdx_port
        self.method = method
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_cert = ca_cert
        self.verify_tdx_cert = verify_tdx_cert
        self.refresh_interval = refresh_interval
        self.verbose = verbose
        self.running = False
        
        # Cached TDX verification state (protected by lock)
        self._lock = threading.Lock()
        self._cached_result: VerificationResult = None
        self._cached_quote_hash: str = ""
        self._last_verification_time: float = 0.0
        self._verification_count: int = 0
        
        # End-user request stats
        self.stats = {
            "requests": 0,
            "served": 0,
            "errors": 0,
            "start_time": datetime.now().isoformat(),
        }
        
        # Create the internal TDX verifier (reuses existing logic)
        self._verifier = SGXTDXVerifier(
            tdx_host=self.tdx_host,
            tdx_port=self.tdx_port,
            ca_cert=self.ca_cert,
            verify_cert=self.verify_tdx_cert,
            verbose=self.verbose,
            method=self.method
        )
    
    def log(self, msg: str):
        if self.verbose:
            print(f"[{self.controller_id}] {msg}")
    
    # ─── Background TDX verification ─────────────────────────────────────
    
    def _verify_tdx_once(self):
        """Perform one TDX attestation and cache the result."""
        self.log("Verifying TDX attestation...")
        start = time.time()
        
        try:
            result = self._verifier.attest_tdx()
            elapsed = (time.time() - start) * 1000
            
            # Compute quote hash for auditability
            # (We don't have the raw quote here — the verifier consumed it.
            #  Use a hash of MRTD + timestamp as a proxy.)
            quote_hash = hashlib.sha256(
                f"{result.mrtd}:{time.time()}".encode()
            ).hexdigest()[:32]
            
            with self._lock:
                self._cached_result = result
                self._cached_quote_hash = quote_hash
                self._last_verification_time = time.time()
                self._verification_count += 1
            
            status_icon = "✓" if result.verified else "✗"
            print(f"[{self.controller_id}] {status_icon} TDX verification #{self._verification_count}: "
                  f"{result.verdict} ({elapsed:.1f}ms)")
            
            if result.mrtd:
                self.log(f"  MRTD: {result.mrtd[:32]}...")
            
        except Exception as e:
            print(f"[{self.controller_id}] ✗ TDX verification failed: {e}")
            with self._lock:
                self._cached_result = VerificationResult(
                    verdict="ERROR", error=str(e)
                )
                self._last_verification_time = time.time()
    
    def _background_verifier(self):
        """Background thread: periodically re-attest TDX."""
        while self.running:
            self._verify_tdx_once()
            
            # Sleep in small intervals so we can stop quickly
            for _ in range(self.refresh_interval * 10):
                if not self.running:
                    return
                time.sleep(0.1)
    
    # ─── End-user request handling ────────────────────────────────────────
    
    def _build_token(self, request: EndUserRequest) -> ControllerToken:
        """Build a ControllerToken from cached TDX state + end-user nonce."""
        with self._lock:
            result = self._cached_result
            quote_hash = self._cached_quote_hash
            verify_time = self._last_verification_time
        
        if result is None:
            return ControllerToken.error_response(
                "TDX not yet verified — controller is still initializing"
            )
        
        # Compute nonce hash (proves we saw the nonce)
        nonce_hash = hashlib.sha256(request.nonce.encode()).hexdigest()
        
        # Build warnings
        warnings = list(result.warnings) if result.warnings else []
        staleness = time.time() - verify_time
        if staleness > self.refresh_interval * 2:
            warnings.append(f"TDX verification is {staleness:.0f}s stale")
        
        token = ControllerToken(
            status="success" if result.verified else "error",
            controller_id=self.controller_id,
            controller_port=self.port,
            tdx_verified=result.verified,
            tdx_verdict=result.verdict,
            tdx_mrtd=result.mrtd,
            tdx_attestation_method=result.attestation_method,
            tdx_verification_time=verify_time,
            tdx_quote_hash=quote_hash,
            tdx_tcb_status=result.tcb_status,
            tdx_is_debuggable=result.is_debuggable,
            nonce_echo=request.nonce,
            nonce_hash=nonce_hash,
            warnings=warnings,
        )
        
        return token
    
    def _handle_client(self, conn: ssl.SSLSocket, addr):
        """Handle a single end-user connection."""
        self.stats["requests"] += 1
        req_num = self.stats["requests"]
        start = time.time()
        
        print(f"\n[{self.controller_id}] Request #{req_num} from {addr[0]}:{addr[1]}")
        
        try:
            # Receive end-user request
            request_json = receive_message(conn)
            request = EndUserRequest.from_json(request_json)
            
            valid, error = request.validate()
            if not valid:
                token = ControllerToken.error_response(error)
                send_message(conn, token.to_json())
                self.stats["errors"] += 1
                return
            
            self.log(f"  Nonce: {request.nonce[:16]}...")
            
            # Build response from cached TDX state
            token = self._build_token(request)
            
            # Send response
            send_message(conn, token.to_json())
            
            elapsed = (time.time() - start) * 1000
            self.stats["served"] += 1
            
            icon = "✓" if token.tdx_verified else "✗"
            print(f"[{self.controller_id}]   {icon} Served: {token.tdx_verdict} ({elapsed:.1f}ms)")
            
        except Exception as e:
            self.stats["errors"] += 1
            print(f"[{self.controller_id}]   ✗ Error: {e}")
            try:
                token = ControllerToken.error_response(str(e))
                send_message(conn, token.to_json())
            except:
                pass
        finally:
            conn.close()
    
    # ─── Server lifecycle ─────────────────────────────────────────────────
    
    def run(self):
        """Start the controller: background verifier + end-user listener."""
        self._print_banner()
        
        # Do initial TDX verification before accepting users
        print(f"[{self.controller_id}] Performing initial TDX verification...")
        self._verify_tdx_once()
        
        if self._cached_result and not self._cached_result.verified:
            print(f"[{self.controller_id}] ⚠ Initial verification: {self._cached_result.verdict}")
            print(f"[{self.controller_id}]   Continuing anyway (will retry in background)")
        
        self.running = True
        
        # Start background verification thread
        bg_thread = threading.Thread(target=self._background_verifier, daemon=True)
        bg_thread.start()
        print(f"[{self.controller_id}] Background verifier started (interval: {self.refresh_interval}s)")
        
        # Create TLS server socket
        tls_context = create_tls_context_server(self.cert_file, self.key_file)
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', self.port))
        server_socket.listen(10)
        server_socket.settimeout(1.0)
        
        tls_socket = tls_context.wrap_socket(server_socket, server_side=True)
        
        print(f"\n[{self.controller_id}] Listening for end-user requests on port {self.port}...")
        print(f"[{self.controller_id}] Press Ctrl+C to stop\n")
        
        try:
            while self.running:
                try:
                    conn, addr = tls_socket.accept()
                    # Handle each client in a thread for concurrency
                    t = threading.Thread(target=self._handle_client, args=(conn, addr))
                    t.daemon = True
                    t.start()
                except socket.timeout:
                    continue
                except ssl.SSLError as e:
                    self.log(f"TLS error: {e}")
                except Exception as e:
                    self.log(f"Error: {e}")
        except KeyboardInterrupt:
            print(f"\n[{self.controller_id}] Shutting down...")
        finally:
            self.running = False
            tls_socket.close()
            self._print_stats()
    
    def _print_banner(self):
        print("=" * 70)
        print(f"SGX Multi-Controller: {self.controller_id}")
        print("=" * 70)
        print(f"Protocol Version:    {PROTOCOL_VERSION}")
        print(f"Controller ID:       {self.controller_id}")
        print(f"Controller Port:     {self.port}")
        print(f"TDX Target:          {self.tdx_host}:{self.tdx_port}")
        print(f"Attestation Method:  {self.method.upper()}")
        print(f"Refresh Interval:    {self.refresh_interval}s")
        print(f"TLS Certificate:     {self.cert_file}")
        print(f"Started:             {self.stats['start_time']}")
        print("=" * 70)
    
    def _print_stats(self):
        print("\n" + "=" * 70)
        print(f"Controller {self.controller_id} Statistics")
        print("=" * 70)
        print(f"End-user requests:    {self.stats['requests']}")
        print(f"Successfully served:  {self.stats['served']}")
        print(f"Errors:               {self.stats['errors']}")
        print(f"TDX verifications:    {self._verification_count}")
        print("=" * 70)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SGX Multi-Controller — Scalable TDX Attestation Service",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Controller settings
    parser.add_argument("--controller-id", default="ctrl-1",
                        help="Unique controller identifier (default: ctrl-1)")
    parser.add_argument("--port", type=int, default=DEFAULT_CONTROLLER_PORT,
                        help=f"Controller port for end-user requests (default: {DEFAULT_CONTROLLER_PORT})")
    parser.add_argument("--refresh-interval", type=int, default=DEFAULT_REFRESH_INTERVAL,
                        help=f"TDX re-attestation interval in seconds (default: {DEFAULT_REFRESH_INTERVAL})")
    
    # TDX server target
    parser.add_argument("--tdx-host", required=True,
                        help="TDX attestation server hostname/IP")
    parser.add_argument("--tdx-port", type=int, default=DEFAULT_PORT,
                        help=f"TDX server port (default: {DEFAULT_PORT})")
    parser.add_argument("--method", choices=[METHOD_ITA, METHOD_DCAP], default=METHOD_DCAP,
                        help=f"Attestation method (default: {METHOD_DCAP})")
    
    # TLS certificates for controller (server-side, for end-users)
    parser.add_argument("--cert", default="../certs/server.crt",
                        help="TLS certificate for controller server")
    parser.add_argument("--key", default="../certs/server.key",
                        help="TLS private key for controller server")
    
    # TLS for TDX connection (client-side)
    parser.add_argument("--ca-cert",
                        help="CA certificate for verifying TDX server")
    parser.add_argument("--no-verify-tdx", action="store_true",
                        help="Skip TLS certificate verification for TDX connection")
    
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Resolve certificate paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cert_file = os.path.join(script_dir, args.cert) if not os.path.isabs(args.cert) else args.cert
    key_file = os.path.join(script_dir, args.key) if not os.path.isabs(args.key) else args.key
    
    ca_cert = None
    if args.ca_cert:
        ca_cert = os.path.join(script_dir, args.ca_cert) if not os.path.isabs(args.ca_cert) else args.ca_cert
    
    try:
        controller = SGXController(
            controller_id=args.controller_id,
            port=args.port,
            tdx_host=args.tdx_host,
            tdx_port=args.tdx_port,
            method=args.method,
            cert_file=cert_file,
            key_file=key_file,
            ca_cert=ca_cert,
            verify_tdx_cert=not args.no_verify_tdx,
            refresh_interval=args.refresh_interval,
            verbose=args.verbose,
        )
        controller.run()
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
