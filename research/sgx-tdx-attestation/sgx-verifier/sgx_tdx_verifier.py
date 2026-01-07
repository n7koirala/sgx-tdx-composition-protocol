#!/usr/bin/env python3
"""
SGX Enclave TDX Verifier

This program runs inside an SGX enclave (via Gramine) and acts as the
"owner" or verifier of a TDX VM. It implements the hierarchical attestation
protocol where SGX attests TDX.

Protocol Flow:
    1. Generate cryptographic nonce
    2. Connect to TDX attestation server over TLS
    3. Send attestation challenge with nonce
    4. Receive TDX attestation token (JWT)
    5. Verify token:
       - Issuer is Intel Trust Authority
       - Token not expired
       - Nonce is bound in report_data
    6. Output verification verdict

Usage (inside SGX enclave):
    gramine-sgx ./verifier sgx_tdx_verifier.py --tdx-host <TDX_IP> [options]

Options:
    --tdx-host HOST     TDX server hostname/IP (required)
    --tdx-port PORT     TDX server port (default: 8443)
    --ca-cert FILE      CA certificate for TLS verification
    --no-verify         Skip TLS certificate verification
    --test-network      Test network connectivity only
    --verbose           Enable verbose output
"""

import sys
import os
import socket
import ssl
import argparse
import time
import json
from datetime import datetime

# Add parent directory to path for common module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import (
    AttestationRequest, AttestationResponse, VerificationResult,
    generate_nonce, verify_nonce_binding, verify_jwt_simple, decode_jwt_payload,
    create_tls_context_client, send_message, receive_message,
    DEFAULT_PORT, PROTOCOL_VERSION, ProtocolError
)


class SGXTDXVerifier:
    """
    SGX Enclave-based TDX attestation verifier.
    
    Connects to TDX attestation server, challenges it with a nonce,
    and verifies the returned attestation token.
    """
    
    def __init__(self, tdx_host: str, tdx_port: int,
                 ca_cert: str = None, verify_cert: bool = True,
                 verbose: bool = False):
        self.tdx_host = tdx_host
        self.tdx_port = tdx_port
        self.ca_cert = ca_cert
        self.verify_cert = verify_cert
        self.verbose = verbose
    
    def log(self, msg: str):
        """Log message if verbose mode enabled"""
        if self.verbose:
            print(f"[DEBUG] {msg}")
    
    def attest_tdx(self) -> VerificationResult:
        """
        Perform TDX attestation and verification.
        
        Returns:
            VerificationResult with verdict and details
        """
        result = VerificationResult()
        start_time = time.time()
        
        try:
            # Step 1: Generate nonce
            self.log("Generating nonce...")
            nonce = generate_nonce()
            self.log(f"Nonce: {nonce[:16]}...")
            
            # Step 2: Create TLS connection
            self.log(f"Connecting to {self.tdx_host}:{self.tdx_port}...")
            tls_context = create_tls_context_client(
                ca_cert_file=self.ca_cert,
                verify=self.verify_cert
            )
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            
            tls_sock = tls_context.wrap_socket(sock, server_hostname=self.tdx_host)
            tls_sock.connect((self.tdx_host, self.tdx_port))
            self.log("TLS connection established")
            
            try:
                # Step 3: Send attestation request
                request = AttestationRequest(nonce=nonce)
                self.log("Sending attestation request...")
                send_message(tls_sock, request.to_json())
                
                # Step 4: Receive response
                self.log("Waiting for response...")
                response_json = receive_message(tls_sock)
                response = AttestationResponse.from_json(response_json)
                
                if response.status != "success":
                    result.error = f"TDX server error: {response.error}"
                    result.verdict = "ERROR"
                    return result
                
                self.log(f"Received token ({len(response.token)} bytes)")
                
                # Step 5: Verify token
                result = self._verify_token(response.token, nonce)
                result.mrtd = response.mrtd
                
            finally:
                tls_sock.close()
        
        except socket.timeout:
            result.error = "Connection timeout"
            result.verdict = "ERROR"
        except ssl.SSLError as e:
            result.error = f"TLS error: {e}"
            result.verdict = "ERROR"
        except ConnectionRefusedError:
            result.error = f"Connection refused to {self.tdx_host}:{self.tdx_port}"
            result.verdict = "ERROR"
        except ProtocolError as e:
            result.error = f"Protocol error: {e}"
            result.verdict = "ERROR"
        except Exception as e:
            result.error = str(e)
            result.verdict = "ERROR"
        
        result.verification_time_ms = (time.time() - start_time) * 1000
        return result
    
    def _verify_token(self, token: str, expected_nonce: str) -> VerificationResult:
        """
        Verify the TDX attestation token.
        
        Checks:
        1. JWT issuer (Intel Trust Authority)
        2. Token expiry
        3. Nonce binding in report_data
        """
        result = VerificationResult()
        
        # Verify JWT structure, issuer, and expiry
        self.log("Verifying JWT issuer and expiry...")
        valid, payload, error = verify_jwt_simple(token)
        
        if not valid:
            result.error = error
            result.verdict = "UNTRUSTED"
            return result
        
        result.issuer_verified = True
        result.expiry_verified = True
        
        # Extract TDX claims
        if 'tdx' not in payload:
            result.error = "No TDX claims in token"
            result.verdict = "UNTRUSTED"
            return result
        
        tdx = payload['tdx']
        result.mrtd = tdx.get('tdx_mrtd', '')
        result.tcb_status = tdx.get('attester_tcb_status', '')
        result.is_debuggable = tdx.get('tdx_is_debuggable', False)
        
        # Verify nonce binding
        self.log("Verifying nonce binding...")
        report_data = tdx.get('tdx_report_data', '')
        result.nonce_verified = verify_nonce_binding(expected_nonce, report_data, debug=self.verbose)
        
        if not result.nonce_verified:
            result.error = "Nonce not properly bound in report_data"
            result.verdict = "UNTRUSTED"
            result.warnings.append("Possible replay attack or binding failure")
            return result
        
        # Add warnings for concerning states
        if result.is_debuggable:
            result.warnings.append("TD is debuggable - not for production!")
        
        if result.tcb_status not in ("UpToDate", "SWHardeningNeeded"):
            result.warnings.append(f"TCB status: {result.tcb_status}")
        
        # All checks passed
        result.verified = True
        result.verdict = "TRUSTED"
        
        return result
    
    def test_network(self) -> bool:
        """Test network connectivity to TDX server"""
        print(f"Testing connection to {self.tdx_host}:{self.tdx_port}...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.tdx_host, self.tdx_port))
            sock.close()
            print("  ✓ TCP connection successful")
            
            # Test TLS
            tls_context = create_tls_context_client(
                ca_cert_file=self.ca_cert,
                verify=self.verify_cert
            )
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            tls_sock = tls_context.wrap_socket(sock, server_hostname=self.tdx_host)
            tls_sock.connect((self.tdx_host, self.tdx_port))
            
            cipher = tls_sock.cipher()
            print(f"  ✓ TLS handshake successful")
            print(f"    Cipher: {cipher[0] if cipher else 'unknown'}")
            
            tls_sock.close()
            return True
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
            return False


def check_enclave_environment():
    """Check if running inside Gramine SGX enclave"""
    attestation_dir = "/dev/attestation"
    
    if os.path.exists(attestation_dir):
        print("✓ Running inside Gramine SGX enclave")
        
        # Read attestation type
        try:
            with open(os.path.join(attestation_dir, "attestation_type"), "r") as f:
                att_type = f.read().strip()
            print(f"  Attestation type: {att_type}")
        except:
            pass
        
        return True
    else:
        print("⚠ Running outside enclave (development mode)")
        return False


def print_banner():
    """Print startup banner"""
    print("=" * 70)
    print("SGX Enclave TDX Verifier")
    print("Hierarchical TEE Attestation Protocol")
    print("=" * 70)


def print_result(result: VerificationResult):
    """Print verification result"""
    print("\n" + "=" * 70)
    print("VERIFICATION RESULT")
    print("=" * 70)
    
    # Verdict with color indication
    if result.verdict == "TRUSTED":
        print(f"\n  ✓ Verdict: {result.verdict}")
    elif result.verdict == "UNTRUSTED":
        print(f"\n  ✗ Verdict: {result.verdict}")
    else:
        print(f"\n  ? Verdict: {result.verdict}")
    
    if result.error:
        print(f"  Error: {result.error}")
    
    print(f"\n  Time: {result.verification_time_ms:.1f} ms")
    
    print("\n  Checks:")
    print(f"    Issuer:  {'✓' if result.issuer_verified else '✗'}")
    print(f"    Expiry:  {'✓' if result.expiry_verified else '✗'}")
    print(f"    Nonce:   {'✓' if result.nonce_verified else '✗'}")
    
    if result.mrtd:
        print(f"\n  TDX Measurements:")
        print(f"    MRTD:       {result.mrtd[:48]}...")
        print(f"    TCB Status: {result.tcb_status}")
        print(f"    Debuggable: {result.is_debuggable}")
    
    if result.warnings:
        print("\n  Warnings:")
        for warning in result.warnings:
            print(f"    ⚠ {warning}")
    
    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="SGX Enclave TDX Verifier",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--tdx-host", required=True,
                       help="TDX attestation server hostname/IP")
    parser.add_argument("--tdx-port", type=int, default=DEFAULT_PORT,
                       help=f"TDX server port (default: {DEFAULT_PORT})")
    parser.add_argument("--ca-cert",
                       help="CA certificate for TLS verification")
    parser.add_argument("--no-verify", action="store_true",
                       help="Skip TLS certificate verification")
    parser.add_argument("--test-network", action="store_true",
                       help="Test network connectivity only")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose output")
    parser.add_argument("--json", action="store_true",
                       help="Output result as JSON")
    
    args = parser.parse_args()
    
    print_banner()
    
    # Check environment
    in_enclave = check_enclave_environment()
    print(f"Protocol Version: {PROTOCOL_VERSION}")
    print()
    
    # Resolve CA cert path
    ca_cert = None
    if args.ca_cert:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        ca_cert = os.path.join(script_dir, args.ca_cert) if not os.path.isabs(args.ca_cert) else args.ca_cert
    
    # Create verifier
    verifier = SGXTDXVerifier(
        tdx_host=args.tdx_host,
        tdx_port=args.tdx_port,
        ca_cert=ca_cert,
        verify_cert=not args.no_verify,
        verbose=args.verbose
    )
    
    if args.test_network:
        success = verifier.test_network()
        sys.exit(0 if success else 1)
    
    # Perform attestation
    print(f"Attesting TDX server at {args.tdx_host}:{args.tdx_port}...")
    result = verifier.attest_tdx()
    
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_result(result)
    
    # Exit code based on verdict
    if result.verdict == "TRUSTED":
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
