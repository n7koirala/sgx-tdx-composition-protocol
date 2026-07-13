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
    4. Receive TDX attestation response:
       - ITA mode:  JWT token from Intel Trust Authority
       - DCAP mode: Raw TDX quote (locally verified)
    5. Verify:
       - ITA:  JWT issuer, expiry, nonce binding
       - DCAP: ECDSA signature, nonce binding in report_data
    6. Output verification verdict

Usage (inside SGX enclave):
    gramine-sgx ./verifier sgx_tdx_verifier.py --tdx-host <TDX_IP> [options]

Options:
    --tdx-host HOST     TDX server hostname/IP (required)
    --tdx-port PORT     TDX server port (default: 8443)
    --method METHOD     Attestation method: ita or dcap (default: ita)
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
import base64
from datetime import datetime

# Add parent directory to path for common module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import (
    AttestationRequest, AttestationResponse, VerificationResult,
    generate_nonce, verify_nonce_binding, verify_jwt_simple, decode_jwt_payload,
    verify_dcap_quote, verify_ima_log,
    create_tls_context_client, send_message, receive_message,
    DEFAULT_PORT, PROTOCOL_VERSION, ProtocolError,
    METHOD_ITA, METHOD_DCAP, VALID_METHODS
)

from common.runtime_verifier import expand_runtime_evidence, verify_runtime_evidence

class SGXTDXVerifier:
    """
    SGX Enclave-based TDX attestation verifier with mTLS support.
    
    Connects to TDX attestation server, challenges it with a nonce,
    and verifies the returned attestation token.
    
    When client_cert and client_key are provided, the verifier authenticates
    itself to the TDX server using mutual TLS (mTLS).
    """
    
    def __init__(self, tdx_host: str, tdx_port: int,
                 ca_cert: str = None, verify_cert: bool = True,
                 client_cert: str = None, client_key: str = None,
                 verbose: bool = False, method: str = METHOD_ITA,
                 require_runtime: bool = True,
                 expected_rtmr3_base: str = "auto",
                 golden_file: str = None,
                 require_golden: bool = False,
                 require_ak_cert: bool = False,
                 save_golden: str = None):
        self.tdx_host = tdx_host
        self.tdx_port = tdx_port
        self.ca_cert = ca_cert
        self.verify_cert = verify_cert
        self.client_cert = client_cert
        self.client_key = client_key
        self.verbose = verbose
        self.method = method
        self.require_runtime = require_runtime
        self.expected_rtmr3_base = expected_rtmr3_base
        self.require_golden = require_golden
        self.require_ak_cert = require_ak_cert
        self.save_golden = save_golden
        self.golden = self._load_golden(golden_file) if golden_file else None
        self._runtime_binary = b""
        self._runtime_ascii = ""
        self._runtime_entry_count = 0
    
    def log(self, msg: str):
        """Log message if verbose mode enabled"""
        if self.verbose:
            print(f"[DEBUG] {msg}")
    
    @staticmethod
    def _load_golden(path: str) -> dict:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def _save_observed_golden(
        self, path: str, quote_bytes: bytes, runtime_evidence: dict
    ) -> None:
        from common.protocol import parse_dcap_quote

        quote_info = parse_dcap_quote(quote_bytes)
        anchor = runtime_evidence.get("anchor", {})
        data = {
            "mrtd": quote_info.mrtd,
            "rtmr0": quote_info.rtmr0,
            "rtmr1": quote_info.rtmr1,
            "rtmr2": quote_info.rtmr2,
            "rtmr3_base": anchor.get("rtmr3_base_before_start", ""),
            "runtime_evidence_version": runtime_evidence.get("version", ""),
        }
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        self.log(f"Saved observed golden measurements to {path}")

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
            
            # Step 2: Create TLS connection (with mTLS if client cert provided)
            self.log(f"Connecting to {self.tdx_host}:{self.tdx_port}...")
            tls_context = create_tls_context_client(
                ca_cert_file=self.ca_cert,
                client_cert_file=self.client_cert,
                client_key_file=self.client_key,
                verify=self.verify_cert
            )
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            
            tls_sock = tls_context.wrap_socket(sock, server_hostname=self.tdx_host)
            tls_sock.connect((self.tdx_host, self.tdx_port))
            self.log("TLS connection established")
            
            try:
                # Step 3: Send attestation request with method
                request = AttestationRequest(
                    nonce=nonce, attestation_method=self.method,
                    ima_offset=self._runtime_entry_count,
                )
                self.log(f"Sending attestation request (method={self.method})...")
                send_message(tls_sock, request.to_json())
                
                # Step 4: Receive response
                self.log("Waiting for response...")
                response_json = receive_message(tls_sock)
                response = AttestationResponse.from_json(response_json)
                
                if response.status != "success":
                    result.error = f"TDX server error: {response.error}"
                    result.verdict = "ERROR"
                    return result
                
                # Step 5: Verify the TDX quote/token and composed runtime evidence.
                if response.attestation_method == METHOD_DCAP:
                    self.log(
                        f"Received DCAP quote ({len(response.raw_quote)} bytes base64)"
                    )
                    quote_bytes = base64.b64decode(response.raw_quote)
                    self.log(f"Decoded quote: {len(quote_bytes)} bytes")
                    result = verify_dcap_quote(quote_bytes, nonce, debug=self.verbose)
                    result.mrtd = response.mrtd

                    if result.verified and response.runtime_evidence:
                        expanded_evidence, full_binary, full_ascii = (
                            expand_runtime_evidence(
                                response.runtime_evidence,
                                self._runtime_binary,
                                self._runtime_ascii,
                            )
                        )
                        runtime = verify_runtime_evidence(
                            expanded_evidence,
                            quote_bytes,
                            nonce,
                            expected_rtmr3_base=self.expected_rtmr3_base,
                            golden=self.golden,
                            require_golden=self.require_golden,
                            require_ak_cert=self.require_ak_cert,
                        )
                        result.runtime_checks = runtime.checks
                        result.runtime_details = runtime.details
                        result.ima_verified = runtime.ok
                        result.ima_entry_count = runtime.details.get(
                            "ima_entries", 0
                        )
                        result.warnings.extend(runtime.warnings)

                        if runtime.ok:
                            if self.save_golden:
                                self._save_observed_golden(
                                    self.save_golden,
                                    quote_bytes,
                                    expanded_evidence,
                                )
                            self._runtime_binary = full_binary
                            self._runtime_ascii = full_ascii
                            self._runtime_entry_count = result.ima_entry_count
                            result.runtime_verdict = "CLEAN"
                            self.log(
                                "Composed runtime evidence verified "
                                f"(wire start={response.runtime_evidence.get('ima_start_index', 0)})"
                            )
                        else:
                            result.verified = False
                            result.verdict = "UNTRUSTED"
                            result.runtime_verdict = "RUNTIME_VIOLATION"
                            result.error = runtime.error
                            self.log(
                                f"Composed runtime verification failed: {runtime.error}"
                            )
                    elif result.verified and self.require_runtime:
                        result.verified = False
                        result.verdict = "UNTRUSTED"
                        result.runtime_verdict = "IMA_UNAVAILABLE"
                        result.error = "required composed runtime evidence is missing"
                    elif result.verified:
                        result.runtime_verdict = "IMA_UNAVAILABLE"
                        result.warnings.append(
                            "Composed runtime evidence was not required"
                        )
                else:
                    self.log(f"Received ITA token ({len(response.token)} bytes)")
                    result = self._verify_token(response.token, nonce)
                    result.mrtd = response.mrtd

                # Legacy ASCII IMA verification remains available only when the
                # server did not provide the composed v1.1 evidence object.
                if not response.runtime_evidence and response.ima_log and response.pcr10:
                    self.log(
                        f"Verifying legacy IMA log ({response.ima_entry_count} entries)..."
                    )
                    try:
                        ima_log_text = base64.b64decode(response.ima_log).decode(
                            "utf-8"
                        )
                        ima_valid, ima_count, ima_msg = verify_ima_log(
                            ima_log_text, response.pcr10, debug=self.verbose
                        )
                        result.ima_verified = ima_valid
                        result.ima_entry_count = ima_count
                        result.runtime_verdict = (
                            "CLEAN" if ima_valid else "RUNTIME_VIOLATION"
                        )
                        if not ima_valid:
                            result.warnings.append(
                                f"Legacy IMA verification failed: {ima_msg}"
                            )
                    except Exception as exc:
                        result.runtime_verdict = "IMA_ERROR"
                        result.warnings.append(
                            f"Legacy IMA verification error: {exc}"
                        )
                elif not response.runtime_evidence and not result.runtime_verdict:
                    result.runtime_verdict = "IMA_UNAVAILABLE"
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
            result.verified = False
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
        result.attestation_method = METHOD_ITA
        
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
    print()
    print("=" * 60)
    print("ATTESTATION RESULT")
    print("=" * 60)
    
    # Boot integrity (Layer 1)
    if result.verdict == "TRUSTED":
        print(f"  Boot Verdict:     ✓ {result.verdict}")
    else:
        print(f"  Boot Verdict:     ✗ {result.verdict}")
    
    # Runtime integrity (Layer 2)
    if result.runtime_verdict == "CLEAN":
        print(f"  Runtime Verdict:  ✓ {result.runtime_verdict} ({result.ima_entry_count} IMA entries verified)")
    elif result.runtime_verdict == "RUNTIME_VIOLATION":
        print(f"  Runtime Verdict:  ✗ {result.runtime_verdict}")
    elif result.runtime_verdict == "IMA_UNAVAILABLE":
        print(f"  Runtime Verdict:  ⚠ {result.runtime_verdict} (IMA data not in response)")
    elif result.runtime_verdict:
        print(f"  Runtime Verdict:  ⚠ {result.runtime_verdict}")
    
    print(f"  Method:           {result.attestation_method}")
    print(f"  MRTD:             {result.mrtd[:32]}..." if result.mrtd else "  MRTD:             N/A")
    
    print()
    print("  Verification Checks:")
    checks = [
        ("Nonce binding", result.nonce_verified),
        ("Issuer", result.issuer_verified),
        ("Expiry", result.expiry_verified),
        ("Signature", result.signature_verified),
        ("IMA log replay", result.ima_verified),
    ]
    for name, passed in checks:
        icon = "✓" if passed else "✗"
        print(f"    {icon} {name}")
    
    if result.runtime_checks:
        print("\n  Composed Runtime Checks:")
        for name, passed in result.runtime_checks.items():
            icon = "✓" if passed else "✗"
            print(f"    {icon} {name}")
        details = result.runtime_details
        if details:
            print(
                "    PCR-10 prefix: "
                f"{details.get('pcr10_prefix_entries', '<none>')} entries"
            )
            print(
                "    RTMR3 base:     "
                f"{details.get('rtmr3_base_source', '<unknown>')}"
            )
    if result.tcb_status:
        print(f"\n  TCB Status: {result.tcb_status}")
    
    if result.warnings:
        print(f"\n  Warnings:")
        for w in result.warnings:
            print(f"    ⚠ {w}")
    
    if result.error:
        print(f"\n  Error: {result.error}")
    
    print(f"\n  Verification Time: {result.verification_time_ms:.1f}ms")
    print("=" * 60)


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
    parser.add_argument("--client-cert",
                       help="Client certificate for mTLS authentication")
    parser.add_argument("--client-key",
                       help="Client private key for mTLS authentication")
    parser.add_argument("--no-verify", action="store_true",
                       help="Skip TLS certificate verification")
    parser.add_argument("--test-network", action="store_true",
                       help="Test network connectivity only")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose output")
    parser.add_argument("--method", choices=[METHOD_ITA, METHOD_DCAP], default=METHOD_ITA,
                        help=f"Attestation method: {METHOD_ITA} (cloud) or {METHOD_DCAP} (local). Default: {METHOD_ITA}")
    parser.add_argument("--json", action="store_true",
                        help="Output result as JSON")
    parser.add_argument(
        "--allow-legacy-runtime",
        action="store_true",
        help="Do not require composed vTPM/RTMR3 evidence in DCAP mode",
    )
    parser.add_argument(
        "--expected-rtmr3-base",
        default="auto",
        help="'auto', 'zero', or an explicit 96-hex-character RTMR3 base",
    )
    parser.add_argument("--golden-file",
                        help="Expected MRTD/RTMR0-2 and optional RTMR3 base JSON")
    parser.add_argument("--save-golden",
                        help="Save observed MRTD/RTMR0-2 and RTMR3 base JSON")
    parser.add_argument("--require-golden", action="store_true",
                        help="Fail unless a supplied golden file matches")
    parser.add_argument("--require-ak-cert", action="store_true",
                        help="Fail unless the Google AK certificate binds to ak_pub")
    
    args = parser.parse_args()
    
    print_banner()
    
    # Check environment
    in_enclave = check_enclave_environment()
    print(f"Protocol Version: {PROTOCOL_VERSION}")
    print()
    
    # Resolve CA cert path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    ca_cert = None
    if args.ca_cert:
        ca_cert = os.path.join(script_dir, args.ca_cert) if not os.path.isabs(args.ca_cert) else args.ca_cert
    
    # Resolve client cert paths for mTLS
    client_cert = None
    client_key = None
    if args.client_cert and args.client_key:
        client_cert = os.path.join(script_dir, args.client_cert) if not os.path.isabs(args.client_cert) else args.client_cert
        client_key = os.path.join(script_dir, args.client_key) if not os.path.isabs(args.client_key) else args.client_key
        print(f"[mTLS] Using client certificate: {client_cert}")
    elif args.client_cert or args.client_key:
        print("Warning: Both --client-cert and --client-key required for mTLS")
    
    # Create verifier
    verifier = SGXTDXVerifier(
        tdx_host=args.tdx_host,
        tdx_port=args.tdx_port,
        ca_cert=ca_cert,
        verify_cert=not args.no_verify,
        client_cert=client_cert,
        client_key=client_key,
        verbose=args.verbose,
        method=args.method,
        require_runtime=not args.allow_legacy_runtime,
        expected_rtmr3_base=args.expected_rtmr3_base,
        golden_file=args.golden_file,
        require_golden=args.require_golden,
        require_ak_cert=args.require_ak_cert,
        save_golden=args.save_golden
    )
    
    if args.test_network:
        success = verifier.test_network()
        sys.exit(0 if success else 1)
    
    # Perform attestation
    method_label = "ITA" if args.method == METHOD_ITA else "DCAP"
    print(f"Attesting TDX server at {args.tdx_host}:{args.tdx_port} (method: {method_label})...")
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
