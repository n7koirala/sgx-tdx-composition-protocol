#!/usr/bin/env python3
"""
TDX Hierarchical Attestation Server

This server runs on the TDX VM and handles attestation challenges from
the SGX enclave. It implements the challenge-response protocol:

1. Receives challenge with nonce from SGX enclave (over TLS)
2. Generates TDX quote with nonce bound in report_data
3. Gets attestation token from Intel Trust Authority (ITA mode)
   OR generates raw DCAP quote via libtdx_attest (DCAP mode)
4. Returns the token/quote to SGX enclave

Usage:
    python3 tdx_attestation_server.py [options]
    
    Options:
        --port PORT         Server port (default: 8443)
        --method METHOD     Attestation method: ita or dcap (default: ita)
        --cert CERT_FILE    TLS certificate file (default: ../certs/server.crt)
        --key KEY_FILE      TLS private key file (default: ../certs/server.key)
        --config CONFIG     Trust Authority config (default: ~/config.json)
        --test              Run self-test mode
        
Example:
    python3 tdx_attestation_server.py --port 8443 --method dcap
"""

import sys
import os
import socket
import ssl
import argparse
import subprocess
import json
import base64
import time
import ctypes
import ctypes.util
from datetime import datetime

# Add parent directory to path for common module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import (
    AttestationRequest, AttestationResponse, ProtocolError,
    create_tls_context_server, send_message, receive_message,
    DEFAULT_PORT, PROTOCOL_VERSION, METHOD_ITA, METHOD_DCAP, VALID_METHODS,
    parse_dcap_quote
)


class TDXAttestationServer:
    """
    TLS server for TDX attestation challenge-response with mTLS support.
    
    Handles requests from SGX enclave to attest the TDX VM.
    When require_client_cert is True, only clients with valid certificates
    signed by the CA can connect (mTLS).
    """
    
    def __init__(self, port: int, cert_file: str, key_file: str, config_path: str,
                 ca_cert_file: str = None, require_client_cert: bool = False,
                 method: str = METHOD_ITA):
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.config_path = config_path
        self.ca_cert_file = ca_cert_file
        self.require_client_cert = require_client_cert
        self.method = method
        self.running = False
        
        # libtdx_attest library handle (for DCAP mode)
        self._tdx_lib = None
        
        # Statistics
        self.stats = {
            "requests": 0,
            "successful": 0,
            "failed": 0,
            "rejected_no_cert": 0,
            "start_time": None
        }
        
        self._verify_setup()
    
    def _verify_setup(self):
        """Verify TDX and attestation dependencies are available"""
        # Check TDX device
        if not os.path.exists("/dev/tdx_guest"):
            raise RuntimeError("TDX device not found: /dev/tdx_guest")
        
        # Check certificates
        if not os.path.exists(self.cert_file):
            raise RuntimeError(f"Certificate not found: {self.cert_file}")
        if not os.path.exists(self.key_file):
            raise RuntimeError(f"Private key not found: {self.key_file}")
        
        # Check CA certificate for mTLS
        if self.require_client_cert:
            if not self.ca_cert_file:
                raise RuntimeError("CA certificate required for mTLS (--require-client-cert)")
            if not os.path.exists(self.ca_cert_file):
                raise RuntimeError(f"CA certificate not found: {self.ca_cert_file}")
        
        # Method-specific checks
        if self.method == METHOD_ITA:
            # Check config file
            if not os.path.exists(self.config_path):
                raise RuntimeError(f"Trust Authority config not found: {self.config_path}")
            # Check trustauthority-cli
            result = subprocess.run(["which", "trustauthority-cli"], 
                                   capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError("trustauthority-cli not found in PATH")
        
        elif self.method == METHOD_DCAP:
            # Check libtdx_attest
            self._tdx_lib = self._load_libtdx_attest()
            if self._tdx_lib is None:
                raise RuntimeError(
                    "libtdx_attest.so not found. Install with:\n"
                    "  sudo bash install_dcap_packages.sh")
    
    def _load_libtdx_attest(self):
        """Load the libtdx_attest shared library for DCAP quote generation."""
        lib_paths = [
            "libtdx_attest.so",
            "libtdx_attest.so.1",
            ctypes.util.find_library("tdx_attest"),
        ]
        
        for path in lib_paths:
            if path is None:
                continue
            try:
                lib = ctypes.CDLL(path)
                
                # Define function signatures
                lib.tdx_att_get_quote.restype = ctypes.c_int
                lib.tdx_att_get_quote.argtypes = [
                    ctypes.c_void_p,   # report_data
                    ctypes.c_void_p,   # att_key_id_list
                    ctypes.c_uint32,   # list_size
                    ctypes.c_void_p,   # att_key_id out
                    ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),  # pp_quote
                    ctypes.POINTER(ctypes.c_uint32),  # p_quote_size
                    ctypes.c_uint32,   # flags
                ]
                
                lib.tdx_att_free_quote.restype = None
                lib.tdx_att_free_quote.argtypes = [
                    ctypes.POINTER(ctypes.c_uint8),
                ]
                
                return lib
            except OSError:
                continue
        
        return None
    
    def get_tdx_token(self, nonce: str) -> tuple:
        """
        Generate TDX attestation token with nonce bound in report_data.
        
        Args:
            nonce: Base64-encoded nonce from SGX enclave
        
        Returns:
            Tuple of (token_string, mrtd)
        """
        # The nonce is passed as user_data, which gets included in the quote
        # Intel Trust Authority then includes it in the token's report_data
        cmd = [
            "sudo", "trustauthority-cli", "token", "--tdx",
            "-c", self.config_path,
            "-u", nonce[:32]  # user_data is limited, use first 32 chars
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode != 0:
            raise RuntimeError(f"Token generation failed: {result.stderr}")
        
        # Extract JWT token from output
        token_str = None
        for line in result.stdout.strip().split('\n'):
            if line.startswith('eyJ'):
                token_str = line
                break
        
        if not token_str:
            raise RuntimeError("No JWT token found in output")
        
        # Extract MRTD from token for quick reference
        mrtd = self._extract_mrtd(token_str)
        
        return token_str, mrtd
    
    def get_tdx_quote_dcap(self, nonce: str) -> tuple:
        """
        Generate TDX quote using libtdx_attest (DCAP mode).
        
        The nonce is decoded from base64 and written directly into
        the TDX report_data (64 bytes, zero-padded).
        
        Args:
            nonce: Base64-encoded nonce from SGX enclave
        
        Returns:
            Tuple of (raw_quote_bytes, mrtd_hex)
        """
        if self._tdx_lib is None:
            raise RuntimeError("libtdx_attest not loaded")
        
        # Decode nonce and prepare 64-byte report_data
        nonce_bytes = base64.b64decode(nonce)
        report_data = nonce_bytes + b'\x00' * (64 - len(nonce_bytes))
        report_data = report_data[:64]  # Ensure exactly 64 bytes
        
        # Create report_data buffer
        rd_buf = (ctypes.c_uint8 * 64)(*report_data)
        
        # Output pointers
        pp_quote = ctypes.POINTER(ctypes.c_uint8)()
        quote_size = ctypes.c_uint32(0)
        
        # Call tdx_att_get_quote
        ret = self._tdx_lib.tdx_att_get_quote(
            ctypes.byref(rd_buf),
            None, 0, None,
            ctypes.byref(pp_quote),
            ctypes.byref(quote_size),
            0,
        )
        
        if ret != 0:
            raise RuntimeError(f"tdx_att_get_quote failed: error {ret} (0x{ret:08x})")
        
        # Copy quote bytes
        size = quote_size.value
        quote_bytes = bytes(pp_quote[:size])
        
        # Free the quote buffer
        self._tdx_lib.tdx_att_free_quote(pp_quote)
        
        # Extract MRTD from parsed quote
        info = parse_dcap_quote(quote_bytes)
        
        return quote_bytes, info.mrtd
    
    def _extract_mrtd(self, token: str) -> str:
        """Extract MRTD from JWT token payload"""
        try:
            parts = token.split('.')
            payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            if 'tdx' in payload:
                return payload['tdx'].get('tdx_mrtd', '')
        except:
            pass
        return ''
    
    def handle_request(self, request_json: str) -> str:
        """
        Handle an attestation request.
        
        Routes to ITA or DCAP based on the server's configured method,
        or the request's attestation_method field.
        
        Args:
            request_json: JSON string of AttestationRequest
        
        Returns:
            JSON string of AttestationResponse
        """
        try:
            # Parse request
            request = AttestationRequest.from_json(request_json)
            
            # Validate request
            valid, error = request.validate()
            if not valid:
                return AttestationResponse.error_response(error).to_json()
            
            # Use the server's method (override request method with server method)
            method = self.method
            
            if method == METHOD_DCAP:
                # DCAP mode: generate raw quote via libtdx_attest
                quote_bytes, mrtd = self.get_tdx_quote_dcap(request.nonce)
                
                response = AttestationResponse(
                    status="success",
                    nonce_echo=request.nonce,
                    mrtd=mrtd,
                    attestation_method=METHOD_DCAP,
                    raw_quote=base64.b64encode(quote_bytes).decode('ascii'),
                )
            else:
                # ITA mode: get JWT token from Intel Trust Authority
                token, mrtd = self.get_tdx_token(request.nonce)
                
                response = AttestationResponse(
                    status="success",
                    token=token,
                    nonce_echo=request.nonce,
                    mrtd=mrtd,
                    attestation_method=METHOD_ITA,
                )
            
            self.stats["successful"] += 1
            return response.to_json()
            
        except Exception as e:
            self.stats["failed"] += 1
            return AttestationResponse.error_response(str(e)).to_json()
    
    def handle_client(self, client_socket: ssl.SSLSocket, addr: tuple):
        """Handle a single client connection"""
        self.stats["requests"] += 1
        req_num = self.stats["requests"]
        
        print(f"[{req_num}] Connection from {addr[0]}:{addr[1]}")
        
        try:
            # Receive request
            start = time.time()
            request_json = receive_message(client_socket)
            receive_time = (time.time() - start) * 1000
            
            print(f"    Received: {len(request_json)} bytes ({receive_time:.1f}ms)")
            
            # Process request
            start = time.time()
            response_json = self.handle_request(request_json)
            process_time = (time.time() - start) * 1000
            
            # Send response
            send_message(client_socket, response_json)
            
            # Check if successful
            response = AttestationResponse.from_json(response_json)
            if response.status == "success":
                print(f"    ✓ Success ({process_time:.1f}ms)")
                print(f"      MRTD: {response.mrtd[:32]}..." if response.mrtd else "      MRTD: N/A")
            else:
                print(f"    ✗ Error: {response.error}")
                
        except Exception as e:
            print(f"    ✗ Exception: {e}")
            try:
                error_response = AttestationResponse.error_response(str(e))
                send_message(client_socket, error_response.to_json())
            except:
                pass
        
        finally:
            client_socket.close()
        
        print()
    
    def run(self):
        """Start the attestation server with optional mTLS"""
        # Create TLS context (with mTLS if configured)
        tls_context = create_tls_context_server(
            self.cert_file, 
            self.key_file,
            ca_cert_file=self.ca_cert_file,
            require_client_cert=self.require_client_cert
        )
        
        # Create socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', self.port))
        server_socket.listen(5)
        
        # Wrap with TLS
        tls_socket = tls_context.wrap_socket(server_socket, server_side=True)
        
        self.running = True
        self.stats["start_time"] = datetime.now().isoformat()
        
        self._print_banner()
        
        try:
            while self.running:
                try:
                    client, addr = tls_socket.accept()
                    self.handle_client(client, addr)
                except KeyboardInterrupt:
                    break
                except ssl.SSLError as e:
                    print(f"TLS error: {e}")
                except Exception as e:
                    print(f"Error: {e}")
        
        finally:
            tls_socket.close()
            self._print_stats()
    
    def _print_banner(self):
        """Print startup banner"""
        print("=" * 70)
        print("TDX Hierarchical Attestation Server")
        print("=" * 70)
        print(f"Protocol Version: {PROTOCOL_VERSION}")
        print(f"Port:             {self.port}")
        print(f"Method:           {self.method.upper()} ({'Intel Trust Authority' if self.method == METHOD_ITA else 'Local DCAP (libtdx_attest)'})")
        print(f"TLS Certificate:  {self.cert_file}")
        print(f"mTLS Enabled:     {self.require_client_cert}")
        if self.require_client_cert:
            print(f"CA Certificate:   {self.ca_cert_file}")
        if self.method == METHOD_ITA:
            print(f"Config:           {self.config_path}")
        print(f"Started:          {self.stats['start_time']}")
        print("=" * 70)
        if self.require_client_cert:
            print("\n[SECURE] Only clients with valid certificates can connect.")
        print("\nWaiting for attestation challenges from SGX enclave...\n")
    
    def _print_stats(self):
        """Print shutdown statistics"""
        print("\n" + "=" * 70)
        print("Server Statistics")
        print("=" * 70)
        print(f"Total requests:  {self.stats['requests']}")
        print(f"Successful:      {self.stats['successful']}")
        print(f"Failed:          {self.stats['failed']}")
        if self.require_client_cert:
            print(f"Rejected (no cert): {self.stats['rejected_no_cert']}")
        print("=" * 70)


def self_test():
    """Run self-test to verify TDX attestation works"""
    print("=" * 70)
    print("TDX Attestation Server - Self Test")
    print("=" * 70)
    
    print("\n[1] Checking TDX device...")
    if os.path.exists("/dev/tdx_guest"):
        print("    ✓ /dev/tdx_guest available")
    else:
        print("    ✗ TDX device not found")
        return False
    
    print("\n[2] Checking trustauthority-cli...")
    result = subprocess.run(["which", "trustauthority-cli"], 
                           capture_output=True, text=True)
    if result.returncode == 0:
        print(f"    ✓ Found at {result.stdout.strip()}")
    else:
        print("    ✗ trustauthority-cli not found")
        return False
    
    print("\n[3] Testing attestation token generation...")
    test_nonce = base64.b64encode(os.urandom(32)).decode()
    config_path = os.path.expanduser("~/config.json")
    
    if not os.path.exists(config_path):
        print(f"    ✗ Config not found: {config_path}")
        return False
    
    cmd = [
        "sudo", "trustauthority-cli", "token", "--tdx",
        "-c", config_path,
        "-u", test_nonce[:32]
    ]
    
    print(f"    Running: {' '.join(cmd)}")
    start = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    elapsed = (time.time() - start) * 1000
    
    if result.returncode != 0:
        print(f"    ✗ Failed: {result.stderr}")
        return False
    
    # Check for token
    token = None
    for line in result.stdout.strip().split('\n'):
        if line.startswith('eyJ'):
            token = line
            break
    
    if not token:
        print("    ✗ No JWT token in output")
        return False
    
    print(f"    ✓ Token generated ({elapsed:.1f}ms, {len(token)} bytes)")
    
    print("\n[4] Parsing token...")
    try:
        parts = token.split('.')
        payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        
        if 'tdx' in payload:
            tdx = payload['tdx']
            print(f"    ✓ MRTD: {tdx.get('tdx_mrtd', 'N/A')[:32]}...")
            print(f"    ✓ TCB Status: {tdx.get('attester_tcb_status', 'N/A')}")
        else:
            print("    ✗ No TDX claims in token")
            return False
    except Exception as e:
        print(f"    ✗ Parse error: {e}")
        return False
    
    print("\n" + "=" * 70)
    print("✓ Self-test PASSED - Ready to serve attestation requests")
    print("=" * 70)
    return True


def main():
    parser = argparse.ArgumentParser(
        description="TDX Hierarchical Attestation Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                       help=f"Server port (default: {DEFAULT_PORT})")
    parser.add_argument("--cert", default="../certs/server.crt",
                       help="TLS certificate file")
    parser.add_argument("--key", default="../certs/server.key",
                       help="TLS private key file")
    parser.add_argument("--ca-cert", default="../certs/ca.crt",
                       help="CA certificate for client verification (mTLS)")
    parser.add_argument("--require-client-cert", action="store_true",
                       help="Require client certificate (mTLS) - only SGX enclave can connect")
    parser.add_argument("--config", default=os.path.expanduser("~/config.json"),
                        help="Intel Trust Authority config file")
    parser.add_argument("--method", choices=[METHOD_ITA, METHOD_DCAP], default=METHOD_ITA,
                        help=f"Attestation method: {METHOD_ITA} (cloud) or {METHOD_DCAP} (local). Default: {METHOD_ITA}")
    parser.add_argument("--test", action="store_true",
                       help="Run self-test mode")
    
    args = parser.parse_args()
    
    if args.test:
        sys.exit(0 if self_test() else 1)
    
    # Resolve paths relative to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cert_file = os.path.join(script_dir, args.cert) if not os.path.isabs(args.cert) else args.cert
    key_file = os.path.join(script_dir, args.key) if not os.path.isabs(args.key) else args.key
    ca_cert_file = os.path.join(script_dir, args.ca_cert) if not os.path.isabs(args.ca_cert) else args.ca_cert
    
    try:
        server = TDXAttestationServer(
            port=args.port,
            cert_file=cert_file,
            key_file=key_file,
            config_path=args.config,
            ca_cert_file=ca_cert_file if args.require_client_cert else None,
            require_client_cert=args.require_client_cert,
            method=args.method
        )
        server.run()
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
