#!/usr/bin/env python3
"""
TDX Attestation Verifier Service
For Hierarchical TEE Composition Protocol

Run this on the SGX machine (or any verifier) to receive and verify
TDX attestation tokens from TDX VMs.

Usage:
    python3 tdx_verifier_service.py [port]
    
    Default port: 9999

Example:
    # On SGX machine (verifier)
    python3 tdx_verifier_service.py 9999
    
    # On TDX machine (prover)
    python3 tdx_remote_attestation.py  # or use the client
"""

import socket
import json
import base64
import time
import sys
import hashlib
from datetime import datetime
from typing import Dict, Any, Tuple, Optional


class TDXTokenVerifier:
    """Verifies TDX attestation tokens (JWTs from Intel Trust Authority)"""
    
    def __init__(self):
        # Expected measurements for policy enforcement
        self.trusted_mrtds = set()  # Add known-good MRTD values
        self.allowed_tcb_statuses = {"UpToDate", "SWHardeningNeeded", "OutOfDate"}
    
    def add_trusted_mrtd(self, mrtd: str):
        """Add a trusted TD measurement"""
        self.trusted_mrtds.add(mrtd.lower())
    
    def verify(self, token_str: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Verify a TDX attestation token
        
        Args:
            token_str: Raw JWT token string
        
        Returns:
            Tuple of (verified, result_dict)
        """
        result = {
            "verified": False,
            "timestamp": datetime.now().isoformat(),
            "checks": {}
        }
        
        try:
            # Step 1: Parse JWT structure
            parts = token_str.strip().split('.')
            if len(parts) != 3:
                result["error"] = "Invalid JWT format (expected 3 parts)"
                return False, result
            result["checks"]["jwt_format"] = True
            
            # Step 2: Decode header and payload
            header = self._decode_jwt_part(parts[0])
            payload = self._decode_jwt_part(parts[1])
            result["checks"]["jwt_decode"] = True
            
            # Step 3: Check issuer
            issuer = payload.get('iss', '')
            if 'trustauthority.intel.com' not in issuer:
                result["error"] = f"Invalid issuer: {issuer}"
                result["checks"]["issuer"] = False
                return False, result
            result["checks"]["issuer"] = True
            
            # Step 4: Check expiry
            exp = payload.get('exp', 0)
            now = time.time()
            if exp < now:
                result["error"] = f"Token expired (exp: {exp}, now: {now})"
                result["checks"]["expiry"] = False
                return False, result
            result["checks"]["expiry"] = True
            result["expires_in_seconds"] = int(exp - now)
            
            # Step 5: Check for TDX claims
            if 'tdx' not in payload:
                result["error"] = "No TDX claims in token"
                result["checks"]["tdx_claims"] = False
                return False, result
            result["checks"]["tdx_claims"] = True
            
            # Step 6: Extract TDX measurements
            tdx = payload['tdx']
            tdx_info = {
                "mrtd": tdx.get('tdx_mrtd', ''),
                "mrowner": tdx.get('tdx_mrowner', ''),
                "mrownerconfig": tdx.get('tdx_mrownerconfig', ''),
                "report_data": tdx.get('tdx_report_data', ''),
                "tcb_status": tdx.get('attester_tcb_status', ''),
                "is_debuggable": tdx.get('tdx_is_debuggable', False),
                "rtmr0": tdx.get('tdx_rtmr0', ''),
                "rtmr1": tdx.get('tdx_rtmr1', ''),
                "rtmr2": tdx.get('tdx_rtmr2', ''),
                "rtmr3": tdx.get('tdx_rtmr3', ''),
                "seam_svn": tdx.get('tdx_seamsvn', 0),
            }
            result["tdx"] = tdx_info
            
            # Step 7: Policy checks
            
            # Check debug status
            if tdx_info["is_debuggable"]:
                result["warnings"] = result.get("warnings", [])
                result["warnings"].append("TD is debuggable - not for production!")
            result["checks"]["debug_disabled"] = not tdx_info["is_debuggable"]
            
            # Check TCB status
            tcb_ok = tdx_info["tcb_status"] in self.allowed_tcb_statuses
            result["checks"]["tcb_status"] = tcb_ok
            if not tcb_ok:
                result["warnings"] = result.get("warnings", [])
                result["warnings"].append(f"TCB status: {tdx_info['tcb_status']}")
            
            # Check trusted MRTD (if policy is set)
            if self.trusted_mrtds:
                mrtd_trusted = tdx_info["mrtd"].lower() in self.trusted_mrtds
                result["checks"]["mrtd_trusted"] = mrtd_trusted
                if not mrtd_trusted:
                    result["error"] = "MRTD not in trusted list"
                    return False, result
            
            # All checks passed
            result["verified"] = True
            result["verdict"] = "TRUSTED"
            
            return True, result
            
        except Exception as e:
            result["error"] = str(e)
            return False, result
    
    def _decode_jwt_part(self, part: str) -> Dict[str, Any]:
        """Decode a base64url encoded JWT part"""
        padded = part + '=' * (4 - len(part) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)
    
    def extract_binding_data(self, token_str: str) -> Optional[str]:
        """Extract binding data from TDX report_data for SGX composition"""
        try:
            parts = token_str.strip().split('.')
            payload = self._decode_jwt_part(parts[1])
            if 'tdx' in payload:
                return payload['tdx'].get('tdx_report_data', '')
        except:
            pass
        return None


class TDXVerifierService:
    """
    Network service for TDX attestation verification
    
    Listens for TDX attestation tokens and returns verification results.
    Designed to run on the SGX machine in the hierarchical composition.
    """
    
    def __init__(self, port: int = 9999):
        self.port = port
        self.verifier = TDXTokenVerifier()
        self.stats = {
            "total_requests": 0,
            "verified": 0,
            "failed": 0,
            "start_time": datetime.now().isoformat()
        }
    
    def run(self):
        """Start the verification service"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind(('0.0.0.0', self.port))
            server.listen(5)
            
            self._print_banner()
            
            while True:
                try:
                    client, addr = server.accept()
                    self._handle_client(client, addr)
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"Error handling client: {e}")
        
        finally:
            server.close()
            self._print_stats()
    
    def _print_banner(self):
        """Print startup banner"""
        print("=" * 70)
        print("TDX Attestation Verifier Service")
        print("=" * 70)
        print(f"Port:     {self.port}")
        print(f"Started:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)
        print("\nWaiting for TDX attestation tokens...\n")
    
    def _print_stats(self):
        """Print final statistics"""
        print("\n" + "=" * 70)
        print("Service Statistics")
        print("=" * 70)
        print(f"Total requests:  {self.stats['total_requests']}")
        print(f"Verified:        {self.stats['verified']}")
        print(f"Failed:          {self.stats['failed']}")
        print("=" * 70)
    
    def _handle_client(self, client: socket.socket, addr: Tuple[str, int]):
        """Handle incoming attestation request"""
        receive_start = time.time()
        
        # Receive token data
        data = b""
        client.settimeout(10)
        try:
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                data += chunk
                # Check for reasonable token size (JWTs are typically < 10KB)
                if len(data) > 50000:
                    break
        except socket.timeout:
            pass
        
        receive_time = (time.time() - receive_start) * 1000
        
        if not data:
            client.close()
            return
        
        self.stats["total_requests"] += 1
        
        # Decode and verify
        token_str = data.decode('utf-8').strip()
        
        print(f"[{self.stats['total_requests']}] Request from {addr[0]}:{addr[1]}")
        print(f"    Received: {len(data)} bytes ({receive_time:.2f} ms)")
        
        # Verify token
        verify_start = time.time()
        verified, result = self.verifier.verify(token_str)
        verify_time = (time.time() - verify_start) * 1000
        
        result["verification_time_ms"] = verify_time
        result["network_receive_ms"] = receive_time
        
        if verified:
            self.stats["verified"] += 1
            print(f"    ✓ Verification: SUCCESS ({verify_time:.2f} ms)")
            
            # Print key info
            if "tdx" in result:
                tdx = result["tdx"]
                mrtd = tdx.get("mrtd", "N/A")
                if len(mrtd) > 16:
                    mrtd = mrtd[:16] + "..."
                print(f"    MRTD:       {mrtd}")
                print(f"    TCB Status: {tdx.get('tcb_status', 'N/A')}")
                print(f"    Debuggable: {tdx.get('is_debuggable', 'N/A')}")
        else:
            self.stats["failed"] += 1
            error = result.get("error", "Unknown error")
            print(f"    ✗ Verification: FAILED - {error}")
        
        # Send response
        response = json.dumps(result)
        client.sendall(response.encode())
        client.close()
        
        print(f"    Response sent: {len(response)} bytes")
        print()


def main():
    # Parse port from command line
    port = 9999
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Invalid port: {sys.argv[1]}")
            print(f"Usage: {sys.argv[0]} [port]")
            sys.exit(1)
    
    # Start service
    service = TDXVerifierService(port=port)
    
    try:
        service.run()
    except KeyboardInterrupt:
        print("\n\nShutting down...")


if __name__ == "__main__":
    main()
