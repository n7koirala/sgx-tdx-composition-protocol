#!/usr/bin/env python3
"""
TDX Attestation Client
Sends TDX attestation tokens to a remote verifier

Usage:
    python3 tdx_attestation_client.py <verifier_host> [verifier_port]
    
Example:
    python3 tdx_attestation_client.py 10.128.0.5 9999
"""

import socket
import json
import sys
import time
from tdx_remote_attestation import TDXAttestor


def send_attestation(verifier_host: str, verifier_port: int = 9999, 
                     sgx_mrenclave: str = None):
    """
    Generate and send TDX attestation to remote verifier
    
    Args:
        verifier_host: IP/hostname of verifier
        verifier_port: Port of verifier service
        sgx_mrenclave: Optional SGX measurement for binding
    """
    print("=" * 70)
    print("TDX Attestation Client")
    print("=" * 70)
    print(f"Verifier: {verifier_host}:{verifier_port}")
    print()
    
    # Generate attestation
    print("[1] Generating TDX attestation...")
    gen_start = time.perf_counter()
    
    attestor = TDXAttestor()
    
    if sgx_mrenclave:
        binding_hash, token = attestor.get_binding_data(sgx_mrenclave=sgx_mrenclave)
        print(f"    ✓ Bound to SGX MRENCLAVE: {sgx_mrenclave[:16]}...")
        print(f"    Binding hash: {binding_hash[:32]}...")
    else:
        token = attestor.get_attestation_token()
    
    gen_time = (time.perf_counter() - gen_start) * 1000
    print(f"    ✓ Attestation generated in {gen_time:.2f} ms")
    print(f"    Token length: {len(token.raw_token)} bytes")
    
    # Send to verifier
    print(f"\n[2] Sending to verifier {verifier_host}:{verifier_port}...")
    net_start = time.perf_counter()
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect((verifier_host, verifier_port))
        sock.sendall(token.raw_token.encode())
        sock.shutdown(socket.SHUT_WR)
        
        # Receive response
        response_data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response_data += chunk
        sock.close()
        
        net_time = (time.perf_counter() - net_start) * 1000
        print(f"    ✓ Response received in {net_time:.2f} ms")
        
    except socket.timeout:
        print("    ✗ Connection timeout")
        return False
    except ConnectionRefusedError:
        print("    ✗ Connection refused (is the verifier running?)")
        return False
    except Exception as e:
        print(f"    ✗ Network error: {e}")
        return False
    
    # Parse response
    print("\n[3] Verification result:")
    try:
        result = json.loads(response_data.decode())
        
        if result.get("verified"):
            print("    ✓ VERIFIED - TD is TRUSTED")
        else:
            error = result.get("error", "Unknown")
            print(f"    ✗ FAILED - {error}")
        
        if "tdx" in result:
            tdx = result["tdx"]
            print(f"\n    Measurements confirmed:")
            print(f"      MRTD:       {tdx.get('mrtd', 'N/A')[:32]}...")
            print(f"      TCB Status: {tdx.get('tcb_status', 'N/A')}")
            print(f"      Debuggable: {tdx.get('is_debuggable', 'N/A')}")
        
        if "warnings" in result:
            print(f"\n    Warnings:")
            for w in result["warnings"]:
                print(f"      ⚠ {w}")
        
        print(f"\n    Timing:")
        print(f"      Generation:   {gen_time:.2f} ms")
        print(f"      Network RTT:  {net_time:.2f} ms")
        print(f"      Verification: {result.get('verification_time_ms', 0):.2f} ms")
        print(f"      Total:        {gen_time + net_time:.2f} ms")
        
        return result.get("verified", False)
        
    except json.JSONDecodeError:
        print(f"    ✗ Invalid response from verifier")
        print(f"    Raw: {response_data.decode()[:200]}")
        return False


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <verifier_host> [verifier_port] [--bind-sgx <mrenclave>]")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} 10.128.0.5")
        print(f"  {sys.argv[0]} 10.128.0.5 9999")
        print(f"  {sys.argv[0]} 10.128.0.5 9999 --bind-sgx 05b8e0fe8118ceb23099e92fb9be99d1")
        sys.exit(1)
    
    verifier_host = sys.argv[1]
    verifier_port = 9999
    sgx_mrenclave = None
    
    # Parse optional arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--bind-sgx" and i + 1 < len(sys.argv):
            sgx_mrenclave = sys.argv[i + 1]
            i += 2
        else:
            try:
                verifier_port = int(sys.argv[i])
            except ValueError:
                pass
            i += 1
    
    print()
    success = send_attestation(verifier_host, verifier_port, sgx_mrenclave)
    print()
    print("=" * 70)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
