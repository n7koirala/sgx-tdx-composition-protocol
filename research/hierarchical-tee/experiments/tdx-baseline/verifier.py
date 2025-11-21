#!/usr/bin/env python3
"""
Simple Attestation Verifier
Run this on a separate machine to receive and verify attestations
"""

import socket
import time
import json
import base64

def verify_jwt_token(token):
    """Basic JWT token verification (structure check only)"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False, "Invalid JWT format"
        
        # Decode payload
        payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_padded))
        
        # Check for TDX data
        if 'tdx' not in payload:
            return False, "No TDX data in token"
        
        # Check expiry
        exp = payload.get('exp', 0)
        if exp < time.time():
            return False, "Token expired"
        
        return True, payload
    
    except Exception as e:
        return False, f"Verification error: {e}"

def run_verifier(port=9999):
    """Run the attestation verifier"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(('0.0.0.0', port))
        server.listen(5)
        print(f"=" * 70)
        print(f"Attestation Verifier Running on Port {port}")
        print(f"=" * 70)
        print(f"Waiting for attestations...
")
        
        count = 0
        while True:
            client, addr = server.accept()
            receive_start = time.time()
            
            # Receive data
            data = b""
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                data += chunk
            
            receive_end = time.time()
            
            if data:
                count += 1
                token = data.decode('utf-8').strip()
                
                print(f"[{count}] Attestation from {addr[0]}:{addr[1]}")
                print(f"    Received: {len(data)} bytes")
                print(f"    Network time: {(receive_end - receive_start)*1000:.2f} ms")
                
                # Verify token
                verify_start = time.time()
                valid, result = verify_jwt_token(token)
                verify_end = time.time()
                
                verification_time = (verify_end - verify_start) * 1000
                
                if valid:
                    print(f"    ✓ Verification: SUCCESS ({verification_time:.2f} ms)")
                    
                    # Extract some info
                    if isinstance(result, dict) and 'tdx' in result:
                        tdx = result['tdx']
                        print(f"    TD Measurement: {tdx.get('tdx_mrtd', 'N/A')[:16]}...")
                        print(f"    TCB Status: {tdx.get('attester_tcb_status', 'N/A')}")
                else:
                    print(f"    ✗ Verification: FAILED - {result}")
                
                # Send response
                response = {
                    "verified": valid,
                    "timestamp": receive_end,
                    "verdict": "Trusted" if valid else "Untrusted",
                    "verification_time_ms": verification_time
                }
                
                client.send(json.dumps(response).encode())
                print(f"    Response sent
")
            
            client.close()
    
    except KeyboardInterrupt:
        print(f"

Shutting down verifier...")
    finally:
        server.close()

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    run_verifier(port)
