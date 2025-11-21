#!/usr/bin/env python3
"""
Remote Attestation Test
Measures end-to-end attestation latency and overhead
"""

import socket
import time
import subprocess
import json
from datetime import datetime

class RemoteAttestationTest:
    def __init__(self, config_path: str = "~/config.json"):
        self.config_path = config_path
    
    def setup_simple_verifier(self, port: int = 9999):
        """Set up a simple attestation verifier (run this on another machine)"""
        
        verifier_code = '''#!/usr/bin/env python3
import socket
import time
import json

def run_verifier(port=9999):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    print(f"Verifier listening on port {port}...")
    
    while True:
        client, addr = server.accept()
        print(f"\\nConnection from {addr}")
        
        # Receive attestation
        data = client.recv(1024*1024)  # 1MB buffer
        receive_time = time.time()
        
        if data:
            print(f"Received {len(data)} bytes")
            
            # Simulate verification (would do real verification here)
            time.sleep(0.01)  # Simulate verification overhead
            
            response = {
                "verified": True,
                "timestamp": receive_time,
                "verdict": "Trusted",
                "verification_time_ms": 10
            }
            
            client.send(json.dumps(response).encode())
            print("Sent verification response")
        
        client.close()

if __name__ == "__main__":
    run_verifier()
'''
        
        with open("verifier.py", "w") as f:
            f.write(verifier_code)
        
        print("Verifier created: verifier.py")
        print("Run this on your remote machine with: python3 verifier.py")
    
    def test_remote_attestation(self, verifier_host: str, verifier_port: int = 9999, iterations: int = 10):
        """Test remote attestation to a verifier"""
        print(f"\nTesting remote attestation to {verifier_host}:{verifier_port}")
        
        latencies = []
        
        for i in range(iterations):
            # Generate attestation
            start = time.perf_counter()
            
            result = subprocess.run(
                ["sudo", "trustauthority-cli", "token", "--tdx", "-c", self.config_path],
                capture_output=True,
                text=True
            )
            
            attestation_time = time.perf_counter()
            
            if result.returncode == 0:
                token = result.stdout
                
                # Send to verifier
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((verifier_host, verifier_port))
                    sock.send(token.encode())
                    
                    # Receive verification response
                    response = sock.recv(4096)
                    sock.close()
                    
                    end = time.perf_counter()
                    
                    total_latency = (end - start) * 1000
                    latencies.append(total_latency)
                    
                    print(f"  Iteration {i+1}/{iterations}: {total_latency:.2f} ms")
                
                except Exception as e:
                    print(f"  ❌ Failed to connect to verifier: {e}")
            
            time.sleep(0.5)
        
        if latencies:
            import statistics
            return {
                "operation": "Remote Attestation (End-to-End)",
                "verifier": f"{verifier_host}:{verifier_port}",
                "iterations": len(latencies),
                "mean_ms": statistics.mean(latencies),
                "median_ms": statistics.median(latencies),
                "min_ms": min(latencies),
                "max_ms": max(latencies)
            }
        else:
            return {"error": "No successful attestations"}

if __name__ == "__main__":
    test = RemoteAttestationTest()
    
    print("=" * 60)
    print("Remote Attestation Test")
    print("=" * 60)
    
    # Setup verifier script
    test.setup_simple_verifier()
    
    print("\nTo test remote attestation:")
    print("1. Copy verifier.py to another machine")
    print("2. Run: python3 verifier.py")
    print("3. Then run: python3 remote_attestation_test.py --test <verifier-ip>")
