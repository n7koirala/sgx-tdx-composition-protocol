#!/usr/bin/env python3
"""
Fixed: Remote Attestation Test
Measures end-to-end attestation latency and overhead
"""

import socket
import time
import subprocess
import json
import sys
from datetime import datetime
import statistics

class RemoteAttestationTest:
    def __init__(self, config_path: str = None):
        if config_path is None:
            import os
            self.config_path = os.path.expanduser("~/config.json")
        else:
            self.config_path = config_path
    
    def create_verifier_script(self):
        """Create verifier script to run on remote machine"""
        
        verifier_code = '''#!/usr/bin/env python3
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
        print(f"Waiting for attestations...\n")
        
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
                print(f"    Response sent\n")
            
            client.close()
    
    except KeyboardInterrupt:
        print(f"\n\nShutting down verifier...")
    finally:
        server.close()

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    run_verifier(port)
'''
        
        with open("verifier.py", "w") as f:
            f.write(verifier_code)
        
        print("✓ Created verifier.py")
        print("\nTo run the verifier on remote machine:")
        print("  1. Copy verifier.py to remote machine")
        print("  2. Run: python3 verifier.py [port]")
        print("  3. Default port: 9999\n")
    
    def test_local_attestation_generation(self, iterations: int = 5):
        """Test local attestation generation time (baseline)"""
        print(f"Testing local attestation generation ({iterations} iterations)...")
        
        latencies = []
        token_sizes = []
        
        for i in range(iterations):
            start = time.perf_counter()
            
            result = subprocess.run(
                ["sudo", "trustauthority-cli", "token", "--tdx", "-c", self.config_path],
                capture_output=True,
                text=True
            )
            
            end = time.perf_counter()
            
            # Extract token
            if "eyJ" in result.stdout:
                lines = result.stdout.strip().split('\n')
                token = lines[-1]
                
                latencies.append((end - start) * 1000)
                token_sizes.append(len(token))
                
                print(f"  ✓ Generated attestation {i+1}/{iterations}: {(end-start)*1000:.2f} ms")
            else:
                print(f"  ✗ Failed to generate attestation {i+1}")
            
            time.sleep(0.5)
        
        if latencies:
            return {
                "mean_ms": statistics.mean(latencies),
                "median_ms": statistics.median(latencies),
                "min_ms": min(latencies),
                "max_ms": max(latencies),
                "token_size_bytes": statistics.mean(token_sizes)
            }
        return None
    
    def test_remote_attestation(self, verifier_host: str, verifier_port: int = 9999, 
                               iterations: int = 10):
        """Test remote attestation to a verifier"""
        print(f"\nTesting remote attestation to {verifier_host}:{verifier_port}")
        print(f"Iterations: {iterations}\n")
        
        results = {
            "verifier": f"{verifier_host}:{verifier_port}",
            "iterations": iterations,
            "successful": 0,
            "failed": 0,
            "latencies": {
                "total": [],
                "generation": [],
                "network": [],
                "verification": []
            }
        }
        
        for i in range(iterations):
            print(f"[{i+1}/{iterations}] ", end="", flush=True)
            
            try:
                # Generate attestation
                gen_start = time.perf_counter()
                
                result = subprocess.run(
                    ["sudo", "trustauthority-cli", "token", "--tdx", "-c", self.config_path],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                gen_end = time.perf_counter()
                generation_time = (gen_end - gen_start) * 1000
                
                # Extract token
                if "eyJ" not in result.stdout:
                    print("✗ Failed to generate token")
                    results["failed"] += 1
                    continue
                
                lines = result.stdout.strip().split('\n')
                token = lines[-1]
                
                # Send to verifier
                network_start = time.perf_counter()
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((verifier_host, verifier_port))
                sock.sendall(token.encode())
                sock.shutdown(socket.SHUT_WR)
                
                # Receive response
                response = sock.recv(4096)
                sock.close()
                
                network_end = time.perf_counter()
                network_time = (network_end - network_start) * 1000
                
                total_time = (network_end - gen_start) * 1000
                
                # Parse verifier response
                try:
                    resp_data = json.loads(response.decode())
                    verified = resp_data.get('verified', False)
                    verify_time = resp_data.get('verification_time_ms', 0)
                    
                    if verified:
                        print(f"✓ {total_time:.2f} ms (gen: {generation_time:.2f}, net: {network_time:.2f}, ver: {verify_time:.2f})")
                        
                        results["successful"] += 1
                        results["latencies"]["total"].append(total_time)
                        results["latencies"]["generation"].append(generation_time)
                        results["latencies"]["network"].append(network_time)
                        results["latencies"]["verification"].append(verify_time)
                    else:
                        print(f"✗ Verification failed")
                        results["failed"] += 1
                
                except json.JSONDecodeError:
                    print(f"✗ Invalid response from verifier")
                    results["failed"] += 1
            
            except socket.timeout:
                print("✗ Connection timeout")
                results["failed"] += 1
            except socket.error as e:
                print(f"✗ Network error: {e}")
                results["failed"] += 1
            except Exception as e:
                print(f"✗ Error: {e}")
                results["failed"] += 1
            
            time.sleep(1)
        
        return results
    
    def analyze_results(self, local_results, remote_results):
        """Analyze and compare local vs remote attestation"""
        print("\n" + "=" * 70)
        print("REMOTE ATTESTATION ANALYSIS")
        print("=" * 70)
        
        print(f"\n[1] LOCAL ATTESTATION BASELINE:")
        if local_results:
            print(f"    Mean:   {local_results['mean_ms']:.2f} ms")
            print(f"    Median: {local_results['median_ms']:.2f} ms")
            print(f"    Range:  [{local_results['min_ms']:.2f}, {local_results['max_ms']:.2f}] ms")
            print(f"    Token Size: {local_results['token_size_bytes']:.0f} bytes")
        
        print(f"\n[2] REMOTE ATTESTATION RESULTS:")
        print(f"    Success Rate: {remote_results['successful']}/{remote_results['iterations']} ({remote_results['successful']/remote_results['iterations']*100:.1f}%)")
        
        if remote_results['latencies']['total']:
            lats = remote_results['latencies']
            
            print(f"\n[3] LATENCY BREAKDOWN:")
            print(f"    Total (End-to-End):")
            print(f"      Mean:   {statistics.mean(lats['total']):.2f} ms")
            print(f"      Median: {statistics.median(lats['total']):.2f} ms")
            
            print(f"    Generation (Local):")
            print(f"      Mean:   {statistics.mean(lats['generation']):.2f} ms")
            
            print(f"    Network Transfer:")
            print(f"      Mean:   {statistics.mean(lats['network']):.2f} ms")
            
            print(f"    Verification (Remote):")
            print(f"      Mean:   {statistics.mean(lats['verification']):.2f} ms")
            
            # Calculate overheads
            total_mean = statistics.mean(lats['total'])
            gen_mean = statistics.mean(lats['generation'])
            net_mean = statistics.mean(lats['network'])
            
            print(f"\n[4] OVERHEAD ANALYSIS:")
            print(f"    Network Overhead: {net_mean:.2f} ms ({net_mean/total_mean*100:.1f}% of total)")
            print(f"    Remote Overhead (vs Local): +{total_mean - (local_results['mean_ms'] if local_results else 0):.2f} ms")
            
            print(f"\n[5] IMPLICATIONS FOR YOUR RESEARCH:")
            print(f"    • Adding SGX composition will increase generation time")
            print(f"    • Network latency is significant: {net_mean:.2f} ms")
            print(f"    • Hierarchical attestation should aim for <2x overhead")
            print(f"    • Current baseline: {gen_mean:.2f} ms (TDX only)")
            print(f"    • Target with SGX+TDX: <{gen_mean*2:.2f} ms")
        
        print("\n" + "=" * 70)
    
    def run_full_test(self, verifier_host: str = None, verifier_port: int = 9999):
        """Run complete remote attestation test"""
        print("=" * 70)
        print("Remote Attestation Test Suite")
        print("=" * 70)
        
        # Create verifier script
        self.create_verifier_script()
        
        if verifier_host is None:
            print("\nNo verifier host specified.")
            print("\nTo run full test:")
            print(f"  python3 {sys.argv[0]} --test <verifier-ip> [port]")
            print("\nSetup instructions:")
            print("  1. Copy verifier.py to remote machine")
            print("  2. On remote: python3 verifier.py")
            print("  3. On this machine: python3 remote_attestation_test_fixed.py --test <remote-ip>")
            return
        
        # Test local attestation
        print("\n" + "=" * 70)
        print("Phase 1: Local Attestation Baseline")
        print("=" * 70)
        local_results = self.test_local_attestation_generation(iterations=5)
        
        # Test remote attestation
        print("\n" + "=" * 70)
        print("Phase 2: Remote Attestation")
        print("=" * 70)
        remote_results = self.test_remote_attestation(
            verifier_host, 
            verifier_port, 
            iterations=10
        )
        
        # Analyze
        self.analyze_results(local_results, remote_results)
        
        # Save results
        output_file = f"remote_attestation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        results = {
            "timestamp": datetime.now().isoformat(),
            "verifier": f"{verifier_host}:{verifier_port}",
            "local_baseline": local_results,
            "remote_attestation": remote_results
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n✓ Results saved to: {output_file}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Remote Attestation Test')
    parser.add_argument('--test', metavar='HOST', help='Verifier host IP to test against')
    parser.add_argument('--port', type=int, default=9999, help='Verifier port (default: 9999)')
    parser.add_argument('--iterations', type=int, default=10, help='Number of test iterations')
    
    args = parser.parse_args()
    
    test = RemoteAttestationTest()
    
    if args.test:
        test.run_full_test(verifier_host=args.test, verifier_port=args.port)
    else:
        test.run_full_test()
