#!/usr/bin/env python3
"""
Fixed Benchmark TDX Attestation Performance
Handles non-zero exit codes and provides better debugging
"""

import subprocess
import time
import json
import statistics
from datetime import datetime
from typing import List, Dict

class TDXAttestationBenchmark:
    def __init__(self, config_path: str = None):
        if config_path is None:
            import os
            self.config_path = os.path.expanduser("~/config.json")
        else:
            self.config_path = config_path
        self.results = {}
    
    def benchmark_local_evidence_collection(self, iterations: int = 50) -> Dict:
        """Measure local TDX evidence collection time"""
        print(f"\n[1/5] Benchmarking local evidence collection ({iterations} iterations)...")
        
        latencies = []
        successes = 0
        failures = 0
        
        for i in range(iterations):
            start = time.perf_counter()
            
            # Run local evidence collection
            result = subprocess.run(
                ["sudo", "trustauthority-cli", "evidence", "--tdx", "-c", self.config_path],
                capture_output=True,
                text=True
            )
            
            end = time.perf_counter()
            
            # Check if we got output (sometimes succeeds with non-zero exit code)
            has_output = len(result.stdout) > 0 or "Trace Id" in result.stdout
            
            if result.returncode == 0 or has_output:
                latencies.append((end - start) * 1000)  # Convert to ms
                successes += 1
            else:
                failures += 1
                if i == 0:  # Print first failure for debugging
                    print(f"  First failure - Return code: {result.returncode}")
                    print(f"  Stdout: {result.stdout[:200]}")
                    print(f"  Stderr: {result.stderr[:200]}")
            
            if (i + 1) % 10 == 0:
                print(f"  Progress: {i+1}/{iterations} (successes: {successes}, failures: {failures})")
        
        if not latencies:
            return {
                "operation": "Local TDX Evidence Collection",
                "error": "No successful iterations",
                "total_attempts": iterations,
                "failures": failures
            }
        
        return {
            "operation": "Local TDX Evidence Collection",
            "iterations": len(latencies),
            "successes": successes,
            "failures": failures,
            "mean_ms": statistics.mean(latencies),
            "median_ms": statistics.median(latencies),
            "stdev_ms": statistics.stdev(latencies) if len(latencies) > 1 else 0,
            "min_ms": min(latencies),
            "max_ms": max(latencies),
            "p95_ms": sorted(latencies)[int(len(latencies) * 0.95)] if len(latencies) > 1 else latencies[0],
            "p99_ms": sorted(latencies)[int(len(latencies) * 0.99)] if len(latencies) > 1 else latencies[0],
        }
    
    def benchmark_full_attestation(self, iterations: int = 20) -> Dict:
        """Measure full attestation with Intel Trust Authority"""
        print(f"\n[2/5] Benchmarking full attestation with ITA ({iterations} iterations)...")
        
        latencies = []
        token_sizes = []
        successes = 0
        
        for i in range(iterations):
            start = time.perf_counter()
            
            result = subprocess.run(
                ["sudo", "trustauthority-cli", "token", "--tdx", "-c", self.config_path],
                capture_output=True,
                text=True
            )
            
            end = time.perf_counter()
            
            # Token command outputs JWT token in stdout
            if "eyJ" in result.stdout:  # JWT tokens start with eyJ
                latencies.append((end - start) * 1000)
                # Extract just the token (last line usually)
                lines = result.stdout.strip().split('\n')
                token = lines[-1]
                token_sizes.append(len(token))
                successes += 1
            
            if (i + 1) % 5 == 0:
                print(f"  Progress: {i+1}/{iterations} (successes: {successes})")
            
            # Rate limit to avoid API throttling
            time.sleep(1)
        
        if not latencies:
            return {
                "operation": "Full TDX Attestation (with ITA)",
                "error": "No successful attestations",
                "total_attempts": iterations
            }
        
        return {
            "operation": "Full TDX Attestation (with ITA)",
            "iterations": len(latencies),
            "successes": successes,
            "mean_ms": statistics.mean(latencies),
            "median_ms": statistics.median(latencies),
            "stdev_ms": statistics.stdev(latencies) if len(latencies) > 1 else 0,
            "min_ms": min(latencies),
            "max_ms": max(latencies),
            "p95_ms": sorted(latencies)[int(len(latencies) * 0.95)] if len(latencies) > 1 else latencies[0],
            "p99_ms": sorted(latencies)[int(len(latencies) * 0.99)] if len(latencies) > 1 else latencies[0],
            "token_size_bytes": {
                "mean": statistics.mean(token_sizes) if token_sizes else 0,
                "median": statistics.median(token_sizes) if token_sizes else 0,
                "min": min(token_sizes) if token_sizes else 0,
                "max": max(token_sizes) if token_sizes else 0
            }
        }
    
    def measure_evidence_size(self) -> Dict:
        """Measure sizes of TDX attestation artifacts"""
        print(f"\n[3/5] Measuring evidence and token sizes...")
        
        sizes = {"operation": "TDX Evidence and Token Sizes"}
        
        # Get evidence
        result = subprocess.run(
            ["sudo", "trustauthority-cli", "evidence", "--tdx", "-c", self.config_path],
            capture_output=True,
            text=True
        )
        
        sizes["evidence_raw_output_bytes"] = len(result.stdout)
        
        # Get token
        result = subprocess.run(
            ["sudo", "trustauthority-cli", "token", "--tdx", "-c", self.config_path],
            capture_output=True,
            text=True
        )
        
        # Extract token
        if "eyJ" in result.stdout:
            lines = result.stdout.strip().split('\n')
            token = lines[-1]
            sizes["token_jwt_bytes"] = len(token)
            
            # Decode JWT to get payload size (rough estimate)
            parts = token.split('.')
            if len(parts) == 3:
                sizes["token_header_bytes"] = len(parts[0])
                sizes["token_payload_bytes"] = len(parts[1])
                sizes["token_signature_bytes"] = len(parts[2])
        
        return sizes
    
    def benchmark_quote_generation_only(self, iterations: int = 100) -> Dict:
        """Benchmark just the TDX report generation using C program"""
        print(f"\n[4/5] Benchmarking TDX report generation ({iterations} iterations)...")
        
        import os
        report_program = os.path.expanduser("~/get_tdx_report")
        
        if not os.path.exists(report_program):
            return {
                "operation": "TDX Report Generation (Hardware Only)",
                "error": "get_tdx_report program not found",
                "note": "Run the C program compilation from earlier steps"
            }
        
        latencies = []
        for i in range(iterations):
            start = time.perf_counter()
            
            result = subprocess.run(
                ["sudo", report_program],
                capture_output=True,
                text=True
            )
            
            end = time.perf_counter()
            
            if "Successfully generated TDX report" in result.stdout:
                latencies.append((end - start) * 1000)
            
            if (i + 1) % 20 == 0:
                print(f"  Progress: {i+1}/{iterations}")
        
        if not latencies:
            return {
                "operation": "TDX Report Generation (Hardware Only)",
                "error": "No successful report generations"
            }
        
        return {
            "operation": "TDX Report Generation (Hardware Only)",
            "iterations": len(latencies),
            "mean_ms": statistics.mean(latencies),
            "median_ms": statistics.median(latencies),
            "stdev_ms": statistics.stdev(latencies) if len(latencies) > 1 else 0,
            "min_ms": min(latencies),
            "max_ms": max(latencies),
            "p95_ms": sorted(latencies)[int(len(latencies) * 0.95)] if len(latencies) > 1 else latencies[0],
        }
    
    def breakdown_attestation_phases(self) -> Dict:
        """Break down attestation into phases"""
        print(f"\n[5/5] Breaking down attestation phases...")
        
        phases = {"operation": "Attestation Phase Breakdown"}
        
        import os
        report_program = os.path.expanduser("~/get_tdx_report")
        
        # Phase 1: Quote generation (if available)
        if os.path.exists(report_program):
            times = []
            for _ in range(5):
                start = time.perf_counter()
                subprocess.run(["sudo", report_program], capture_output=True)
                times.append((time.perf_counter() - start) * 1000)
            phases["quote_generation_mean_ms"] = statistics.mean(times)
        
        # Phase 2: Evidence collection
        times = []
        for _ in range(5):
            start = time.perf_counter()
            subprocess.run(
                ["sudo", "trustauthority-cli", "evidence", "--tdx", "-c", self.config_path],
                capture_output=True
            )
            times.append((time.perf_counter() - start) * 1000)
        phases["evidence_collection_mean_ms"] = statistics.mean(times)
        
        # Phase 3: Full attestation
        times = []
        for _ in range(5):
            start = time.perf_counter()
            subprocess.run(
                ["sudo", "trustauthority-cli", "token", "--tdx", "-c", self.config_path],
                capture_output=True
            )
            times.append((time.perf_counter() - start) * 1000)
            time.sleep(0.5)
        phases["full_attestation_mean_ms"] = statistics.mean(times)
        
        # Calculate overheads
        if "evidence_collection_mean_ms" in phases and "quote_generation_mean_ms" in phases:
            phases["formatting_overhead_ms"] = (
                phases["evidence_collection_mean_ms"] - phases["quote_generation_mean_ms"]
            )
        
        if "full_attestation_mean_ms" in phases and "evidence_collection_mean_ms" in phases:
            phases["network_verification_overhead_ms"] = (
                phases["full_attestation_mean_ms"] - phases["evidence_collection_mean_ms"]
            )
        
        return phases
    
    def run_all(self, output_file: str = None):
        """Run all benchmarks and save results"""
        print("=" * 70)
        print("TDX Attestation Baseline Benchmark Suite")
        print("=" * 70)
        
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "platform": "Google Cloud C3 with Intel TDX",
            "benchmarks": []
        }
        
        # Run benchmarks
        self.results["benchmarks"].append(
            self.benchmark_quote_generation_only(iterations=100)
        )
        self.results["benchmarks"].append(
            self.benchmark_local_evidence_collection(iterations=50)
        )
        self.results["benchmarks"].append(
            self.benchmark_full_attestation(iterations=20)
        )
        self.results["benchmarks"].append(
            self.measure_evidence_size()
        )
        self.results["benchmarks"].append(
            self.breakdown_attestation_phases()
        )
        
        # Save results
        if output_file is None:
            output_file = f"tdx_baseline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Print summary
        self._print_summary()
        
        print(f"\n✓ Results saved to: {output_file}")
        print("=" * 70)
    
    def _print_summary(self):
        """Print formatted summary"""
        print("\n" + "=" * 70)
        print("BENCHMARK RESULTS SUMMARY")
        print("=" * 70)
        
        for benchmark in self.results["benchmarks"]:
            print(f"\n{benchmark['operation']}:")
            
            if 'error' in benchmark:
                print(f"  ❌ {benchmark['error']}")
                continue
            
            if 'mean_ms' in benchmark:
                print(f"  Iterations: {benchmark.get('iterations', 'N/A')}")
                print(f"  Mean:       {benchmark['mean_ms']:.3f} ms")
                print(f"  Median:     {benchmark['median_ms']:.3f} ms")
                print(f"  Std Dev:    {benchmark['stdev_ms']:.3f} ms")
                if 'p95_ms' in benchmark:
                    print(f"  P95:        {benchmark['p95_ms']:.3f} ms")
                if 'p99_ms' in benchmark:
                    print(f"  P99:        {benchmark['p99_ms']:.3f} ms")
                print(f"  Range:      [{benchmark['min_ms']:.3f}, {benchmark['max_ms']:.3f}] ms")
                
                if 'token_size_bytes' in benchmark:
                    token_size = benchmark['token_size_bytes']
                    print(f"  Token Size: {token_size['mean']:.0f} bytes (avg)")
            
            elif 'quote_generation_mean_ms' in benchmark:
                # Phase breakdown
                for key, value in benchmark.items():
                    if key != 'operation' and isinstance(value, (int, float)):
                        print(f"  {key.replace('_', ' ').title()}: {value:.3f}")
            
            else:
                # Size measurements
                for key, value in benchmark.items():
                    if key != 'operation' and isinstance(value, (int, float)):
                        print(f"  {key.replace('_', ' ').title()}: {value} bytes")

if __name__ == "__main__":
    benchmark = TDXAttestationBenchmark()
    benchmark.run_all()
