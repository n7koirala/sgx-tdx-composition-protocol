#!/usr/bin/env python3
"""
Benchmark TDX Attestation Performance
Establishes baseline before SGX composition
"""

import subprocess
import time
import json
import statistics
from datetime import datetime
from typing import List, Dict

class TDXAttestationBenchmark:
    def __init__(self, config_path: str = "~/config.json"):
        self.config_path = config_path
        self.results = {}
    
    def benchmark_local_evidence_collection(self, iterations: int = 100) -> Dict:
        """Measure local TDX report generation time"""
        print(f"\n[1/5] Benchmarking local evidence collection ({iterations} iterations)...")
        
        latencies = []
        for i in range(iterations):
            start = time.perf_counter()
            
            # Run local evidence collection (without network call)
            result = subprocess.run(
                ["sudo", "trustauthority-cli", "evidence", "--tdx", "-c", self.config_path],
                capture_output=True,
                text=True
            )
            
            end = time.perf_counter()
            
            if result.returncode == 0:
                latencies.append((end - start) * 1000)  # Convert to ms
            
            if (i + 1) % 10 == 0:
                print(f"  Progress: {i+1}/{iterations}")
        
        return {
            "operation": "Local TDX Evidence Collection",
            "iterations": len(latencies),
            "mean_ms": statistics.mean(latencies),
            "median_ms": statistics.median(latencies),
            "stdev_ms": statistics.stdev(latencies) if len(latencies) > 1 else 0,
            "min_ms": min(latencies),
            "max_ms": max(latencies),
            "p95_ms": sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0,
            "p99_ms": sorted(latencies)[int(len(latencies) * 0.99)] if latencies else 0,
        }
    
    def benchmark_full_attestation(self, iterations: int = 50) -> Dict:
        """Measure full attestation with Intel Trust Authority (includes network)"""
        print(f"\n[2/5] Benchmarking full attestation with ITA ({iterations} iterations)...")
        
        latencies = []
        token_sizes = []
        
        for i in range(iterations):
            start = time.perf_counter()
            
            # Full attestation with token generation
            result = subprocess.run(
                ["sudo", "trustauthority-cli", "token", "--tdx", "-c", self.config_path],
                capture_output=True,
                text=True
            )
            
            end = time.perf_counter()
            
            if result.returncode == 0:
                latencies.append((end - start) * 1000)
                # Measure token size
                token_sizes.append(len(result.stdout))
            
            if (i + 1) % 5 == 0:
                print(f"  Progress: {i+1}/{iterations}")
            
            # Rate limit to avoid hitting API limits
            time.sleep(0.5)
        
        return {
            "operation": "Full TDX Attestation (with ITA)",
            "iterations": len(latencies),
            "mean_ms": statistics.mean(latencies),
            "median_ms": statistics.median(latencies),
            "stdev_ms": statistics.stdev(latencies) if len(latencies) > 1 else 0,
            "min_ms": min(latencies),
            "max_ms": max(latencies),
            "p95_ms": sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0,
            "p99_ms": sorted(latencies)[int(len(latencies) * 0.99)] if latencies else 0,
            "token_size_bytes": {
                "mean": statistics.mean(token_sizes) if token_sizes else 0,
                "min": min(token_sizes) if token_sizes else 0,
                "max": max(token_sizes) if token_sizes else 0
            }
        }
    
    def measure_evidence_size(self) -> Dict:
        """Measure sizes of TDX attestation artifacts"""
        print(f"\n[3/5] Measuring evidence sizes...")
        
        # Get evidence
        result = subprocess.run(
            ["sudo", "trustauthority-cli", "evidence", "--tdx", "-c", self.config_path],
            capture_output=True,
            text=True
        )
        
        sizes = {
            "operation": "TDX Evidence Sizes",
            "raw_output_bytes": len(result.stdout),
        }
        
        try:
            # Try to parse JSON output
            evidence = json.loads(result.stdout)
            if "tdx" in evidence:
                tdx_data = evidence["tdx"]
                if "quote" in tdx_data:
                    sizes["quote_base64_bytes"] = len(tdx_data["quote"])
                if "event_log" in tdx_data:
                    sizes["event_log_base64_bytes"] = len(tdx_data["event_log"])
        except:
            pass
        
        return sizes
    
    def benchmark_quote_generation_only(self, iterations: int = 100) -> Dict:
        """Benchmark just the quote generation (using C program)"""
        print(f"\n[4/5] Benchmarking TDX report generation ({iterations} iterations)...")
        
        # Compile the C program if not already done
        if not subprocess.run(["test", "-f", "~/get_tdx_report"], 
                             capture_output=True).returncode == 0:
            print("  Compiling TDX report generator...")
            # Assume it's already compiled from earlier
        
        latencies = []
        for i in range(iterations):
            start = time.perf_counter()
            
            result = subprocess.run(
                ["sudo", "~/get_tdx_report"],
                capture_output=True,
                text=True
            )
            
            end = time.perf_counter()
            
            if result.returncode == 0:
                latencies.append((end - start) * 1000)
            
            if (i + 1) % 10 == 0:
                print(f"  Progress: {i+1}/{iterations}")
        
        return {
            "operation": "TDX Report Generation (Hardware Only)",
            "iterations": len(latencies),
            "mean_ms": statistics.mean(latencies) if latencies else 0,
            "median_ms": statistics.median(latencies) if latencies else 0,
            "stdev_ms": statistics.stdev(latencies) if len(latencies) > 1 else 0,
            "min_ms": min(latencies) if latencies else 0,
            "max_ms": max(latencies) if latencies else 0,
        }
    
    def breakdown_attestation_phases(self) -> Dict:
        """Break down attestation into phases to identify bottlenecks"""
        print(f"\n[5/5] Breaking down attestation phases...")
        
        phases = {}
        
        # Phase 1: Quote generation
        start = time.perf_counter()
        subprocess.run(["sudo", "~/get_tdx_report"], capture_output=True)
        phases["quote_generation_ms"] = (time.perf_counter() - start) * 1000
        
        # Phase 2: Evidence collection (includes formatting)
        start = time.perf_counter()
        subprocess.run(
            ["sudo", "trustauthority-cli", "evidence", "--tdx", "-c", self.config_path],
            capture_output=True
        )
        phases["evidence_collection_ms"] = (time.perf_counter() - start) * 1000
        
        # Phase 3: Full attestation (includes network + verification)
        start = time.perf_counter()
        subprocess.run(
            ["sudo", "trustauthority-cli", "token", "--tdx", "-c", self.config_path],
            capture_output=True
        )
        phases["full_attestation_ms"] = (time.perf_counter() - start) * 1000
        
        # Calculate network overhead
        phases["network_overhead_ms"] = (
            phases["full_attestation_ms"] - phases["evidence_collection_ms"]
        )
        
        return {
            "operation": "Attestation Phase Breakdown",
            **phases
        }
    
    def run_all(self, output_file: str = None):
        """Run all benchmarks and save results"""
        print("=" * 60)
        print("TDX Attestation Baseline Benchmark Suite")
        print("=" * 60)
        
        self.results = {
            "timestamp": datetime.now().isoformat(),
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
        print("\n" + "=" * 60)
        print("BENCHMARK RESULTS SUMMARY")
        print("=" * 60)
        
        for benchmark in self.results["benchmarks"]:
            print(f"\n{benchmark['operation']}:")
            if 'mean_ms' in benchmark:
                print(f"  Mean:     {benchmark['mean_ms']:.3f} ms")
                print(f"  Median:   {benchmark['median_ms']:.3f} ms")
                print(f"  Std Dev:  {benchmark['stdev_ms']:.3f} ms")
                print(f"  P95:      {benchmark.get('p95_ms', 0):.3f} ms")
                print(f"  P99:      {benchmark.get('p99_ms', 0):.3f} ms")
                print(f"  Range:    [{benchmark['min_ms']:.3f}, {benchmark['max_ms']:.3f}] ms")
        
        print(f"\n✓ Results saved to: {output_file}")
        print("=" * 60)

if __name__ == "__main__":
    benchmark = TDXAttestationBenchmark()
    benchmark.run_all()
