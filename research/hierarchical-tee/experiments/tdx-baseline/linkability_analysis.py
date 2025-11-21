#!/usr/bin/env python3
"""
Analyze TDX attestation for linkable information
Identifies what needs to be anonymized in your protocol
"""

import subprocess
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Set

class LinkabilityAnalyzer:
    def __init__(self, config_path: str = "~/config.json"):
        self.config_path = config_path
    
    def collect_multiple_attestations(self, count: int = 10) -> List[Dict]:
        """Collect multiple attestations to analyze for linkable fields"""
        print(f"Collecting {count} attestations for linkability analysis...")
        
        attestations = []
        for i in range(count):
            result = subprocess.run(
                ["sudo", "trustauthority-cli", "evidence", "--tdx", "-c", self.config_path],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                try:
                    evidence = json.loads(result.stdout)
                    attestations.append(evidence)
                    print(f"  Collected {i+1}/{count}")
                except:
                    pass
            
            # Small delay
            import time
            time.sleep(1)
        
        return attestations
    
    def analyze_quote_fields(self, attestations: List[Dict]) -> Dict:
        """Analyze which fields are consistent (linkable) across attestations"""
        print("\nAnalyzing quote fields for linkability...")
        
        if not attestations or "tdx" not in attestations[0]:
            return {"error": "No valid attestations"}
        
        analysis = {
            "total_attestations": len(attestations),
            "linkable_fields": [],
            "variable_fields": [],
            "privacy_concerns": []
        }
        
        # Extract quotes (would need to decode base64 and parse in real implementation)
        quotes = [a["tdx"].get("quote", "") for a in attestations]
        
        # Check if quotes are identical (high linkability)
        unique_quotes = set(quotes)
        if len(unique_quotes) == 1:
            analysis["linkable_fields"].append({
                "field": "complete_quote",
                "status": "IDENTICAL across all attestations",
                "risk": "HIGH - Platform completely linkable"
            })
        else:
            analysis["variable_fields"].append({
                "field": "complete_quote",
                "unique_values": len(unique_quotes),
                "status": "Variable"
            })
        
        # Analyze event logs
        event_logs = [a["tdx"].get("event_log", "") for a in attestations]
        unique_logs = set(event_logs)
        
        if len(unique_logs) == 1:
            analysis["linkable_fields"].append({
                "field": "event_log",
                "status": "IDENTICAL",
                "risk": "MEDIUM - Boot configuration linkable"
            })
        
        # Privacy concerns summary
        analysis["privacy_concerns"] = [
            {
                "concern": "Platform Configuration Key (PCK)",
                "description": "TDX quotes include platform-specific identifiers",
                "mitigation": "Your hierarchical protocol should anonymize this"
            },
            {
                "concern": "TCB Information",
                "description": "Microcode versions, platform security version",
                "mitigation": "Group similar platforms or use zero-knowledge proofs"
            },
            {
                "concern": "MRTD (Measurement Register)",
                "description": "TD-specific measurement, constant for same VM",
                "mitigation": "Can be preserved as it's per-TD, not per-platform"
            }
        ]
        
        return analysis
    
    def extract_platform_identifiers(self, attestation: Dict) -> Dict:
        """Extract what could identify the platform"""
        print("\nExtracting platform identifiers...")
        
        identifiers = {
            "quote_signature": "Contains platform key material",
            "quote_header": "May contain platform info",
            "rtmr_values": "Runtime measurement registers (per-TD)",
            "Note": "Full parsing requires decoding base64 and understanding TDX quote structure"
        }
        
        # In real implementation, you'd decode the quote and extract:
        # - PPID (Platform Provisioning ID)
        # - CPUSVN (CPU Security Version Number)  
        # - PCESVN (PCE Security Version Number)
        # - QE Identity
        
        return identifiers
    
    def simulate_linkability_attack(self, attestations: List[Dict]) -> Dict:
        """Simulate how an adversary could link attestations"""
        print("\nSimulating linkability attack...")
        
        attack_results = {
            "attack": "Quote Comparison Attack",
            "method": "Compare raw quotes to link attestations to same platform",
            "success": None,
            "implications": []
        }
        
        # Check if any two attestations can be linked
        quotes = [a["tdx"].get("quote", "") for a in attestations]
        
        # Count how many unique quote signatures (simplified)
        unique_hashes = set(hashlib.sha256(q.encode()).hexdigest()[:16] for q in quotes)
        
        if len(unique_hashes) < len(quotes):
            attack_results["success"] = True
            attack_results["linkable_attestations"] = len(quotes) - len(unique_hashes)
            attack_results["implications"] = [
                "Platform can be tracked across attestations",
                "User privacy compromised",
                "Can build profile of platform usage patterns",
                "Your hierarchical protocol must prevent this"
            ]
        else:
            attack_results["success"] = False
            attack_results["note"] = "Quotes appear unique (may have nonces)"
        
        return attack_results
    
    def run_analysis(self, output_file: str = None):
        """Run complete linkability analysis"""
        print("=" * 60)
        print("TDX Attestation Linkability Analysis")
        print("=" * 60)
        
        # Collect attestations
        attestations = self.collect_multiple_attestations(count=10)
        
        if not attestations:
            print("❌ Failed to collect attestations")
            return
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "analysis": {}
        }
        
        # Run analyses
        results["analysis"]["quote_fields"] = self.analyze_quote_fields(attestations)
        results["analysis"]["platform_identifiers"] = self.extract_platform_identifiers(attestations[0])
        results["analysis"]["linkability_attack"] = self.simulate_linkability_attack(attestations)
        
        # Save results
        if output_file is None:
            output_file = f"linkability_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Print summary
        print("\n" + "=" * 60)
        print("LINKABILITY ANALYSIS SUMMARY")
        print("=" * 60)
        
        quote_analysis = results["analysis"]["quote_fields"]
        print(f"\nLinkable Fields Found: {len(quote_analysis.get('linkable_fields', []))}")
        for field in quote_analysis.get('linkable_fields', []):
            print(f"  - {field['field']}: {field['status']} (Risk: {field['risk']})")
        
        print(f"\nPrivacy Concerns:")
        for concern in quote_analysis.get('privacy_concerns', []):
            print(f"  - {concern['concern']}")
            print(f"    Mitigation: {concern['mitigation']}")
        
        print(f"\n✓ Results saved to: {output_file}")
        print("=" * 60)

if __name__ == "__main__":
    analyzer = LinkabilityAnalyzer()
    analyzer.run_analysis()
