#!/usr/bin/env python3
"""
Fixed: Analyze TDX attestation for linkable information
Identifies what needs to be anonymized in your protocol
"""

import subprocess
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Set
import time

class LinkabilityAnalyzer:
    def __init__(self, config_path: str = None):
        if config_path is None:
            import os
            self.config_path = os.path.expanduser("~/config.json")
        else:
            self.config_path = config_path
    
    def collect_multiple_attestations(self, count: int = 10) -> List[Dict]:
        """Collect multiple attestations to analyze for linkable fields"""
        print(f"Collecting {count} attestations for linkability analysis...")
        
        attestations = []
        failures = 0
        
        for i in range(count):
            try:
                # Use token command since it's more reliable
                result = subprocess.run(
                    ["sudo", "trustauthority-cli", "token", "--tdx", "-c", self.config_path],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                # Extract the JWT token from output
                if "eyJ" in result.stdout:
                    lines = result.stdout.strip().split('\n')
                    token = lines[-1]  # Token is usually the last line
                    
                    # Decode JWT to get payload
                    parts = token.split('.')
                    if len(parts) == 3:
                        import base64
                        payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
                        payload = json.loads(base64.urlsafe_b64decode(payload_padded))
                        
                        attestations.append({
                            "token": token,
                            "payload": payload,
                            "timestamp": datetime.now().isoformat()
                        })
                        
                        print(f"  ✓ Collected {i+1}/{count}")
                    else:
                        failures += 1
                        print(f"  ✗ Failed to parse token {i+1}")
                else:
                    failures += 1
                    if i == 0:  # Show first failure for debugging
                        print(f"  Debug - No token found in output:")
                        print(f"    Stdout: {result.stdout[:200]}")
                        print(f"    Stderr: {result.stderr[:200]}")
                
            except subprocess.TimeoutExpired:
                print(f"  ✗ Timeout collecting attestation {i+1}")
                failures += 1
            except Exception as e:
                print(f"  ✗ Error collecting attestation {i+1}: {e}")
                failures += 1
            
            # Rate limiting
            time.sleep(1.5)
        
        print(f"\nCollection complete: {len(attestations)} successes, {failures} failures")
        return attestations
    
    def analyze_token_fields(self, attestations: List[Dict]) -> Dict:
        """Analyze which fields are consistent (linkable) across attestations"""
        print("\nAnalyzing token fields for linkability...")
        
        if not attestations:
            return {"error": "No valid attestations to analyze"}
        
        analysis = {
            "total_attestations": len(attestations),
            "linkable_fields": [],
            "variable_fields": [],
            "privacy_concerns": []
        }
        
        # Extract TDX data from payloads
        tdx_data_list = []
        for att in attestations:
            if "payload" in att and "tdx" in att["payload"]:
                tdx_data_list.append(att["payload"]["tdx"])
        
        if not tdx_data_list:
            return {"error": "No TDX data found in attestations"}
        
        print(f"  Analyzing {len(tdx_data_list)} TDX payloads...")
        
        # Check key fields for consistency
        fields_to_check = {
            "tdx_mrtd": "TD Measurement (VM-specific, OK to keep)",
            "tdx_mrseam": "SEAM Module Measurement",
            "tdx_rtmr0": "Runtime Measurement Register 0",
            "tdx_rtmr1": "Runtime Measurement Register 1",
            "attester_tcb_status": "TCB Status",
            "attester_tcb_date": "TCB Date",
        }
        
        for field, description in fields_to_check.items():
            values = [td.get(field) for td in tdx_data_list if field in td]
            unique_values = set(values)
            
            if len(unique_values) == 1 and values:
                analysis["linkable_fields"].append({
                    "field": field,
                    "description": description,
                    "status": "IDENTICAL across all attestations",
                    "value_preview": str(values[0])[:40] + "...",
                    "risk": "HIGH" if "tcb" in field.lower() else "MEDIUM"
                })
            elif len(unique_values) > 1:
                analysis["variable_fields"].append({
                    "field": field,
                    "description": description,
                    "unique_values": len(unique_values),
                    "status": "Variable"
                })
        
        # Check collateral (platform-specific info)
        if "tdx_collateral" in tdx_data_list[0]:
            collateral_fields = tdx_data_list[0]["tdx_collateral"].keys()
            
            for coll_field in collateral_fields:
                values = [td.get("tdx_collateral", {}).get(coll_field) 
                         for td in tdx_data_list]
                unique_values = set(str(v) for v in values if v is not None)
                
                if len(unique_values) == 1:
                    analysis["linkable_fields"].append({
                        "field": f"tdx_collateral.{coll_field}",
                        "description": "Platform TCB Collateral",
                        "status": "IDENTICAL - PLATFORM LINKABLE!",
                        "value_preview": str(list(unique_values)[0])[:40] + "...",
                        "risk": "CRITICAL"
                    })
        
        # Advisory IDs
        advisory_sets = [set(td.get("attester_advisory_ids", [])) 
                        for td in tdx_data_list]
        if len(set(frozenset(s) for s in advisory_sets)) == 1:
            analysis["linkable_fields"].append({
                "field": "attester_advisory_ids",
                "description": "Platform Security Advisories",
                "status": "IDENTICAL - reveals platform patch level",
                "risk": "HIGH"
            })
        
        # Privacy concerns
        analysis["privacy_concerns"] = [
            {
                "concern": "Platform Configuration Key (PCK)",
                "description": "Embedded in TCB collateral - uniquely identifies platform",
                "mitigation": "Use group signatures or anonymous credentials",
                "severity": "CRITICAL"
            },
            {
                "concern": "FMSPC (Family-Model-Stepping-Platform-Custom SKU)",
                "description": "Identifies the platform family and configuration",
                "mitigation": "Anonymize via k-anonymity or zero-knowledge proofs",
                "severity": "HIGH"
            },
            {
                "concern": "TCB Information Hashes",
                "description": "QE, TCBInfo hashes can link attestations to same platform",
                "mitigation": "Your hierarchical protocol should mask these",
                "severity": "HIGH"
            },
            {
                "concern": "Security Version Numbers",
                "description": "Reveals exact microcode/firmware versions",
                "mitigation": "Generalize to version ranges",
                "severity": "MEDIUM"
            }
        ]
        
        return analysis
    
    def extract_platform_identifiers(self, attestation: Dict) -> Dict:
        """Extract what could identify the platform"""
        print("\nExtracting platform identifiers...")
        
        if "payload" not in attestation or "tdx" not in attestation["payload"]:
            return {"error": "No TDX data in attestation"}
        
        tdx = attestation["payload"]["tdx"]
        
        identifiers = {
            "platform_specific": {},
            "td_specific": {},
            "note": "Platform-specific fields enable linkability"
        }
        
        # Platform-specific (LINKABLE)
        if "tdx_collateral" in tdx:
            coll = tdx["tdx_collateral"]
            identifiers["platform_specific"]["FMSPC"] = coll.get("fmspc", "N/A")
            identifiers["platform_specific"]["QE_ID_Hash"] = coll.get("qeidhash", "N/A")[:16] + "..."
            identifiers["platform_specific"]["TCB_Eval_Number"] = coll.get("tcbevaluationdatanumber", "N/A")
        
        identifiers["platform_specific"]["TCB_Status"] = tdx.get("attester_tcb_status", "N/A")
        identifiers["platform_specific"]["TCB_Date"] = tdx.get("attester_tcb_date", "N/A")
        identifiers["platform_specific"]["Advisory_IDs"] = tdx.get("attester_advisory_ids", [])
        
        # TD-specific (NOT linkable across VMs)
        identifiers["td_specific"]["MRTD"] = tdx.get("tdx_mrtd", "N/A")[:16] + "..."
        identifiers["td_specific"]["RTMR0"] = tdx.get("tdx_rtmr0", "N/A")[:16] + "..."
        identifiers["td_specific"]["RTMR1"] = tdx.get("tdx_rtmr1", "N/A")[:16] + "..."
        
        return identifiers
    
    def simulate_linkability_attack(self, attestations: List[Dict]) -> Dict:
        """Simulate how an adversary could link attestations"""
        print("\nSimulating linkability attack...")
        
        attack_results = {
            "attack_type": "Token Fingerprinting Attack",
            "method": "Compare platform-specific fields across attestations",
            "linkable_attestations": 0,
            "fingerprints": {},
            "success": False,
            "implications": []
        }
        
        # Create fingerprints based on platform-specific info
        for i, att in enumerate(attestations):
            if "payload" in att and "tdx" in att["payload"]:
                tdx = att["payload"]["tdx"]
                
                # Create a fingerprint from platform-specific fields
                fingerprint_data = {
                    "fmspc": tdx.get("tdx_collateral", {}).get("fmspc", ""),
                    "tcb_status": tdx.get("attester_tcb_status", ""),
                    "advisories": tuple(sorted(tdx.get("attester_advisory_ids", [])))
                }
                
                fingerprint = hashlib.sha256(
                    json.dumps(fingerprint_data, sort_keys=True).encode()
                ).hexdigest()[:16]
                
                if fingerprint not in attack_results["fingerprints"]:
                    attack_results["fingerprints"][fingerprint] = []
                
                attack_results["fingerprints"][fingerprint].append(i)
        
        # Analyze results
        unique_fingerprints = len(attack_results["fingerprints"])
        total_attestations = len(attestations)
        
        if unique_fingerprints < total_attestations:
            attack_results["success"] = True
            attack_results["linkable_attestations"] = total_attestations - unique_fingerprints
            attack_results["implications"] = [
                f"✗ Platform can be tracked across {total_attestations} attestations",
                f"✗ Only {unique_fingerprints} unique fingerprints found",
                "✗ User privacy is compromised",
                "✗ Can build profile of VM usage patterns",
                "✓ Your hierarchical protocol MUST prevent this"
            ]
        else:
            attack_results["success"] = False
            attack_results["note"] = "Each attestation has unique fingerprint (unusual)"
            attack_results["implications"] = [
                "✓ Attestations appear unlinkable in this sample",
                "⚠ However, platform info is still present",
                "⚠ Larger sample might reveal linkability"
            ]
        
        return attack_results
    
    def generate_recommendations(self, analysis_results: Dict) -> List[str]:
        """Generate recommendations for your protocol"""
        recommendations = [
            "PROTOCOL DESIGN RECOMMENDATIONS:",
            "",
            "1. ANONYMIZE Platform-Specific Fields:",
            "   - FMSPC: Use k-anonymity or group into families",
            "   - TCB collateral hashes: Replace with range proofs",
            "   - Advisory IDs: Generalize to minimum required set",
            "",
            "2. PRESERVE TD-Specific Fields:",
            "   - MRTD: Keep as-is (VM-specific, not platform-linkable)",
            "   - RTMRs: Keep as-is (runtime measurements)",
            "",
            "3. HIERARCHICAL COMPOSITION:",
            "   - SGX layer: Attests to application/enclave",
            "   - TDX layer: Attests to VM, but anonymizes platform",
            "   - Composition proof: Binds layers without leaking platform ID",
            "",
            "4. CRYPTOGRAPHIC TECHNIQUES:",
            "   - Group signatures for platform anonymity",
            "   - Zero-knowledge proofs for TCB compliance",
            "   - Blind signatures for attestation tokens",
            "",
            "5. VERIFICATION STRATEGY:",
            "   - Verifier checks: TD measurements, security properties",
            "   - Verifier does NOT learn: Platform ID, exact TCB versions",
            "   - Privacy-preserving verification of TCB compliance"
        ]
        
        return recommendations
    
    def run_analysis(self, output_file: str = None):
        """Run complete linkability analysis"""
        print("=" * 70)
        print("TDX Attestation Linkability Analysis")
        print("=" * 70)
        
        # Collect attestations
        attestations = self.collect_multiple_attestations(count=10)
        
        if not attestations:
            print("\n❌ Failed to collect attestations")
            print("\nTroubleshooting:")
            print("1. Check that Intel Trust Authority API key is valid")
            print("2. Verify network connectivity to api.trustauthority.intel.com")
            print("3. Try running manually: sudo trustauthority-cli token --tdx -c ~/config.json")
            return
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "analysis": {}
        }
        
        # Run analyses
        results["analysis"]["token_fields"] = self.analyze_token_fields(attestations)
        results["analysis"]["platform_identifiers"] = self.extract_platform_identifiers(attestations[0])
        results["analysis"]["linkability_attack"] = self.simulate_linkability_attack(attestations)
        results["analysis"]["recommendations"] = self.generate_recommendations(results["analysis"])
        
        # Save results
        if output_file is None:
            output_file = f"linkability_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Print summary
        self._print_summary(results)
        
        print(f"\n✓ Results saved to: {output_file}")
        print("=" * 70)
    
    def _print_summary(self, results: Dict):
        """Print formatted summary"""
        print("\n" + "=" * 70)
        print("LINKABILITY ANALYSIS SUMMARY")
        print("=" * 70)
        
        token_analysis = results["analysis"]["token_fields"]
        
        if "error" not in token_analysis:
            print(f"\n[1] LINKABLE FIELDS: {len(token_analysis.get('linkable_fields', []))}")
            for field in token_analysis.get('linkable_fields', [])[:5]:  # Show first 5
                risk_emoji = "🔴" if field['risk'] in ['CRITICAL', 'HIGH'] else "🟡"
                print(f"  {risk_emoji} {field['field']}")
                print(f"     {field['description']}")
                print(f"     Status: {field['status']}")
                print(f"     Risk: {field['risk']}")
            
            if len(token_analysis.get('linkable_fields', [])) > 5:
                print(f"  ... and {len(token_analysis['linkable_fields']) - 5} more")
            
            print(f"\n[2] PRIVACY CONCERNS:")
            for concern in token_analysis.get('privacy_concerns', [])[:3]:
                print(f"  ⚠️  {concern['concern']}")
                print(f"     {concern['description']}")
                print(f"     Mitigation: {concern['mitigation']}")
        
        attack_results = results["analysis"]["linkability_attack"]
        print(f"\n[3] LINKABILITY ATTACK SIMULATION:")
        if attack_results.get("success"):
            print(f"  ❌ Attack SUCCESS - Platform is linkable!")
            print(f"  📊 {attack_results.get('linkable_attestations', 0)} attestations can be linked")
        else:
            print(f"  ✓ Attack failed in this sample")
        
        for impl in attack_results.get("implications", [])[:3]:
            print(f"     {impl}")
        
        print(f"\n[4] RECOMMENDATIONS FOR YOUR PROTOCOL:")
        for rec in results["analysis"]["recommendations"][:8]:
            print(f"  {rec}")

if __name__ == "__main__":
    analyzer = LinkabilityAnalyzer()
    analyzer.run_analysis()
