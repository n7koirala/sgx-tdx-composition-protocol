#!/usr/bin/env python3
"""
Decode and analyze TDX attestation token
Shows what information is in the token (relevant for linkability research)
"""

import json
import base64
import sys

def decode_jwt(token):
    """Decode JWT token without verification"""
    parts = token.split('.')
    
    if len(parts) != 3:
        print("Invalid JWT format")
        return None
    
    # Decode header
    header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_padded))
    
    # Decode payload
    payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_padded))
    
    return {
        "header": header,
        "payload": payload,
        "signature": parts[2][:50] + "..."  # Truncate signature
    }

def analyze_token(token_data):
    """Analyze token for linkable information"""
    payload = token_data['payload']
    
    print("=" * 70)
    print("TDX ATTESTATION TOKEN ANALYSIS")
    print("=" * 70)
    
    print("\n[1] TOKEN METADATA:")
    print(f"  Issuer: {payload.get('iss', 'N/A')}")
    print(f"  Issued At: {payload.get('iat', 'N/A')}")
    print(f"  Expires: {payload.get('exp', 'N/A')}")
    print(f"  Token ID (JTI): {payload.get('jti', 'N/A')}")
    
    if 'tdx' in payload:
        tdx = payload['tdx']
        
        print("\n[2] TDX MEASUREMENTS:")
        print(f"  MRTD (TD Measurement): {tdx.get('tdx_mrtd', 'N/A')[:32]}...")
        print(f"  MRSEAM: {tdx.get('tdx_mrseam', 'N/A')[:32]}...")
        print(f"  RTMR0: {tdx.get('tdx_rtmr0', 'N/A')[:32]}...")
        print(f"  RTMR1: {tdx.get('tdx_rtmr1', 'N/A')[:32]}...")
        
        print("\n[3] PLATFORM INFORMATION (POTENTIALLY LINKABLE!):")
        print(f"  TCB Status: {tdx.get('attester_tcb_status', 'N/A')}")
        print(f"  TCB Date: {tdx.get('attester_tcb_date', 'N/A')}")
        print(f"  Advisory IDs: {len(tdx.get('attester_advisory_ids', []))} advisories")
        
        if 'tdx_collateral' in tdx:
            coll = tdx['tdx_collateral']
            print(f"\n[4] TCB COLLATERAL (LINKABLE - Contains platform IDs):")
            print(f"  FMSPC: {coll.get('fmspc', 'N/A')}")
            print(f"  QE ID Hash: {coll.get('qeidhas h', 'N/A')[:32]}...")
            print(f"  TCB Eval Number: {coll.get('tcbevaluationdatanumber', 'N/A')}")
        
        print(f"\n[5] SECURITY ATTRIBUTES:")
        print(f"  Debug Mode: {tdx.get('tdx_is_debuggable', 'N/A')}")
        print(f"  SEPT VE Disabled: {tdx.get('tdx_td_attributes_septve_disable', 'N/A')}")
    
    print("\n[6] LINKABILITY CONCERNS:")
    print("  ⚠️  FMSPC identifies the platform family")
    print("  ⚠️  TCB collateral contains platform-specific hashes")
    print("  ⚠️  Advisory IDs reveal platform patch level")
    print("  ⚠️  Multiple attestations can be linked via these fields")
    
    print("\n[7] YOUR RESEARCH GOAL:")
    print("  ✓ Preserve: MRTD, RTMRs (TD-specific, not linkable)")
    print("  ✗ Anonymize: FMSPC, QE hashes, TCB collateral (platform-linkable)")
    
    print("=" * 70)

if __name__ == "__main__":
    # Get token from command line or file
    if len(sys.argv) > 1:
        token = sys.argv[1]
    else:
        print("Usage: python3 decode_token.py <JWT_TOKEN>")
        print("\nOr run: sudo trustauthority-cli token --tdx -c ~/config.json | tail -1 | python3 decode_token.py")
        sys.exit(1)
    
    # If reading from stdin
    if token == "-":
        token = sys.stdin.read().strip()
    
    # Remove any whitespace/newlines
    token = token.strip()
    
    try:
        token_data = decode_jwt(token)
        if token_data:
            # Print full JSON
            print("\n\nFULL TOKEN PAYLOAD (JSON):")
            print(json.dumps(token_data['payload'], indent=2))
            print("\n")
            
            # Analyze
            analyze_token(token_data)
            
            # Save to file
            with open("decoded_token.json", "w") as f:
                json.dump(token_data, f, indent=2)
            print(f"\n✓ Full token saved to: decoded_token.json")
    
    except Exception as e:
        print(f"Error decoding token: {e}")
        import traceback
        traceback.print_exc()
