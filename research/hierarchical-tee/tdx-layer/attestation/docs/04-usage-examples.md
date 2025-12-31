# TDX Attestation Usage Examples

## Basic Usage

### 1. Generate and Verify TDX Attestation

```python
#!/usr/bin/env python3
from tdx_remote_attestation import TDXAttestor

# Initialize attestor
attestor = TDXAttestor()

# Get attestation token from Intel Trust Authority
token = attestor.get_attestation_token()

# Print key measurements
print(f"MRTD: {token.mrtd}")
print(f"Report Data: {token.report_data}")
print(f"TCB Status: {token.tcb_status}")
print(f"Debuggable: {token.is_debuggable}")

# Check validity
if token.is_valid():
    print("✓ Token is valid")
else:
    print("✗ Token has expired")
```

### 2. Generate Evidence Only (No Intel TA Call)

```python
from tdx_remote_attestation import TDXAttestor

attestor = TDXAttestor()

# Generate local evidence (faster, no network)
evidence = attestor.get_evidence()

print(f"Quote length: {len(evidence.quote)} bytes")
print(f"Timestamp: {evidence.timestamp}")

# Save quote for later verification
with open("tdx_quote.b64", "w") as f:
    f.write(evidence.quote)
```

### 3. Include Custom User Data

```python
import base64
from tdx_remote_attestation import TDXAttestor

attestor = TDXAttestor()

# Encode custom data
custom_data = "my-nonce-12345"
user_data = base64.b64encode(custom_data.encode()).decode()

# Get attestation with custom data
token = attestor.get_attestation_token(user_data=user_data)

# The custom data will be reflected in report_data
print(f"Report Data: {token.report_data}")
```

---

## Remote Verification

### 4. Send Attestation to Remote Verifier

```python
import socket
import json
from tdx_remote_attestation import TDXAttestor

VERIFIER_HOST = "10.128.0.5"  # SGX machine IP
VERIFIER_PORT = 9999

# Generate attestation
attestor = TDXAttestor()
token = attestor.get_attestation_token()

# Send to verifier
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((VERIFIER_HOST, VERIFIER_PORT))
sock.sendall(token.raw_token.encode())
sock.shutdown(socket.SHUT_WR)

# Receive response
response = sock.recv(4096)
sock.close()

# Parse result
result = json.loads(response.decode())
if result["verified"]:
    print("✓ TD is TRUSTED")
else:
    print(f"✗ Verification failed: {result.get('error')}")
```

### 5. Run Verifier Service

```python
from tdx_verifier_service import TDXVerifierService

# Create and run verifier
service = TDXVerifierService(port=9999)
service.run()  # Blocks and listens for connections
```

Or from command line:
```bash
python3 tdx_verifier_service.py 9999
```

---

## SGX Integration

### 6. Bind TDX to SGX Enclave

```python
from tdx_remote_attestation import TDXAttestor

attestor = TDXAttestor()

# Your SGX enclave's MRENCLAVE (from gramine-sgx-sigstruct-view)
sgx_mrenclave = "05b8e0fe8118ceb23099e92fb9be99d154a043d62626624cf0e9de40390cf0e3"

# Generate bound attestation
binding_hash, token = attestor.get_binding_data(sgx_mrenclave=sgx_mrenclave)

print(f"Binding hash: {binding_hash}")
print(f"Token report_data: {token.report_data}")

# The verifier can check that report_data matches the expected binding
```

### 7. Verify Binding on Verifier Side

```python
import hashlib
import json
from tdx_verifier_service import TDXTokenVerifier

def verify_sgx_binding(token_str: str, expected_mrenclave: str) -> bool:
    """Verify TDX token is bound to expected SGX enclave"""
    
    verifier = TDXTokenVerifier()
    verified, result = verifier.verify(token_str)
    
    if not verified:
        return False
    
    # Reconstruct expected binding
    binding_data = {
        "timestamp": "...",  # Would need to match
        "purpose": "hierarchical-tee-composition",
        "sgx_mrenclave": expected_mrenclave
    }
    binding_json = json.dumps(binding_data, sort_keys=True)
    expected_hash = hashlib.sha256(binding_json.encode()).hexdigest()
    
    # Compare with report_data in token
    actual_report_data = result["tdx"]["report_data"]
    
    # Check if binding matches (first 32 chars of hash)
    return actual_report_data.startswith(expected_hash[:32])
```

---

## Benchmarking

### 8. Measure Attestation Performance

```python
import time
from tdx_remote_attestation import TDXAttestor

attestor = TDXAttestor()

# Benchmark evidence generation
times = []
for i in range(10):
    start = time.perf_counter()
    evidence = attestor.get_evidence()
    elapsed = (time.perf_counter() - start) * 1000
    times.append(elapsed)
    print(f"Evidence {i+1}: {elapsed:.2f} ms")

print(f"\nEvidence generation:")
print(f"  Mean: {sum(times)/len(times):.2f} ms")
print(f"  Min:  {min(times):.2f} ms")
print(f"  Max:  {max(times):.2f} ms")

# Note: Token generation has rate limits, don't benchmark aggressively
```

---

## Error Handling

### 9. Handle Common Errors

```python
from tdx_remote_attestation import TDXAttestor

try:
    attestor = TDXAttestor()
except RuntimeError as e:
    if "TDX device not found" in str(e):
        print("Not running in a TDX VM")
    elif "config file not found" in str(e):
        print("Create ~/config.json with Intel TA credentials")
    elif "trustauthority-cli not found" in str(e):
        print("Install trustauthority-cli")
    raise

try:
    token = attestor.get_attestation_token()
except RuntimeError as e:
    if "429" in str(e) or "rate" in str(e).lower():
        print("Rate limited - wait and retry")
        time.sleep(60)
        token = attestor.get_attestation_token()
    else:
        raise
```

### 10. Graceful Degradation

```python
from tdx_remote_attestation import TDXAttestor

def get_attestation_with_retry(max_retries=3, delay=10):
    """Get attestation with retry logic for rate limits"""
    attestor = TDXAttestor()
    
    for attempt in range(max_retries):
        try:
            return attestor.get_attestation_token()
        except RuntimeError as e:
            if "429" in str(e):
                print(f"Rate limited, waiting {delay}s (attempt {attempt+1}/{max_retries})")
                time.sleep(delay)
                delay *= 2  # Exponential backoff
            else:
                raise
    
    raise RuntimeError("Max retries exceeded")
```

---

## Saving and Loading

### 11. Save Token for Later Use

```python
import json
from tdx_remote_attestation import TDXAttestor

attestor = TDXAttestor()
token = attestor.get_attestation_token()

# Save raw token
with open("attestation_token.jwt", "w") as f:
    f.write(token.raw_token)

# Save parsed data
with open("attestation_data.json", "w") as f:
    json.dump(token.to_dict(), f, indent=2)
```

### 12. Load and Parse Saved Token

```python
from tdx_remote_attestation import TDXAttestor

attestor = TDXAttestor()

# Load raw token
with open("attestation_token.jwt", "r") as f:
    token_str = f.read()

# Parse it
token = attestor.parse_token(token_str)

# Verify it's still valid
is_valid, message = attestor.verify_token_locally(token)
print(f"Token valid: {is_valid} - {message}")
```

---

## Complete Example: End-to-End Flow

### 13. Full Attestation and Verification

```python
#!/usr/bin/env python3
"""
Complete TDX attestation flow example
"""

import socket
import json
import time
from tdx_remote_attestation import TDXAttestor

def main():
    # Configuration
    VERIFIER_HOST = "10.128.0.5"
    VERIFIER_PORT = 9999
    SGX_MRENCLAVE = None  # Set if doing hierarchical binding
    
    print("=" * 60)
    print("TDX Remote Attestation - Complete Flow")
    print("=" * 60)
    
    # Step 1: Initialize
    print("\n[1] Initializing...")
    attestor = TDXAttestor()
    
    # Step 2: Generate attestation
    print("[2] Generating attestation...")
    start = time.perf_counter()
    
    if SGX_MRENCLAVE:
        binding_hash, token = attestor.get_binding_data(sgx_mrenclave=SGX_MRENCLAVE)
        print(f"    Bound to SGX: {SGX_MRENCLAVE[:16]}...")
    else:
        token = attestor.get_attestation_token()
    
    gen_time = (time.perf_counter() - start) * 1000
    print(f"    Generated in {gen_time:.2f} ms")
    
    # Step 3: Display measurements
    print("\n[3] TDX Measurements:")
    print(f"    MRTD:     {token.mrtd[:32]}...")
    print(f"    TCB:      {token.tcb_status}")
    print(f"    Debug:    {token.is_debuggable}")
    
    # Step 4: Send to verifier
    print(f"\n[4] Sending to {VERIFIER_HOST}:{VERIFIER_PORT}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect((VERIFIER_HOST, VERIFIER_PORT))
        sock.sendall(token.raw_token.encode())
        sock.shutdown(socket.SHUT_WR)
        
        response = sock.recv(4096)
        sock.close()
        
        result = json.loads(response.decode())
        
        if result.get("verified"):
            print("    ✓ VERIFIED - TD is TRUSTED")
        else:
            print(f"    ✗ FAILED: {result.get('error')}")
            
    except Exception as e:
        print(f"    ✗ Connection failed: {e}")
        print("    (Is the verifier running?)")
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    main()
```
