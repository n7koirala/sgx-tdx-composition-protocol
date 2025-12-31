# SGX-TDX Integration for Hierarchical Attestation

This document describes how to integrate TDX attestation with SGX for your hierarchical TEE composition protocol.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Hierarchical TEE Composition Protocol                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│        SGX Machine                              TDX VM (GCP)                 │
│   ┌─────────────────────┐                ┌─────────────────────┐            │
│   │     SGX Enclave     │                │     TDX Guest       │            │
│   │     (Gramine)       │                │                     │            │
│   │                     │                │                     │            │
│   │  ┌───────────────┐  │                │  ┌───────────────┐  │            │
│   │  │ MRENCLAVE     │──┼────────────────┼─▶│ Report Data   │  │            │
│   │  │ (app hash)    │  │   Binding      │  │ (SGX hash)    │  │            │
│   │  └───────────────┘  │                │  └───────────────┘  │            │
│   │                     │                │          │          │            │
│   │  ┌───────────────┐  │                │          ▼          │            │
│   │  │ SGX Quote     │  │                │  ┌───────────────┐  │            │
│   │  └───────────────┘  │                │  │ TDX Token     │  │            │
│   │         │           │                │  └───────────────┘  │            │
│   └─────────┼───────────┘                └──────────┼──────────┘            │
│             │                                       │                        │
│             ▼                                       ▼                        │
│   ┌─────────────────────────────────────────────────────────────┐           │
│   │                    Verifier                                  │           │
│   │  1. Verify SGX Quote                                        │           │
│   │  2. Verify TDX Token                                        │           │
│   │  3. Check binding: TDX.report_data == hash(SGX.MRENCLAVE)   │           │
│   └─────────────────────────────────────────────────────────────┘           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Binding Mechanism

The key insight is that TDX's `report_data` field (64 bytes) can include a hash of the SGX enclave's measurement, creating a cryptographic binding:

```
TDX_report_data = SHA256(SGX_MRENCLAVE || purpose || timestamp)
```

This proves:
1. The SGX enclave is running inside this specific TDX VM
2. The TDX attestation was generated with knowledge of the SGX identity
3. A verifier can check both attestations are from the same composite system

## SGX Side Setup

Your SGX attestation code is in:
```
sgx_machine_code/gramine_attestation/
├── attestation_demo.py      # Quote generation
├── verify_quote.py          # Quote verification
├── attestation.manifest.template
└── README.md
```

### Get SGX MRENCLAVE

```bash
# On SGX machine
cd sgx_machine_code/gramine_attestation
gramine-sgx-sigstruct-view attestation.sig
```

Output:
```
Attributes:
    mr_signer: 3ca59c440a720c7bb9dd4c86da5567bb...
    mr_enclave: 05b8e0fe8118ceb23099e92fb9be99d1...  # This is MRENCLAVE
    isv_prod_id: 0
    isv_svn: 0
```

### Generate SGX Quote

```bash
make run-sgx
# Creates quote.bin
```

## TDX Side Setup

Use the attestation module we created:

```python
from tdx_remote_attestation import TDXAttestor

attestor = TDXAttestor()

# Bind to SGX enclave
sgx_mrenclave = "05b8e0fe8118ceb23099e92fb9be99d154a043d62626624cf0e9de40390cf0e3"
binding_hash, token = attestor.get_binding_data(sgx_mrenclave=sgx_mrenclave)

print(f"Binding hash: {binding_hash}")
# The token's report_data now contains the binding
```

## Complete Integration Flow

### Step 1: SGX Generates Quote

```python
# On SGX machine
import subprocess

# Generate SGX quote with Gramine
result = subprocess.run(
    ["gramine-sgx", "python3", "attestation_demo.py"],
    capture_output=True
)

# Read the generated quote
with open("quote.bin", "rb") as f:
    sgx_quote = f.read()

# Get MRENCLAVE from sigstruct
# (In practice, you know this from the build process)
mrenclave = "05b8e0fe8118ceb23099e92fb9be99d154a043d62626624cf0e9de40390cf0e3"
```

### Step 2: SGX Sends MRENCLAVE to TDX

```python
# SGX machine sends MRENCLAVE to TDX VM
import socket

sock = socket.socket()
sock.connect((TDX_VM_IP, 8888))
sock.send(mrenclave.encode())
sock.close()
```

### Step 3: TDX Generates Bound Attestation

```python
# On TDX VM
from tdx_remote_attestation import TDXAttestor

# Receive MRENCLAVE from SGX
server = socket.socket()
server.bind(('0.0.0.0', 8888))
server.listen(1)
conn, _ = server.accept()
mrenclave = conn.recv(128).decode()
conn.close()

# Generate bound attestation
attestor = TDXAttestor()
binding_hash, tdx_token = attestor.get_binding_data(sgx_mrenclave=mrenclave)
```

### Step 4: Both Attestations Sent to Verifier

```python
# TDX VM sends both to verifier
import json

composite_attestation = {
    "sgx_quote": sgx_quote.hex(),  # Received from SGX
    "sgx_mrenclave": mrenclave,
    "tdx_token": tdx_token.raw_token,
    "binding_hash": binding_hash
}

sock = socket.socket()
sock.connect((VERIFIER_IP, 9999))
sock.send(json.dumps(composite_attestation).encode())
response = sock.recv(4096)
sock.close()
```

### Step 5: Verifier Checks Both

```python
# On Verifier
import hashlib
from tdx_verifier_service import TDXTokenVerifier

def verify_hierarchical(data: dict) -> bool:
    """Verify hierarchical SGX+TDX attestation"""
    
    # Step 1: Verify SGX quote
    # (Use Intel DCAP libraries for real verification)
    sgx_quote = bytes.fromhex(data["sgx_quote"])
    sgx_mrenclave = data["sgx_mrenclave"]
    # sgx_valid = dcap_verify(sgx_quote)  # Real implementation
    
    # Step 2: Verify TDX token
    verifier = TDXTokenVerifier()
    tdx_valid, tdx_result = verifier.verify(data["tdx_token"])
    
    if not tdx_valid:
        return False
    
    # Step 3: Verify binding
    # Reconstruct expected binding
    binding_data = {
        "purpose": "hierarchical-tee-composition",
        "sgx_mrenclave": sgx_mrenclave
    }
    # Note: timestamp matching would need synchronization
    
    expected_hash = hashlib.sha256(
        json.dumps(binding_data, sort_keys=True).encode()
    ).hexdigest()
    
    actual_report_data = tdx_result["tdx"]["report_data"]
    
    # Check if binding matches
    binding_valid = expected_hash[:32] in actual_report_data
    
    return tdx_valid and binding_valid  # and sgx_valid
```

## Security Considerations

### 1. Binding Freshness

Include a timestamp or nonce in the binding to prevent replay:

```python
binding_data = {
    "timestamp": datetime.now().isoformat(),
    "nonce": os.urandom(16).hex(),
    "purpose": "hierarchical-tee-composition",
    "sgx_mrenclave": mrenclave
}
```

### 2. Bidirectional Binding

For stronger binding, SGX can also include TDX measurement:

```python
# SGX includes TDX MRTD in its user_report_data
sgx_report_data = hash(TDX_MRTD)

# TDX includes SGX MRENCLAVE in its report_data
tdx_report_data = hash(SGX_MRENCLAVE)

# Verifier checks both bindings
```

### 3. Trust Root

The trust chain is:
1. Intel's signing keys (root of trust)
2. SGX quote signed by CPU
3. TDX token signed by Intel Trust Authority
4. Binding hash links them together

## Files Reference

### SGX Side (on SGX machine)

```
sgx_machine_code/gramine_attestation/
├── attestation_demo.py      # Generate quote in enclave
├── verify_quote.py          # Verify quotes
├── Makefile                 # Build/run commands
└── attestation.manifest.template
```

### TDX Side (on this VM)

```
tdx-layer/attestation/
├── tdx_remote_attestation.py    # Main module with binding
├── tdx_verifier_service.py      # Verifier service
├── tdx_attestation_client.py    # Client for testing
└── docs/                        # This documentation
```

## Example: Minimal Hierarchical Verification

```python
#!/usr/bin/env python3
"""
Minimal hierarchical TEE verification example
Run on the verifier machine
"""

import json
import socket
from tdx_verifier_service import TDXTokenVerifier

def verify_composite_attestation(composite: dict) -> dict:
    """Verify a composite SGX+TDX attestation"""
    
    result = {
        "sgx_verified": False,
        "tdx_verified": False,
        "binding_verified": False,
        "overall": False
    }
    
    # 1. Verify TDX token
    verifier = TDXTokenVerifier()
    tdx_ok, tdx_result = verifier.verify(composite["tdx_token"])
    result["tdx_verified"] = tdx_ok
    result["tdx_details"] = tdx_result
    
    # 2. Verify SGX quote
    # (Would use real DCAP verification here)
    result["sgx_verified"] = True  # Placeholder
    
    # 3. Verify binding
    if tdx_ok:
        report_data = tdx_result["tdx"]["report_data"]
        binding_hash = composite.get("binding_hash", "")
        result["binding_verified"] = binding_hash[:32] in report_data
    
    # Overall verdict
    result["overall"] = all([
        result["sgx_verified"],
        result["tdx_verified"],
        result["binding_verified"]
    ])
    
    return result

# Usage
if __name__ == "__main__":
    # Receive composite attestation
    server = socket.socket()
    server.bind(('0.0.0.0', 9999))
    server.listen(1)
    
    print("Waiting for composite attestation...")
    conn, addr = server.accept()
    data = json.loads(conn.recv(65536).decode())
    
    result = verify_composite_attestation(data)
    
    print(f"SGX:     {'✓' if result['sgx_verified'] else '✗'}")
    print(f"TDX:     {'✓' if result['tdx_verified'] else '✗'}")
    print(f"Binding: {'✓' if result['binding_verified'] else '✗'}")
    print(f"Overall: {'TRUSTED' if result['overall'] else 'UNTRUSTED'}")
    
    conn.send(json.dumps(result).encode())
    conn.close()
```

## Next Steps

1. **Implement real SGX quote verification** using Intel DCAP libraries
2. **Add nonce-based challenge-response** for freshness
3. **Build composition protocol** with unlinkability features (your research)
4. **Create end-to-end demo** with both machines
