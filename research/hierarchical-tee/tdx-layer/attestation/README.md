# TDX Remote Attestation Module

This directory contains the TDX remote attestation components for the Hierarchical TEE Composition Protocol.

## Overview

The TDX attestation module provides:
- **TDX quote/evidence generation** via Intel Trust Authority CLI
- **Remote attestation tokens** (JWT) from Intel Trust Authority
- **Verifier service** for validating TDX attestations
- **SGX binding support** for hierarchical composition

## Architecture

```
+-------------------+        +---------------------+        +------------------+
|   TDX VM (GCP)    |        |  Intel Trust        |        |  SGX Machine     |
|                   |        |  Authority          |        |  (Verifier)      |
|  +-------------+  |        |                     |        |  +-----------+   |
|  | TDX Attestor|  |------->| Verify & Sign       |        |  | Verifier  |   |
|  +-------------+  |        | (Cloud Service)     |        |  | Service   |   |
|        |          |        +---------------------+        |  +-----------+   |
|        v          |                                       |        ^         |
|  [JWT Token]      |-------------------------------------->|        |         |
|                   |           Remote Attestation          |   Verify Token   |
+-------------------+                                       +------------------+
```

## Files

| File | Description |
|------|-------------|
| `tdx_remote_attestation.py` | Main TDX attestation module with `TDXAttestor` class |
| `tdx_verifier_service.py` | Standalone verifier service (runs on SGX machine) |
| `tdx_attestation_client.py` | Client to send attestations to remote verifier |
| `tdx_attestation.py` | Low-level TDX report generation (direct device access) |

## Quick Start

### On the TDX VM (this machine)

```bash
# Test TDX attestation locally
sudo python3 tdx_remote_attestation.py

# Send attestation to remote verifier
sudo python3 tdx_attestation_client.py <VERIFIER_IP> 9999
```

### On the SGX Machine (or any verifier)

```bash
# Start the verifier service
python3 tdx_verifier_service.py 9999
```

## Usage in Python

### Generate TDX Attestation Token

```python
from tdx_remote_attestation import TDXAttestor

# Initialize attestor
attestor = TDXAttestor()

# Get attestation token from Intel Trust Authority
token = attestor.get_attestation_token()

# Access measurements
print(f"MRTD: {token.mrtd}")
print(f"TCB Status: {token.tcb_status}")
print(f"Is Debuggable: {token.is_debuggable}")

# Send token.raw_token to your verifier
```

### Generate TDX Evidence (Quote Only)

```python
from tdx_remote_attestation import TDXAttestor

attestor = TDXAttestor()

# Get raw evidence without Intel TA verification
evidence = attestor.get_evidence()
print(f"Quote: {evidence.quote[:100]}...")
```

### Bind TDX Attestation to SGX Enclave

```python
from tdx_remote_attestation import TDXAttestor

attestor = TDXAttestor()

# Get attestation bound to SGX MRENCLAVE
sgx_mrenclave = "05b8e0fe8118ceb23099e92fb9be99d154a043d62626624cf0e9de40390cf0e3"
binding_hash, token = attestor.get_binding_data(sgx_mrenclave=sgx_mrenclave)

print(f"Binding Hash: {binding_hash}")
print(f"Token Report Data: {token.report_data}")
```

### Verify TDX Token (on Verifier)

```python
from tdx_verifier_service import TDXTokenVerifier

verifier = TDXTokenVerifier()

# Optionally add trusted MRTD values
verifier.add_trusted_mrtd("a5844e88897b70c318bef929ef4dfd6c...")

# Verify token
verified, result = verifier.verify(token_string)

if verified:
    print(f"MRTD: {result['tdx']['mrtd']}")
    print("TD is TRUSTED")
else:
    print(f"Verification failed: {result['error']}")
```

## Configuration

### Intel Trust Authority Config (`~/config.json`)

```json
{
  "trustauthority_api_url": "https://api.trustauthority.intel.com",
  "trustauthority_api_key": "your-api-key-here"
}
```

### CLI Commands

```bash
# Generate TDX evidence (quote)
sudo trustauthority-cli evidence --tdx -c ~/config.json

# Get verified attestation token
sudo trustauthority-cli token --tdx -c ~/config.json

# Include custom user data
sudo trustauthority-cli token --tdx -c ~/config.json -u $(echo "custom-data" | base64)
```

## TDX Measurements

| Measurement | Description |
|-------------|-------------|
| `MRTD` | TD Measurement - hash of TD's initial configuration |
| `MROWNE` | Owner identity measurement |
| `RTMR0-3` | Runtime measurements (like PCRs) |
| `Report Data` | 64 bytes of user-provided data |
| `SEAM SVN` | TDX module security version |

## For Hierarchical Composition

This TDX attestation can be composed with SGX attestation:

1. **SGX enclave generates its quote** on SGX machine
2. **TDX VM includes SGX MRENCLAVE** in its report_data
3. **Verifier checks both** SGX quote and TDX token
4. **Binding verified** via report_data hash chain

See the `get_binding_data()` method for implementation details.

## Troubleshooting

### TDX device not found

```bash
ls -la /dev/tdx_guest
# Should show the TDX guest device
```

### Permission denied

```bash
# Run with sudo for TDX device access
sudo python3 tdx_remote_attestation.py
```

### Intel Trust Authority errors

```bash
# Check config file
cat ~/config.json

# Test CLI directly
sudo trustauthority-cli token --tdx -c ~/config.json
```

### TCB Status "OutOfDate"

This is normal for VMs that haven't been updated recently. The attestation still works but the TCB (Trusted Computing Base) may have known vulnerabilities.

## Performance

Typical latencies on GCP Intel TDX VM:

| Operation | Time |
|-----------|------|
| Evidence Generation | ~450-500 ms |
| Token Generation (with ITA) | ~400-500 ms |
| Local Verification | < 1 ms |
| Network Transfer | Depends on distance |
