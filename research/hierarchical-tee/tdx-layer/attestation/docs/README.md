# TDX Remote Attestation Documentation

This documentation describes the TDX remote attestation setup for the Hierarchical TEE Composition Protocol.

## Table of Contents

1. [Overview](./01-overview.md) - Architecture and concepts
2. [Setup Guide](./02-setup-guide.md) - Prerequisites and configuration
3. [API Reference](./03-api-reference.md) - Module and class documentation
4. [Usage Examples](./04-usage-examples.md) - Code examples and patterns
5. [Integration with SGX](./05-sgx-integration.md) - Hierarchical composition
6. [Troubleshooting](./06-troubleshooting.md) - Common issues and solutions

## Quick Reference

### Files in this Module

| File | Purpose |
|------|---------|
| `tdx_remote_attestation.py` | Main attestation module with `TDXAttestor` class |
| `tdx_verifier_service.py` | Remote verifier service (runs on SGX machine) |
| `tdx_attestation_client.py` | Client to send attestations to verifier |
| `tdx_attestation.py` | Low-level TDX device access (legacy) |

### Key Commands

```bash
# Generate and test TDX attestation
sudo python3 tdx_remote_attestation.py

# Send attestation to remote verifier
sudo python3 tdx_attestation_client.py <VERIFIER_IP> 9999

# Start verifier service (on SGX machine)
python3 tdx_verifier_service.py 9999
```

### Key Classes

- `TDXAttestor` - Main class for generating TDX attestations
- `TDXAttestationToken` - Parsed JWT attestation token
- `TDXEvidence` - Raw TDX evidence/quote
- `TDXVerifier` - Token verification
- `TDXVerifierService` - Network verifier service

## Last Updated

- **Date**: 2025-12-31
- **Development Platform**: Antigravity
- **Status**: Working ✓
