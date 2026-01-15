# SGX-TDX Runtime Update System - Documentation

## Overview

This documentation covers the SGX-TDX Runtime Update System, which enables secure command execution on TDX VMs through an SGX enclave gateway.

## Documents

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture and component overview |
| [PROTOCOL_SPEC.md](PROTOCOL_SPEC.md) | Message formats and communication protocol |
| [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) | Threat model, security controls, attack scenarios |
| [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) | Step-by-step installation and configuration |
| [API_REFERENCE.md](API_REFERENCE.md) | Gateway API, CLI commands, library functions |

## Quick Links

### For Operators

1. [Prerequisites](DEPLOYMENT_GUIDE.md#prerequisites)
2. [Generate Certificates](DEPLOYMENT_GUIDE.md#step-1-generate-certificates-and-keys)
3. [Start Gateway](DEPLOYMENT_GUIDE.md#step-4-build-and-start-gateway)
4. [Troubleshooting](DEPLOYMENT_GUIDE.md#troubleshooting)

### For ASPs

1. [Generate Keys](API_REFERENCE.md#generate-keys)
2. [Execute Commands](API_REFERENCE.md#execute)
3. [Retrieve Logs](API_REFERENCE.md#get-logs)

### For Security Auditors

1. [Threat Model](SECURITY_ANALYSIS.md#threat-model)
2. [Security Controls](SECURITY_ANALYSIS.md#security-controls)
3. [Attack Scenarios](SECURITY_ANALYSIS.md#attack-scenarios)
4. [Recommendations](SECURITY_ANALYSIS.md#recommendations)

## System Requirements

| Component | Requirement |
|-----------|-------------|
| SGX Gateway | Intel SGX CPU, Gramine 1.9+, Python 3.8+ |
| TDX VM | Intel TDX, SSH server |
| ASP Client | Python 3.8+, cryptography library |

## Getting Started

```bash
# Clone and navigate
cd sgx-tdx-runtime-update

# Generate certificates
cd certs && ./generate_certs.sh <GATEWAY_IP>

# Generate enclave keys
cd ../sgx-gateway && make gen-keys

# Build and run
make all && make run-sgx
```

See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for detailed instructions.
