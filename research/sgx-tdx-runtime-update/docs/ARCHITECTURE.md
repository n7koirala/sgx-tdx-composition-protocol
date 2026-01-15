# SGX-TDX Runtime Update System - Architecture

## Overview

The Runtime Update System enables Application Service Providers (ASPs) to securely execute commands on their TDX VMs through an SGX enclave gateway. Every command is cryptographically signed, verified, and logged for auditability.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           RUNTIME UPDATE SYSTEM                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐     ┌─────────────────────────────────────────────────┐   │
│  │     ASP     │     │            SGX ENCLAVE (Gramine)                │   │
│  │             │     │                                                  │   │
│  │ ┌─────────┐ │     │  ┌───────────┐  ┌───────────┐  ┌────────────┐  │   │
│  │ │ Private │ │     │  │    ASP    │  │  Command  │  │   Audit    │  │   │
│  │ │   Key   │ │     │  │ Registry  │  │ Verifier  │  │  Logger    │  │   │
│  │ └────┬────┘ │     │  │ (Trusted) │  │           │  │ (Sealed)   │  │   │
│  │      │      │     │  └─────┬─────┘  └─────┬─────┘  └─────┬──────┘  │   │
│  │      ▼      │     │        │              │              │         │   │
│  │ ┌─────────┐ │     │        │              │              │         │   │
│  │ │  Sign   │ │     │        ▼              ▼              ▼         │   │
│  │ │ Command │─┼────►│  ┌──────────────────────────────────────┐     │   │
│  │ └─────────┘ │     │  │         Gateway Server               │     │   │
│  │             │ mTLS│  │  1. Receive signed command           │     │   │
│  └─────────────┘     │  │  2. Verify ASP signature             │     │   │
│                      │  │  3. Check policy (ASP → VM)          │     │   │
│                      │  │  4. Execute via SSH                  │     │   │
│                      │  │  5. Log with enclave signature       │     │   │
│                      │  └──────────────────┬───────────────────┘     │   │
│                      │                     │                          │   │
│                      └─────────────────────┼──────────────────────────┘   │
│                                            │ SSH                          │
│                                            ▼                              │
│                      ┌─────────────────────────────────────────────────┐  │
│                      │                  TDX VM                          │  │
│                      │  • Executes command                              │  │
│                      │  • Returns stdout/stderr                         │  │
│                      │  • Only accessible from SGX enclave              │  │
│                      └─────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. ASP Client (`asp-client/`)

Tool for Application Service Providers to:
- Generate RSA/ECDSA key pairs for command signing
- Create signed command payloads
- Send commands to the SGX gateway
- Retrieve audit logs

### 2. SGX Gateway (`sgx-gateway/`)

Main enclave application that:
- Listens for incoming signed commands (TLS + mTLS)
- Verifies signatures against registered ASP public keys
- Enforces access policies (which ASP can access which VM)
- Executes commands on TDX VMs via SSH
- Maintains signed audit logs in sealed storage

### 3. Common Libraries (`common/`)

Shared code for protocol and cryptography:
- `protocol.py`: Data structures (SignedCommand, CommandResult, AuditLogEntry)
- `crypto.py`: Signature verification/generation utilities

### 4. Configuration (`config/`)

- `asp_registry.json`: Maps ASP identifiers to their public keys and allowed VMs

## Data Flow

```
┌───────────────────────────────────────────────────────────────────────┐
│                        COMMAND EXECUTION FLOW                         │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  1. ASP CREATES COMMAND                                               │
│     ┌─────────────────────────────────────────┐                       │
│     │ {                                       │                       │
│     │   "asp_id": "company-a",                │                       │
│     │   "target_vm": "146.148.46.72",         │                       │
│     │   "command": "apt-get update",          │                       │
│     │   "timestamp": 1705356000.123,          │                       │
│     │   "nonce": "abc123..."                  │                       │
│     │ }                                       │                       │
│     └─────────────────────────────────────────┘                       │
│                          │                                            │
│                          ▼                                            │
│  2. ASP SIGNS COMMAND                                                 │
│     signature = sign(hash(command), ASP_PRIVATE_KEY)                  │
│                          │                                            │
│                          ▼                                            │
│  3. SEND TO SGX GATEWAY (mTLS)                                        │
│     ┌─────────────────────────────────────────┐                       │
│     │ GatewayRequest {                        │                       │
│     │   type: "execute_command",              │                       │
│     │   payload: SignedCommand                │                       │
│     │ }                                       │                       │
│     └─────────────────────────────────────────┘                       │
│                          │                                            │
│                          ▼                                            │
│  4. SGX GATEWAY VERIFIES                                              │
│     a. Validate timestamp (not expired)                               │
│     b. Check nonce (prevent replay)                                   │
│     c. Lookup ASP public key in registry                              │
│     d. Verify signature                                               │
│     e. Check ASP is allowed to access target VM                       │
│                          │                                            │
│                          ▼                                            │
│  5. EXECUTE ON TDX VM                                                 │
│     SSH to VM, run command, capture output                            │
│                          │                                            │
│                          ▼                                            │
│  6. LOG AND SEAL                                                      │
│     ┌─────────────────────────────────────────┐                       │
│     │ AuditLogEntry {                         │                       │
│     │   log_id: "log-20260115...",            │                       │
│     │   asp_id, target_vm, command,           │                       │
│     │   result: { stdout, stderr, exit_code }, │                      │
│     │   enclave_signature: "..."              │◄── Signed by enclave  │
│     │ }                                       │                       │
│     └─────────────────────────────────────────┘                       │
│                          │                                            │
│                          ▼                                            │
│  7. RETURN RESULT TO ASP                                              │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

## Trust Model

| Entity | Trust Level | Justification |
|--------|-------------|---------------|
| SGX Enclave | Trusted | Hardware-enforced isolation, code is measured |
| ASP Registry | Trusted | Loaded into enclave, contributes to MRENCLAVE |
| ASP | Authenticated | Identity verified via signature |
| TDX VM | Trusted | Attested via hierarchical attestation |
| Cloud Provider | Untrusted | Cannot read enclave memory or modify code |

## Security Properties

1. **Authenticity**: Only registered ASPs with valid private keys can execute commands
2. **Authorization**: ASPs can only access their assigned VMs
3. **Integrity**: Commands are signed; tampering is detected
4. **Non-repudiation**: Audit logs prove which ASP executed which command
5. **Freshness**: Timestamps and nonces prevent replay attacks
6. **Auditability**: All operations are logged with enclave signatures
