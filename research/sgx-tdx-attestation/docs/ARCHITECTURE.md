# SGX-TDX Hierarchical Attestation - Architecture Overview

## Introduction

This document describes the architecture of the hierarchical TEE attestation protocol where an **SGX enclave acts as the "owner" or verifier of a TDX VM**. This creates a chain of trust: `End User → SGX Enclave → TDX VM`.

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        HIERARCHICAL ATTESTATION ARCHITECTURE                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         SGX MACHINE (Lab)                           │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │                   SGX ENCLAVE (Gramine)                     │    │    │
│  │  │                                                             │    │    │
│  │  │  ┌─────────────────┐    ┌────────────────────────────┐      │    │    │
│  │  │  │ sgx_tdx_verifier│───▶│ TDX Verification Logic     │      │    │    │
│  │  │  │     .py         │    │ • Nonce generation         │      │    │    │
│  │  │  └─────────────────┘    │ • JWT parsing              │      │    │    │
│  │  │                         │ • Nonce binding check      │      │    │    │
│  │  │                         │ • Issuer/expiry validation │      │    │    │
│  │  │                         └────────────────────────────┘      │    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  │         │                                                           │    │
│  │         │ TLS (Port 8443)                                           │    │
│  └─────────┼───────────────────────────────────────────────────────────┘    │
│            │                                                                │
│            │ Challenge: {nonce}                                             │
│            │ Response: {JWT token}                                          │
│            ▼                                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      TDX VM (Google Cloud)                          │    │
│  │                                                                     │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │              TDX Attestation Server                         │    │    │
│  │  │                                                             │    │    │
│  │  │  ┌─────────────────┐    ┌────────────────────────────┐      │    │    │
│  │  │  │  TLS Server     │───▶│ Intel Trust Authority CLI  │      │    │    │
│  │  │  │  (Port 8443)    │    │ • Generate TDX quote       │      │    │    │
│  │  │  └─────────────────┘    │ • Bind nonce in report_data│      │    │    │
│  │  │                         │ • Get signed JWT token     │      │    │    │
│  │  │                         └────────────────────────────┘      │    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Trust Model

### Chain of Trust

1. **End User → SGX Enclave**
   - User attests the SGX enclave using standard DCAP attestation
   - Verifies MRENCLAVE, MRSIGNER, and other SGX measurements
   - Trusts Intel's attestation infrastructure

2. **SGX Enclave → TDX VM**
   - SGX enclave challenges TDX VM with a fresh nonce
   - TDX VM generates a quote binding the nonce
   - Intel Trust Authority signs the TDX attestation as JWT
   - SGX enclave verifies nonce binding, issuer, and expiry

### Security Properties

| Property | Mechanism |
|----------|-----------|
| Freshness | 32-byte cryptographic nonce |
| Authenticity | Intel Trust Authority signature |
| Integrity | TDX quote measurements (MRTD, RTMRs) |
| Confidentiality | TLS 1.2+ for all communication |

## Components

### 1. Common Protocol Library (`common/protocol.py`)

Shared definitions used by both SGX and TDX components:

- **AttestationRequest**: Challenge message with nonce
- **AttestationResponse**: TDX token response
- **VerificationResult**: Verification outcome
- **Nonce utilities**: Generation and verification
- **JWT utilities**: Simple parsing without crypto
- **TLS utilities**: Context creation for client/server

### 2. TDX Attestation Server (`tdx-server/`)

Runs on the TDX VM:
- TLS server listening on port 8443
- Receives attestation challenges
- Uses `trustauthority-cli` to generate TDX quotes
- Binds nonce in the TDX quote's user_data field
- Returns JWT token from Intel Trust Authority

### 3. SGX Enclave Verifier (`sgx-verifier/`)

Runs inside Gramine SGX enclave:
- Generates cryptographic nonce
- Connects to TDX server over TLS
- Sends attestation challenge
- Verifies returned JWT token:
  - Issuer (Intel Trust Authority)
  - Expiry (not expired)
  - Nonce binding (in report_data)
- Outputs verification verdict

### 4. TLS Certificates (`certs/`)

Self-signed certificates for development:
- CA certificate (trusted by SGX enclave)
- Server certificate (used by TDX server)
- Server private key

## Protocol Flow

```
┌─────────────┐                              ┌─────────────┐                    ┌─────────────┐
│ SGX Enclave │                              │  TDX Server │                    │  Intel ITA  │
└──────┬──────┘                              └──────┬──────┘                    └──────┬──────┘
       │                                            │                                   │
       │ 1. Generate 32-byte nonce                  │                                   │
       │                                            │                                   │
       │ 2. TLS Connect ──────────────────────────▶│                                   │
       │                                            │                                   │
       │ 3. AttestationRequest{nonce} ────────────▶│                                   │
       │                                            │                                   │
       │                                            │ 4. trustauthority-cli             │
       │                                            │    --tdx -u <nonce[:32]> ────────▶│
       │                                            │                                   │
       │                                            │                 5. Generate quote │
       │                                            │                    with nonce     │
       │                                            │                                   │
       │                                            │◀────────────── 6. JWT Token ──────│
       │                                            │                                   │
       │◀──────── 7. AttestationResponse{token} ───│                                   │
       │                                            │                                   │
       │ 8. Parse JWT                               │                                   │
       │    - Check issuer                          │                                   │
       │    - Check expiry                          │                                   │
       │    - Verify nonce in report_data           │                                   │
       │                                            │                                   │
       │ 9. Issue TRUSTED/UNTRUSTED verdict         │                                   │
       ▼                                            ▼                                   ▼
```

## Verification Checks

The SGX enclave performs these verification checks:

### 1. Issuer Verification
- JWT `iss` claim must contain `trustauthority.intel.com`
- Ensures token came from legitimate Intel Trust Authority

### 2. Expiry Verification
- JWT `exp` claim must be in the future
- Prevents use of stale attestation tokens

### 3. Nonce Binding Verification
- The nonce sent by SGX must appear in `tdx_report_data`
- Prevents replay attacks with old tokens
- Ensures the TDX quote was generated for this specific challenge

## File Structure

```
sgx-tdx-attestation/
├── README.md                          # Project overview
├── docs/
│   ├── ARCHITECTURE.md               # This file
│   ├── SETUP_GUIDE.md                # Step-by-step setup
│   ├── PROTOCOL_SPEC.md              # Protocol specification
│   └── TROUBLESHOOTING.md            # Common issues
├── certs/
│   ├── generate_certs.sh             # Certificate generation
│   ├── ca.crt                        # CA certificate
│   ├── server.crt                    # Server certificate
│   └── server.key                    # Server private key
├── common/
│   ├── __init__.py
│   └── protocol.py                   # Shared protocol code
├── tdx-server/
│   └── tdx_attestation_server.py     # TDX attestation server
└── sgx-verifier/
    ├── sgx_tdx_verifier.py           # SGX enclave verifier
    ├── verifier.manifest.template    # Gramine manifest
    └── Makefile                      # Build and run
```

## Security Considerations

### Current Limitations (Research)

1. **No Cryptographic JWT Verification**
   - Only checks issuer string and expiry
   - Does not verify signature against Intel's public keys
   - Suitable for research, not production

2. **Flexible MRTD Policy**
   - Accepts any MRTD measurement
   - Should be restricted to known-good values in production

3. **Self-Signed Certificates**
   - For development only
   - Use proper PKI in production

### Production Recommendations

1. Add cryptographic JWT signature verification
2. Implement MRTD allowlist policy
3. Use proper certificate authority
4. Add mutual TLS authentication
5. Implement rate limiting and DDoS protection
