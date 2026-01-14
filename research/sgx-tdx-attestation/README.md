# Hierarchical SGX-TDX Attestation Protocol

A research implementation of hierarchical TEE attestation where an **SGX enclave verifies TDX VM attestation**, establishing a chain of trust: `End User → SGX → TDX`.

## Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    HIERARCHICAL ATTESTATION FLOW                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────────────┐     Challenge (Nonce)    ┌─────────────────┐  │
│   │    SGX ENCLAVE      │ ───────────────────────→ │     TDX VM      │  │
│   │   (Owner/Verifier)  │       over TLS           │   (Attester)    │  │
│   │                     │                          │                 │  │
│   │  • Generates nonce  │     TDX Token (JWT)      │ • Generates     │  │
│   │  • Verifies token   │ ←─────────────────────── │   quote         │  │
│   │  • Issues verdict   │                          │ • Gets ITA      │  │
│   └─────────────────────┘                          │   token         │  │
│            │                                       └─────────────────┘  │
│            │ SGX Quote                                                  │
│            ▼                                                            │
│   ┌─────────────────────┐                                               │
│   │     End User        │  (Verifies SGX, trusts TDX transitively)      │
│   └─────────────────────┘                                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
sgx-tdx-attestation/
├── README.md                     # This file
├── docs/                         # Documentation
│   ├── SETUP_GUIDE.md            # End-to-end setup instructions
│   ├── ARCHITECTURE.md           # System design and trust model
│   ├── PROTOCOL_SPEC.md          # Message formats and verification
│   └── TROUBLESHOOTING.md        # Common issues and solutions
├── certs/
│   ├── generate_certs.sh         # TLS certificate generation
│   ├── ca.crt                    # CA certificate (generated)
│   ├── server.crt                # TDX server certificate (generated)
│   └── server.key                # TDX server private key (generated)
├── common/
│   ├── __init__.py
│   └── protocol.py               # Shared protocol definitions
├── tdx-server/
│   └── tdx_attestation_server.py # TDX attestation server
└── sgx-verifier/
    ├── sgx_tdx_verifier.py       # SGX enclave verifier
    ├── verifier.manifest.template
    └── Makefile
```

## Documentation

For detailed setup and troubleshooting, see the [docs/](./docs/) folder:

- **[SETUP_GUIDE.md](./docs/SETUP_GUIDE.md)** - Complete step-by-step setup instructions
- **[ARCHITECTURE.md](./docs/ARCHITECTURE.md)** - System design, trust model, components
- **[PROTOCOL_SPEC.md](./docs/PROTOCOL_SPEC.md)** - Message formats, nonce binding, verification
- **[TROUBLESHOOTING.md](./docs/TROUBLESHOOTING.md)** - Common issues and solutions

## Quick Start

### 1. Generate TLS Certificates (with mTLS support)

```bash
cd certs
chmod +x generate_certs.sh
./generate_certs.sh <TDX_IP_ADDRESS>
```

This generates 6 files:
- `ca.crt`, `ca.key` - Certificate Authority
- `server.crt`, `server.key` - TDX server certificates
- `sgx_client.crt`, `sgx_client.key` - SGX enclave client certificates

**Deployment:**
- TDX machine: `ca.crt`, `server.crt`, `server.key`
- SGX machine: `ca.crt`, `sgx_client.crt`, `sgx_client.key`

### 2. Start TDX Attestation Server (on TDX VM)

**Standard mode (any client):**
```bash
cd tdx-server
python3 tdx_attestation_server.py --port 8443
```

**Secure mode with mTLS (SGX enclave only):**
```bash
cd tdx-server
python3 tdx_attestation_server.py --port 8443 --require-client-cert
```

With `--require-client-cert`, only clients presenting a valid certificate signed by the CA can connect.

### 3. Run SGX Verifier (on SGX Machine)

**Standard mode:**
```bash
cd sgx-verifier
make run-sgx TDX_HOST=<TDX_IP> TDX_PORT=8443
```

**With mTLS authentication:**
```bash
cd sgx-verifier
python3 sgx_tdx_verifier.py \
    --tdx-host <TDX_IP> \
    --tdx-port 8443 \
    --ca-cert ../certs/ca.crt \
    --client-cert ../certs/sgx_client.crt \
    --client-key ../certs/sgx_client.key
```

## Protocol Details

### Challenge-Response Flow

1. **SGX Enclave** generates a 32-byte cryptographic nonce
2. **SGX Enclave** connects to TDX server over TLS
3. **SGX Enclave** sends attestation request:
   ```json
   {"action": "attest", "nonce": "<base64>", "protocol_version": "1.0"}
   ```
4. **TDX Server** generates quote with nonce bound in `user_data`
5. **TDX Server** obtains JWT token from Intel Trust Authority
6. **TDX Server** returns response:
   ```json
   {"status": "success", "token": "<JWT>", "nonce_echo": "<nonce>", "mrtd": "..."}
   ```
7. **SGX Enclave** verifies:
   - JWT issuer contains `trustauthority.intel.com`
   - Token not expired
   - Nonce properly bound in `report_data`

### Verification Checks

| Check | Description | Security Purpose |
|-------|-------------|------------------|
| Issuer | Must be Intel Trust Authority | Authenticity |
| Expiry | Token must not be expired | Freshness |
| Nonce | Must match in report_data | Replay protection |

### Token Fields Extracted

- `MRTD` - TD Measurement (like SGX MRENCLAVE)
- `TCB Status` - Platform security status
- `Is Debuggable` - Production readiness flag
- `RTMRs` - Runtime measurements

## Security Considerations

### Current Implementation (Research)

This implementation performs **simple verification** suitable for research:
- Checks JWT issuer string
- Checks token expiry
- Verifies nonce binding

### Production Enhancements Needed

For production use, add:
1. **Cryptographic JWT Signature Verification** - Verify against Intel's JWKS
2. **MRTD Policy Enforcement** - Maintain list of trusted TD measurements
3. **TCB Policy** - Reject outdated TCB status
4. **Mutual Attestation** - Optional TDX → SGX verification

## Configuration

### TDX Server Options

```
--port PORT      Server port (default: 8443)
--cert FILE      TLS certificate
--key FILE       TLS private key
--config FILE    Intel Trust Authority config
--test           Run self-test
```

### SGX Verifier Options

```
--tdx-host HOST  TDX server address (required)
--tdx-port PORT  TDX server port (default: 8443)
--ca-cert FILE   CA certificate for TLS
--no-verify      Skip TLS verification
--verbose        Enable debug output
--json           Output as JSON
```

## Testing

### TDX Server Self-Test

```bash
python3 tdx_attestation_server.py --test
```

### SGX Network Connectivity Test

```bash
make test-network TDX_HOST=<IP>
```

### Pure Python Mode (No SGX)

```bash
make run-python TDX_HOST=<IP>
```

## Troubleshooting

### TDX Server Issues

| Error | Cause | Solution |
|-------|-------|----------|
| `/dev/tdx_guest` not found | Not running on TDX VM | Deploy on TDX-enabled VM |
| `trustauthority-cli` not found | Missing CLI tool | Install Intel Trust Authority CLI |
| Token generation failed | API issues | Check `~/config.json` and API key |

### SGX Verifier Issues

| Error | Cause | Solution |
|-------|-------|----------|
| Connection refused | TDX server not running | Start TDX server |
| TLS error | Certificate mismatch | Regenerate certificates |
| Nonce verification failed | Binding issue | Check TDX server logs |

## License

Research use only. Part of the SGX-TDX Composition Protocol project.
