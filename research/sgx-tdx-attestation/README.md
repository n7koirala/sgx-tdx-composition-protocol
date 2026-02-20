# Hierarchical SGX-TDX Attestation Protocol

A research implementation of hierarchical TEE attestation where an **SGX enclave verifies TDX VM attestation**, establishing a chain of trust: `End User → SGX → TDX`.

Supports two attestation methods:
- **ITA** — Intel Trust Authority (cloud-based JWT verification)
- **DCAP** — Local attestation via `libtdx_attest` (ECDSA signature verification, no cloud dependency)

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
│   │  • Generates nonce  │   ITA: JWT Token         │ • Generates     │  │
│   │  • Verifies token   │   DCAP: Raw TDX Quote    │   TDX quote     │  │
│   │    or DCAP quote    │ ←─────────────────────── │ • ITA: gets JWT │  │
│   │  • Issues verdict   │                          │ • DCAP: returns │  │
│   └─────────────────────┘                          │   raw quote     │  │
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

**ITA mode** (default — uses Intel Trust Authority cloud):
```bash
cd tdx-server
python3 tdx_attestation_server.py --port 8443 --method ita
```

**DCAP mode** (local attestation via `libtdx_attest` — no cloud dependency):
```bash
cd tdx-server
sudo python3 tdx_attestation_server.py --port 8443 --method dcap
```

**Secure mode with mTLS (SGX enclave only):**
```bash
cd tdx-server
sudo python3 tdx_attestation_server.py --port 8443 --method dcap --require-client-cert
```

With `--require-client-cert`, only clients presenting a valid certificate signed by the CA can connect.

### 3. Run SGX Verifier (on SGX Machine)

**ITA mode** (default):
```bash
cd sgx-verifier
python3 sgx_tdx_verifier.py --tdx-host <TDX_IP> --tdx-port 8443 --method ita --no-verify
```

**DCAP mode** (local ECDSA verification):
```bash
cd sgx-verifier
python3 sgx_tdx_verifier.py --tdx-host <TDX_IP> --tdx-port 8443 --method dcap --no-verify -v

```bash
# SGX enclave mode with DCAP
make run-sgx TDX_HOST=<TDX_IP> TDX_PORT=8443 METHOD=dcap
# Direct mode (no SGX) with DCAP
make run-direct TDX_HOST=<TDX_IP> TDX_PORT=8443 METHOD=dcap
# Only Python with DCAP
make run-python TDX_HOST=<TDX_IP> TDX_PORT=8443 METHOD=dcap
```

**With mTLS authentication:**
```bash
cd sgx-verifier
python3 sgx_tdx_verifier.py \
    --tdx-host <TDX_IP> \
    --tdx-port 8443 \
    --method dcap \
    --ca-cert ../certs/ca.crt \
    --client-cert ../certs/sgx_client.crt \
    --client-key ../certs/sgx_client.key
```

## Attestation Methods

| Feature | ITA Mode | DCAP Mode |
|---------|----------|----------|
| **Quote generation** | `trustauthority-cli` | `libtdx_attest` (Intel DCAP library) |
| **Verification** | Intel cloud returns signed JWT | Local ECDSA-P256 signature check |
| **Cloud dependency** | Yes (per attestation) | No (fully local) |
| **Latency** | ~600-1200ms (network round-trip) | ~43ms (local QE only) |
| **Prerequisites** | `trustauthority-cli` + API key | `libtdx_attest.so` (Intel DCAP packages) |
| **Privacy** | Platform IDs in JWT claims | Platform IDs in raw quote (stripped by SGX) |

## Protocol Details

### Challenge-Response Flow

1. **SGX Enclave** generates a 32-byte cryptographic nonce
2. **SGX Enclave** connects to TDX server over TLS
3. **SGX Enclave** sends attestation request:
   ```json
   {"action": "attest", "nonce": "<base64>", "attestation_method": "dcap", "protocol_version": "1.0"}
   ```
4. **TDX Server** generates quote with nonce bound in `report_data`
5. **TDX Server** responds based on method:
   - **ITA**: Obtains JWT from Intel Trust Authority → `{"token": "<JWT>", "attestation_method": "ita", ...}`
   - **DCAP**: Returns raw quote → `{"raw_quote": "<base64>", "attestation_method": "dcap", ...}`
6. **SGX Enclave** verifies based on response method:
   - **ITA**: JWT issuer + expiry + nonce binding in `report_data`
   - **DCAP**: ECDSA-P256 signature + nonce binding in raw quote bytes

### Verification Checks

**ITA Mode:**

| Check | Description | Security Purpose |
|-------|-------------|------------------|
| Issuer | Must be Intel Trust Authority | Authenticity |
| Expiry | Token must not be expired | Freshness |
| Nonce | Must match in report_data | Replay protection |

**DCAP Mode:**

| Check | Description | Security Purpose |
|-------|-------------|------------------|
| Signature | ECDSA-P256 over quote header + body | Authenticity |
| Nonce | Nonce bytes in report_data (64 bytes) | Replay protection |
| MRTD | Extracted from quote body | Integrity |

### Fields Extracted

- `MRTD` - TD Measurement (like SGX MRENCLAVE)
- `TCB Status` - Platform security status (ITA: from JWT, DCAP: from TEE_TCB_SVN)
- `Is Debuggable` - Production readiness flag (from TD attributes)
- `RTMRs` - Runtime measurements (DCAP: parsed from quote body)

## Security Considerations

### Current Implementation (Research)

**ITA mode:**
- Checks JWT issuer string and expiry
- Verifies nonce binding in JWT claims
- Does NOT verify JWT cryptographic signature (research only)

**DCAP mode:**
- Verifies ECDSA-P256 signature on raw TDX quote
- Verifies nonce binding in quote report_data bytes
- Does NOT fetch/verify Intel collateral (PCK cert chain, CRL)

### Production Enhancements Needed

For production use, add:
1. **ITA: Cryptographic JWT Signature Verification** - Verify against Intel's JWKS
2. **DCAP: Full Collateral Verification** - PCK cert chain, CRL, TCB info from Intel PCS
3. **MRTD Policy Enforcement** - Maintain list of trusted TD measurements
4. **TCB Policy** - Reject outdated TCB status
5. **Mutual Attestation** - Optional TDX → SGX verification

## Configuration

### TDX Server Options

```
--port PORT          Server port (default: 8443)
--method {ita,dcap}  Attestation method (default: ita)
--cert FILE          TLS certificate
--key FILE           TLS private key
--config FILE        Intel Trust Authority config (ITA only)
--test               Run self-test
```

### SGX Verifier Options

```
--tdx-host HOST      TDX server address (required)
--tdx-port PORT      TDX server port (default: 8443)
--method {ita,dcap}  Attestation method (default: ita)
--ca-cert FILE       CA certificate for TLS
--no-verify          Skip TLS verification
--verbose            Enable debug output
--json               Output as JSON
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
| `trustauthority-cli` not found | Missing CLI (ITA mode) | Install Intel Trust Authority CLI |
| `libtdx_attest.so` not found | Missing DCAP library (DCAP mode) | Run `sudo bash install_dcap_packages.sh` |
| Token generation failed | API issues (ITA mode) | Check `~/config.json` and API key |
| `tdx_att_get_quote` failed | QE not running (DCAP mode) | Check QGS daemon: `systemctl status qgsd` |

### SGX Verifier Issues

| Error | Cause | Solution |
|-------|-------|----------|
| Connection refused | TDX server not running | Start TDX server |
| TLS error | Certificate mismatch | Regenerate certificates |
| Nonce verification failed | Binding issue | Check TDX server logs |
| Signature verification failed | Quote corrupted or parsing mismatch | Run with `--verbose` to inspect quote bytes |

## License

Research use only. Part of the SGX-TDX Composition Protocol project.
