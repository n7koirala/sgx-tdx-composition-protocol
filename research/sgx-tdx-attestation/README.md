# Hierarchical SGX-TDX Attestation Protocol

A research implementation of hierarchical TEE attestation where an **SGX enclave verifies TDX VM attestation**, establishing a chain of trust: `End User → SGX → TDX`.

Supports two attestation methods:
- **ITA** — Intel Trust Authority (cloud-based JWT verification)
- **DCAP** — Local TDX attestation plus composed vTPM PCR-10 and IMA-to-RTMR[3] runtime verification

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
├── README.md                       # This file
├── docs/                           # Documentation
│   ├── SETUP_GUIDE.md              # End-to-end setup instructions
│   ├── ARCHITECTURE.md             # System design and trust model
│   ├── PROTOCOL_SPEC.md            # Message formats and verification
│   ├── VTPM_RTMR3_INTEGRATION.md    # vTPM/RTMR3 design and test procedure
│   └── TROUBLESHOOTING.md          # Common issues and solutions
├── certs/
│   ├── generate_certs.sh           # TLS certificate generation
│   ├── ca.crt / server.crt / ...   # Generated certificates
├── common/
│   ├── __init__.py
│   ├── protocol.py                 # Shared protocol and DCAP verification
│   ├── ima_rtmr3.py                # Binary IMA parsing and replay
│   ├── vtpm_quote.py               # vTPM AK quote generation/verification
│   ├── runtime_agent.py            # CVM RTMR3 anchor/evidence collector
│   └── runtime_verifier.py         # WEN composed runtime predicate
├── tdx-server/
│   └── tdx_attestation_server.py   # TDX attestation server (ITA + DCAP)
├── sgx-verifier/
│   ├── sgx_tdx_verifier.py         # Single-shot SGX verifier
│   ├── sgx_controller.py           # Multi-controller server (long-running)
│   ├── verifier.manifest.template  # Gramine SGX manifest
│   └── Makefile                    # Build + run targets
└── end-user/
    └── end_user_client.py           # End-user client (multi-controller failover)
```

## Documentation

For detailed setup and troubleshooting, see the [docs/](./docs/) folder:

- **[SETUP_GUIDE.md](./docs/SETUP_GUIDE.md)** - Complete step-by-step setup instructions
- **[ARCHITECTURE.md](./docs/ARCHITECTURE.md)** - System design, trust model, components
- **[PROTOCOL_SPEC.md](./docs/PROTOCOL_SPEC.md)** - Message formats, nonce binding, verification
- **[VTPM_RTMR3_INTEGRATION.md](./docs/VTPM_RTMR3_INTEGRATION.md)** - Production integration, security claims, and exact SGX test steps
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
sudo -E python3 tdx_attestation_server.py --test --method dcap
sudo -E python3 tdx_attestation_server.py --port 8443 --method dcap
```

DCAP mode enables composed vTPM PCR-10 and IMA-to-RTMR[3] evidence by
default. It requires gotpm access to the GCP AK, the binary IMA log, writable
RTMR[3], and `python3-cryptography`. Do not restart the server on the same CVM
boot for a clean RTMR[3] policy test.

**Secure mode with mTLS (SGX enclave only):**
```bash
cd tdx-server
sudo python3 tdx_attestation_server.py --port 8443 --method dcap --require-client-cert
```

With `--require-client-cert`, only clients presenting a valid certificate signed by the CA can connect.

### 3. Run SGX Verifier — Single-Shot (on SGX Machine)

For a one-time verification of the TDX VM:

```bash
cd sgx-verifier

# ITA mode (default)
python3 sgx_tdx_verifier.py --tdx-host <TDX_IP> --tdx-port 8443 --method ita --no-verify

# DCAP mode (local ECDSA verification)
python3 sgx_tdx_verifier.py --tdx-host <TDX_IP> --tdx-port 8443 --method dcap --no-verify -v

# Via Gramine SGX enclave
make clean && make all METHOD=dcap
make run-sgx TDX_HOST=<TDX_IP> TDX_PORT=8443 METHOD=dcap
```

The WEN requires composed runtime evidence in DCAP mode. The default
`--expected-rtmr3-base auto` is intended for mechanism testing. Use an
independently provisioned golden file with `--require-golden` for boot policy
enforcement. See [the integration guide](./docs/VTPM_RTMR3_INTEGRATION.md).

### 4. Run Multi-Controller Setup (Scalable, Fault-Tolerant)

For production-like deployments with multiple independent SGX controllers:

```bash
# ── Terminal 1 (TDX VM): Start attestation server ──
cd tdx-server
sudo python3 tdx_attestation_server.py --port 8443 --method dcap

# ── Terminal 2 (SGX Machine): Start controller #1 ──
cd sgx-verifier
make run-controller-python TDX_HOST=<TDX_IP> METHOD=dcap \
    CONTROLLER_PORT=9001 CONTROLLER_ID=ctrl-1

# ── Terminal 3 (SGX Machine): Start controller #2 ──
cd sgx-verifier
make run-controller-python TDX_HOST=<TDX_IP> METHOD=dcap \
    CONTROLLER_PORT=9002 CONTROLLER_ID=ctrl-2

# ── Terminal 4 (End-User): Verify via any controller ──
cd end-user
python3 end_user_client.py --controller-host <SGX_IP> --controller-port 9001 --no-verify

# Or with automatic failover across multiple controllers:
python3 end_user_client.py --controllers <SGX_IP>:9001,<SGX_IP>:9002 --no-verify
```

**With Gramine SGX enclave** (running the controller inside a real enclave):
```bash
cd sgx-verifier

# Build and sign the manifest (measures sgx_controller.py into MRENCLAVE)
make clean && make all

# Start controller #1 inside SGX enclave
make run-controller TDX_HOST=<TDX_IP> METHOD=dcap \
    CONTROLLER_PORT=9001 CONTROLLER_ID=ctrl-1

# Start controller #2 in a separate terminal
make run-controller TDX_HOST=<TDX_IP> METHOD=dcap \
    CONTROLLER_PORT=9002 CONTROLLER_ID=ctrl-2
```

> **Note:** After modifying `sgx_controller.py` or `protocol.py`, run `make clean && make all`
> to rebuild the manifest. Gramine hashes all trusted files into MRENCLAVE.

## Multi-Controller Architecture

The multi-controller setup enables **horizontal scalability** and **fault tolerance** by running N independent SGX enclave controllers, each periodically re-attesting the same TDX VM.

```
          ┌──────────┐  ┌──────────┐  ┌──────────┐
          │ End User │  │ End User │  │ End User │
          └────┬─────┘  └────┬─────┘  └────┬─────┘
               │             │             │
          ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐
          │ SGX      │  │ SGX      │  │ SGX      │   Port 9001, 9002, 9003
          │ Ctrl #1  │  │ Ctrl #2  │  │ Ctrl #3  │   Each in own enclave
          └────┬─────┘  └────┬─────┘  └────┬─────┘
               │             │             │
               └─────────────┼─────────────┘
                             │   All independently verify same TDX VM
                             ▼
                       ┌───────────┐
                       │  TDX VM   │   Port 8443
                       └───────────┘
```

**Key properties:**
- Each controller is fully independent (no coordination, no leader election)
- Each controller caches the latest TDX verification result (configurable refresh interval)
- End-user connects to any controller and receives a `ControllerToken` with cached TDX info
- If one controller goes down, end-users failover to another

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
   {"action": "attest", "nonce": "<base64>", "attestation_method": "dcap", "ima_offset": 0, "protocol_version": "1.2"}
   ```
4. **TDX Server** obtains a vTPM PCR-10 quote, synchronizes IMA into RTMR[3], and generates a nonce-bound TDX quote
5. **TDX Server** responds based on method:
   - **ITA**: Obtains JWT from Intel Trust Authority → `{"token": "<JWT>", "attestation_method": "ita", ...}`
   - **DCAP**: Returns the raw quote and `runtime_evidence` with the vTPM quote, incremental IMA data, AK bind, and snapshot metadata
   Runtime deltas use the prior IMA count, RTMR3 checkpoint, and CVM stream
   epoch. See [Incremental Runtime Optimization](docs/INCREMENTAL_RUNTIME_OPTIMIZATION.md).
6. **SGX Enclave** verifies based on response method:
   - **ITA**: JWT issuer + expiry + nonce binding in `report_data`
   - **DCAP**: TDX signature/nonce plus vTPM PCR-10, AK-to-RTMR3, IMA replay, and optional golden boot checks

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

### SGX Verifier Options (Single-Shot)

```
--tdx-host HOST      TDX server address (required)
--tdx-port PORT      TDX server port (default: 8443)
--method {ita,dcap}  Attestation method (default: ita)
--ca-cert FILE       CA certificate for TLS
--no-verify          Skip TLS verification
--verbose            Enable debug output
--json               Output as JSON
```

### SGX Controller Options (Multi-Controller)

```
--controller-id ID          Unique controller name (default: ctrl-1)
--port PORT                 End-user listener port (default: 9001)
--tdx-host HOST             TDX server address (required)
--tdx-port PORT             TDX server port (default: 8443)
--method {ita,dcap}         Attestation method (default: dcap)
--refresh-interval SECONDS  TDX re-attestation interval (default: 30)
--cert FILE                 TLS certificate for controller
--key FILE                  TLS private key for controller
--no-verify-tdx             Skip TLS verification for TDX connection
--verbose                   Enable verbose output
```

### End-User Client Options

```
--controller-host HOST      Single controller address
--controller-port PORT      Controller port (default: 9001)
--controllers LIST          Comma-separated list (host1:9001,host2:9002)
--no-verify                 Skip TLS verification
--json                      Output as JSON
--verbose                   Enable verbose output
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
# Single-shot verifier
make run-python TDX_HOST=<IP> METHOD=dcap

# Multi-controller
make run-controller-python TDX_HOST=<IP> METHOD=dcap CONTROLLER_PORT=9001
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

### SGX Verifier / Controller Issues

| Error | Cause | Solution |
|-------|-------|----------|
| Connection refused | TDX server not running | Start TDX server |
| TLS error | Certificate mismatch | Regenerate certificates |
| Nonce verification failed | Binding issue | Check TDX server logs |
| Signature verification failed | Quote corrupted or parsing mismatch | Run with `--verbose` to inspect quote bytes |
| `ImportError: verify_dcap_quote` | Outdated `protocol.py` on SGX machine | Sync updated `protocol.py` from TDX VM |
| Controller shows "PENDING" | Background verification hasn't completed | Wait for first refresh cycle |
| End-user connection refused | Controller not running on that port | Check controller port and firewall |

## License

Research use only. Part of the SGX-TDX Composition Protocol project.
