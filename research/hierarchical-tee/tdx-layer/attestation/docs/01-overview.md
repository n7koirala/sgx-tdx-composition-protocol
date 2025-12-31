# TDX Remote Attestation Overview

## What is TDX Attestation?

Intel Trust Domain Extensions (TDX) provides hardware-based isolation for virtual machines. TDX attestation allows a TDX VM (Trust Domain or TD) to prove its identity and integrity to remote parties.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Hierarchical TEE Setup                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────┐       ┌──────────────────────────┐            │
│  │    SGX Machine           │       │    TDX VM (GCP)          │            │
│  │    (Owner/Verifier)      │       │    (This machine)        │            │
│  │                          │       │                          │            │
│  │  ┌────────────────────┐  │       │  ┌────────────────────┐  │            │
│  │  │   SGX Enclave      │  │       │  │   TDX Guest        │  │            │
│  │  │   (Gramine)        │  │       │  │   /dev/tdx_guest   │  │            │
│  │  │                    │  │       │  │                    │  │            │
│  │  │  - Generate Quote  │  │       │  │  - Generate Quote  │  │            │
│  │  │  - Owner Identity  │  │       │  │  - VM Identity     │  │            │
│  │  └────────────────────┘  │       │  └────────────────────┘  │            │
│  │           │              │       │           │              │            │
│  │           ▼              │       │           ▼              │            │
│  │  ┌────────────────────┐  │       │  ┌────────────────────┐  │            │
│  │  │  Verifier Service  │◄─┼───────┼──│  TDX Attestor      │  │            │
│  │  │  (Port 9999)       │  │       │  │  (trustauthority)  │  │            │
│  │  └────────────────────┘  │       │  └────────────────────┘  │            │
│  │                          │       │           │              │            │
│  └──────────────────────────┘       │           ▼              │            │
│                                      │  ┌────────────────────┐  │            │
│                                      │  │ Intel Trust        │  │            │
│                                      │  │ Authority (Cloud)  │  │            │
│                                      │  └────────────────────┘  │            │
│                                      └──────────────────────────┘            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Attestation Flow

### 1. Local Quote Generation
The TDX hardware generates a cryptographic quote containing:
- **MRTD**: TD Measurement (hash of initial TD configuration)
- **RTMR0-3**: Runtime measurements (like TPM PCRs)
- **Report Data**: 64 bytes of user-provided data
- **TCB Info**: Trusted Computing Base version info

### 2. Intel Trust Authority Verification
The quote is sent to Intel Trust Authority (ITA) which:
- Verifies the quote cryptographically
- Checks TCB status against known vulnerabilities
- Signs a JWT token with the verified claims

### 3. Remote Verification
The JWT token can be verified by any party that trusts Intel's signing keys.

## Key Concepts

### MRTD (TD Measurement)
Similar to SGX's MRENCLAVE, this is a hash that uniquely identifies the TD:
- Initial TD configuration
- Loaded firmware/BIOS
- Measured boot components

### RTMR (Runtime Measurements)
Four 48-byte registers that can be extended during runtime:
- **RTMR0**: Firmware measurements
- **RTMR1**: OS measurements
- **RTMR2**: Application measurements
- **RTMR3**: User-defined measurements

### Report Data
64 bytes that the TD can include in its quote:
- Used for binding (nonces, hashes)
- Can include SGX MRENCLAVE for hierarchical binding
- Included in the signed attestation

### TCB Status
Indicates the security state of the platform:
- **UpToDate**: All security patches applied
- **SWHardeningNeeded**: Software mitigations recommended
- **OutOfDate**: Security patches available but not applied
- **Revoked**: Platform compromised

## Comparison with SGX Attestation

| Aspect | SGX | TDX |
|--------|-----|-----|
| Isolation Level | Process (Enclave) | VM (Trust Domain) |
| Measurement | MRENCLAVE, MRSIGNER | MRTD, RTMR0-3 |
| Report Data | 64 bytes | 64 bytes |
| Quote Size | ~1456 bytes | ~5000+ bytes |
| Attestation | DCAP, EPID | Intel Trust Authority |
| Device | /dev/sgx_enclave | /dev/tdx_guest |

## For Hierarchical Composition

In your research protocol, TDX provides the outer layer of protection:

1. **SGX** (inner layer): Application-level isolation, runs sensitive code
2. **TDX** (outer layer): VM-level isolation, protects the entire VM

The composition binds these together:
- TDX report_data includes hash of SGX measurement
- Verifier checks both attestations
- Cryptographic chain proves: SGX runs inside verified TDX VM

## References

- [Intel TDX Specification](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html)
- [Intel Trust Authority](https://www.intel.com/content/www/us/en/security/trust-authority.html)
- [TDX Guest Kernel Documentation](https://docs.kernel.org/arch/x86/tdx.html)
