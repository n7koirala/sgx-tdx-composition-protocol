# TDX DCAP Architecture & Attestation Flow

This document explains how DCAP-based TDX attestation works, the architecture, and the differences from Intel Trust Authority (ITA).

## What is DCAP?

**Data Center Attestation Primitives (DCAP)** is Intel's framework for performing **locally verifiable** attestation of SGX enclaves and TDX VMs. Unlike the older EPID-based attestation or ITA cloud-based attestation, DCAP enables quote verification without per-attestation calls to Intel.

### DCAP vs Intel Trust Authority (ITA)

```
ITA-Based Flow:                       DCAP-Based Flow:
┌──────┐   ┌───────┐   ┌─────┐      ┌──────┐   ┌───────┐
│Client│──▶│TDX VM │──▶│ ITA │      │Client│──▶│TDX VM │
│      │◀──│       │◀──│(JWT)│      │      │◀──│       │
└──────┘   └───────┘   └─────┘      └──────┘   └───────┘
                          ▲                         │
                     Every quote              Local verification
                    goes to Intel             (no Intel call)
```

| Aspect | ITA (`trustauthority-cli`) | DCAP (this implementation) |
|--------|---------------------------|----------------------------|
| **Quote generation** | `trustauthority-cli` invokes QE | `configfs-tsm` kernel interface |
| **Verification** | Intel cloud returns JWT verdict | Local ECDSA signature check |
| **Per-quote Intel call** | ✅ Yes (API + rate limit) | ❌ No |
| **Internet required** | Every attestation | One-time collateral fetch |
| **Latency** | ~400-2000ms (network RTT) | ~42ms (quote gen) + ~14ms (verify) |
| **Trust model** | Trust Intel's JWT signing | Verify raw crypto yourself |
| **Scalability** | Rate-limited by Intel API | Unlimited local verification |
| **Output format** | JWT token (signed JSON) | Raw binary quote (ECDSA signed) |

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────────┐
│                         TDX VM Guest                            │
│                                                                 │
│  ┌──────────────────┐   ┌───────────────────────────────────┐   │
│  │ dcap_attestation  │   │ TDX Hardware                      │   │
│  │ (main script)     │   │                                   │   │
│  │                   │   │  ┌─────────────┐                  │   │
│  │ 1. Generate nonce│──▶│  │/dev/tdx_guest│ (ioctl)          │   │
│  │                   │   │  └──────┬──────┘                  │   │
│  │ 2. Get quote     │──▶│  ┌──────▼──────┐                  │   │
│  │    (configfs-tsm) │   │  │ configfs-tsm│                  │   │
│  │                   │   │  │ /sys/kernel/ │                  │   │
│  │ 3. Parse quote    │   │  │ config/tsm/  │                  │   │
│  │                   │   │  │   report/    │                  │   │
│  │ 4. Fetch collat. │   │  └──────┬──────┘                  │   │
│  │    (Intel PCS)    │   │         │                          │   │
│  │                   │   │  ┌──────▼──────┐                  │   │
│  │ 5. Verify locally │   │  │  QE (Quote  │ (host-side)      │   │
│  │    (ECDSA + PCK)  │   │  │  Enclave)   │                  │   │
│  │                   │   │  └─────────────┘                  │   │
│  │ 6. Return verdict │   │                                   │   │
│  └──────────────────┘   └───────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ collateral/ (cached)                                     │    │
│  │  ├── *_tcb_info.json          (TCB levels + SVN ranges) │    │
│  │  ├── *_qe_identity.json       (QE identity reference)   │    │
│  │  ├── *_pck.crl                (PCK revocation list)     │    │
│  │  └── *_root_ca.crl            (Root CA revocation list) │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │ (one-time)
                              ▼
               ┌──────────────────────────┐
               │ Intel PCS                 │
               │ api.trustedservices.      │
               │  intel.com                │
               │                           │
               │ TCB Info, QE Identity,    │
               │ CRLs, Certificate chains  │
               └──────────────────────────┘
```

### Module Breakdown

| Module | Responsibility |
|--------|----------------|
| `quote_generator.py` | Generate TDX quotes/reports from hardware |
| `quote_parser.py` | Parse binary TDX quote structure |
| `collateral_fetcher.py` | Fetch & cache Intel PCS collateral |
| `dcap_verifier.py` | Local cryptographic verification |
| `dcap_attestation.py` | Orchestrate the end-to-end flow |

## Attestation Flow (Step by Step)

### Step 1: Nonce/Report Data Generation

```python
report_data = secrets.token_bytes(64)  # 64 random bytes
```

The 64-byte `report_data` serves as a **freshness nonce**. It gets cryptographically bound into the quote, preventing replay attacks.

### Step 2: TDX Quote Generation

Two methods are available, selected automatically:

#### Method A: configfs-tsm (Preferred — Full Quote)

The Linux kernel 6.7+ provides a standardized `configfs-tsm` interface:

```python
# 1. Create a report entry
os.makedirs("/sys/kernel/config/tsm/report/dcap_<pid>_<timestamp>")

# 2. Write 64-byte report_data
with open("<dir>/inblob", 'wb') as f:
    f.write(report_data)

# 3. Read the full quote
with open("<dir>/outblob", 'rb') as f:
    quote = f.read()  # ~8000 bytes

# 4. Cleanup
os.rmdir("<dir>")
```

The kernel handles the complex flow internally:
1. Generates a TDREPORT via `TDCALL[TDG.MR.REPORT]`
2. Sends the TDREPORT to the VMM's Quote Generation Service (QGS)
3. QGS invokes the Quoting Enclave (QE) to sign the report
4. Returns the signed TDX Quote (ECDSA-P256)

**Performance**: ~42ms on GCP TDX (kernel 6.14).

#### Method B: ioctl (Fallback — TDREPORT Only)

```python
# Direct ioctl to /dev/tdx_guest
req = bytearray(report_data + b'\x00' * 1024)
fcntl.ioctl(fd, TDX_CMD_GET_REPORT0, req)  # 0xC0445401
tdreport = req[64:]  # 1024-byte TDREPORT
```

This produces a **TDREPORT** (MAC-authenticated, locally verifiable only), **not** a remotely verifiable Quote. Useful for reading measurements.

### Step 3: Binary Quote Parsing

A TDX v4 Quote has this layout:

```
┌──────────────────────────────────────────────────────────────┐
│ QUOTE HEADER (48 bytes)                                       │
│  ├── version (2B): 4                                         │
│  ├── att_key_type (2B): 2 (ECDSA-P256)                       │
│  ├── tee_type (4B): 0x81 (TDX)                               │
│  ├── reserved (4B)                                            │
│  ├── qe_vendor_id (16B): QE UUID                             │
│  └── user_data (20B)                                          │
├──────────────────────────────────────────────────────────────┤
│ TD QUOTE BODY (584 bytes)                                     │
│  ├── tee_tcb_svn (16B): TEE TCB Security Version             │
│  ├── mrseam (48B): SEAM module measurement                    │
│  ├── mrsigner_seam (48B): SEAM signer measurement            │
│  ├── seam_attributes (8B)                                     │
│  ├── td_attributes (8B): includes debug flag                  │
│  ├── xfam (8B): extended features                             │
│  ├── mrtd (48B): ★ TD initial image measurement              │
│  ├── mrconfigid (48B)                                         │
│  ├── mrowner (48B)                                            │
│  ├── mrownerconfig (48B)                                      │
│  ├── rtmr[0-3] (4×48B): ★ Runtime measurements              │
│  └── report_data (64B): ★ User nonce                         │
├──────────────────────────────────────────────────────────────┤
│ SIGNATURE DATA LENGTH (4 bytes)                               │
├──────────────────────────────────────────────────────────────┤
│ SIGNATURE DATA (variable, ~4299 bytes)                        │
│  ├── ecdsa_signature (64B): r(32) || s(32)                   │
│  ├── attestation_key (64B): x(32) || y(32)                   │
│  ├── qe_report (384B): QE SGX Report                         │
│  ├── qe_report_signature (64B)                                │
│  ├── qe_auth_data (variable)                                  │
│  └── certification_data (variable): PCK cert chain (PEM)     │
└──────────────────────────────────────────────────────────────┘
```

### Step 4: Collateral Fetching (One-Time)

Verification collateral is fetched from Intel's Provisioning Certification Service:

| Collateral | Endpoint | Purpose |
|------------|----------|---------|
| TCB Info | `/tdx/certification/v4/tcb?fmspc=<FMSPC>` | TCB level matching |
| QE Identity | `/sgx/certification/v4/qe/identity` | QE validation |
| PCK CRL | `/sgx/certification/v4/pckcrl?ca=platform` | Certificate revocation |
| Root CA CRL | `certificates.trustedservices.intel.com/IntelSGXRootCA.der` | Root CA revocation |

Collateral is cached to `collateral/` and reused for 24 hours.

### Step 5: Local Verification

All verification is cryptographic and **completely local** after the one-time collateral fetch:

#### 5a. ECDSA-P256 Signature Verification
```
signed_data = SHA-256(header || td_quote_body)   # First 632 bytes
attestation_key = ECDSA P-256 public key from quote
Verify(attestation_key, signature, signed_data)
```

#### 5b. PCK Certificate Chain Verification
```
PCK Cert ──(signed by)──▶ Intel Platform CA ──(signed by)──▶ Intel SGX Root CA
```
Each X.509 certificate signature is verified using the `cryptography` library.

#### 5c. CRL Checking
The PCK certificate's serial number is checked against the Certificate Revocation List.

#### 5d. TCB Status Evaluation
The quote's `tee_tcb_svn` is compared against Intel's published TCB levels to determine if the platform firmware is up-to-date.

#### 5e. Nonce Binding
```
assert quote.report_data == expected_report_data
```
Ensures the quote was generated for this specific challenge, preventing replay attacks.

### Step 6: Verdict

| Condition | Verdict |
|-----------|---------|
| Signature valid + nonce matches | TRUSTED |
| Any critical check fails | UNTRUSTED |
| Exception during verification | ERROR |

## TDREPORT Structure (1024 bytes)

The TDREPORT is the foundation of TDX attestation. It is generated by `TDCALL[TDG.MR.REPORT]` and contains three sections:

```
┌───────────────────────────────────────────────────────────┐
│ REPORTMACSTRUCT (256 bytes, offset 0-255)                  │
│  ├── report_type (4B @ 0)                                  │
│  ├── reserved (12B @ 4)                                    │
│  ├── cpusvn (16B @ 16)                                     │
│  ├── tee_tcb_info_hash (48B @ 32)                          │
│  ├── tee_info_hash (48B @ 80)                              │
│  ├── report_data (64B @ 128) ★ User nonce                  │
│  ├── reserved (32B @ 192)                                  │
│  └── mac (32B @ 224) ★ HMAC over report                    │
├───────────────────────────────────────────────────────────┤
│ TEE_TCB_INFO (256 bytes, offset 256-511)                   │
│  ├── valid (8B @ 256)                                      │
│  ├── tee_tcb_svn (16B @ 264)                               │
│  ├── mrseam (48B @ 280) ★ SEAM module measurement          │
│  ├── mrsigner_seam (48B @ 328)                             │
│  ├── seam_attributes (8B @ 376)                            │
│  └── reserved/padding (128B @ 384)                         │
├───────────────────────────────────────────────────────────┤
│ TDINFO (512 bytes, offset 512-1023)                        │
│  ├── td_attributes (8B @ 512)                              │
│  ├── xfam (8B @ 520)                                       │
│  ├── mrtd (48B @ 528) ★ TD image measurement               │
│  ├── mrconfigid (48B @ 576)                                │
│  ├── mrowner (48B @ 624)                                   │
│  ├── mrownerconfig (48B @ 672)                             │
│  ├── rtmr[0] (48B @ 720)                                   │
│  ├── rtmr[1] (48B @ 768)                                   │
│  ├── rtmr[2] (48B @ 816)                                   │
│  ├── rtmr[3] (48B @ 864)                                   │
│  ├── servtd_hash (48B @ 912)                               │
│  └── reserved (64B @ 960)                                  │
└───────────────────────────────────────────────────────────┘
```

> **Important**: The TEE_TCB_INFO section has **128 bytes of reserved padding** (offsets 384-511). Failing to account for this shifts all TDINFO field offsets incorrectly — a bug we discovered and fixed during implementation.

## Key Measurements

| Measurement | Size | Description |
|------------|------|-------------|
| **MRTD** | 48 bytes | SHA-384 hash of TD's initial memory image. Changes when VM image changes. |
| **RTMR[0]** | 48 bytes | Runtime measurement register 0 — typically firmware measurements |
| **RTMR[1]** | 48 bytes | Runtime measurement register 1 — typically OS kernel measurements |
| **RTMR[2]** | 48 bytes | Runtime measurement register 2 — typically application measurements |
| **RTMR[3]** | 48 bytes | Runtime measurement register 3 — reserved for future use |
| **MRSEAM** | 48 bytes | Measurement of the TDX SEAM module (Intel-provided) |
| **CPUSVN** | 16 bytes | CPU microcode security version |
| **TEE TCB SVN** | 16 bytes | TDX module security version components |
