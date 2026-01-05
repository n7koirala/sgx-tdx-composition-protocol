# TDX Attestation Token Fields Reference

This document provides a complete reference of all fields present in TDX attestation tokens 
returned by Intel Trust Authority, organized by privacy sensitivity.

---

## Token Structure Overview

TDX attestation tokens are **JWT (JSON Web Tokens)** with three parts:

```
eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3BvcnRhbC50...
├── Header (Base64)         ├── Payload (Base64)              ├── Signature
│   - Algorithm             │   - Standard JWT claims         │   - RS256 sig
│   - Key ID                │   - TDX-specific claims         │
│                           │   - Collateral                  │
```

---

## 1. JWT Standard Claims (Header + Payload)

### 1.1 Header Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `alg` | string | Signing algorithm | `"RS256"` or `"PS384"` |
| `kid` | string | Key ID for verification | UUID |
| `typ` | string | Token type | `"JWT"` |

### 1.2 Standard Payload Claims

| Field | Type | Description | Privacy Risk | Example |
|-------|------|-------------|--------------|---------|
| `iss` | string | Token issuer | 🟢 LOW | `"https://portal.trustauthority.intel.com"` |
| `iat` | int | Issued-at timestamp | 🟢 LOW | `1736048673` |
| `exp` | int | Expiration timestamp | 🟢 LOW | `1736048973` |
| `nbf` | int | Not-before timestamp | 🟢 LOW | `1736048673` |
| `jti` | string | Unique token ID | 🟢 LOW | `"448d929c-dadb-4cb9-b3f7-..."` |

---

## 2. Core TDX Claims (Privacy-Preserving)

These fields are **TD-specific** and do NOT enable platform linkability:

### 2.1 TD Measurement (MRTD)

| Field | Description | Privacy Risk |
|-------|-------------|--------------|
| `tdx_mrtd` | 48-byte SHA-384 hash of TD initial state | 🟢 LOW |

**What it measures:**
- TDVF (TD Virtual Firmware) image
- TD creation parameters
- Initial memory layout

**Example:**
```json
"tdx_mrtd": "a5844e88897b70c318bef929ef4dfd6c7304c52c4bc9c3f3..."
```

### 2.2 Runtime Measurement Registers (RTMRs)

| Field | Description | Privacy Risk | Extends By |
|-------|-------------|--------------|------------|
| `tdx_rtmr0` | Firmware measurements | 🟢 LOW | TDVF |
| `tdx_rtmr1` | OS boot measurements | 🟢 LOW | Guest kernel/initrd |
| `tdx_rtmr2` | OS runtime measurements | 🟢 LOW | Applications |
| `tdx_rtmr3` | User-defined measurements | 🟢 LOW | Application code |

**Example:**
```json
"tdx_rtmr0": "cdd12631746b633b87592779e3118c959c8d9e306792ba9a...",
"tdx_rtmr1": "160767baf7423a37bcfbc903877d36c174831818b56aed33...",
"tdx_rtmr2": "4e1d7c0083277d4b617cee58f0b9d76c4a48ce36b1e25cb6...",
"tdx_rtmr3": "000000000000000000000000000000000000000000000000..."
```

### 2.3 User Report Data

| Field | Description | Privacy Risk |
|-------|-------------|--------------|
| `tdx_report_data` | 64 bytes of user-provided data in quote | 🟢 LOW |

**Usage:**
- Binding data (nonces, hashes)
- SGX MRENCLAVE for hierarchical attestation
- Application-specific commitments

**Example:**
```json
"tdx_report_data": "6f635064ec14cdb35553c8183bdd49163114796d07263968..."
```

---

## 3. TDX Module Claims (Version-Linkable)

These fields identify the TDX module version (same across platforms with same TDX):

| Field | Description | Privacy Risk | Why |
|-------|-------------|--------------|-----|
| `tdx_mrseam` | TDX Module measurement | 🟡 MEDIUM | Same for all platforms with same TDX version |
| `tdx_mrsignerseam` | TDX Module signer | 🟡 MEDIUM | Intel's TDX module signature |
| `tdx_seamsvn` | SEAM security version | 🟡 MEDIUM | Narrows to platforms with specific update |

**Example:**
```json
"tdx_mrseam": "bfb360ac8e6233a1bca1433caf7382d95c165b4a77fb00bf...",
"tdx_mrsignerseam": "0000000000000000000000000000000000000000...",
"tdx_seamsvn": 264
```

---

## 4. TD Owner Claims

| Field | Description | Privacy Risk |
|-------|-------------|--------------|
| `tdx_mrowner` | TD Owner identity hash | 🟢 LOW |
| `tdx_mrownerconfig` | Owner configuration hash | 🟢 LOW |

**Note:** Often zero if not configured by cloud provider.

**Example:**
```json
"tdx_mrowner": "000000000000000000000000000000000000000000...",
"tdx_mrownerconfig": "000000000000000000000000000000000000..."
```

---

## 5. TD Attributes

| Field | Description | Privacy Risk | Example |
|-------|-------------|--------------|---------|
| `tdx_xfam` | Extended Feature Activation Mask | 🟢 LOW | `"e700060000000000"` |
| `tdx_is_debuggable` | Debug mode enabled | 🟢 LOW | `false` |
| `tdx_td_attributes_septve_disable` | SEPT VE disabled | 🟢 LOW | `true` |
| `tdx_td_attributes_pks` | Protection Keys for Supervisor | 🟢 LOW | `null` |
| `tdx_td_attributes_kl` | Key Locker enabled | 🟢 LOW | `null` |

---

## 6. TCB Information (Platform-Linkable!) ⚠️

These fields reveal platform security state and are **linkable across attestations**:

| Field | Description | Privacy Risk | Why Linkable |
|-------|-------------|--------------|--------------|
| `attester_tcb_status` | TCB security status | 🟡 MEDIUM | Same platforms have same status |
| `attester_tcb_date` | TCB evaluation date | 🟡 MEDIUM | Reveals when patches applied |
| `attester_advisory_ids` | Security advisories | 🟡 MEDIUM | Reveals which CVEs affect platform |

### 6.1 TCB Status Values

| Value | Meaning | Security |
|-------|---------|----------|
| `UpToDate` | All patches applied | ✅ Secure |
| `SWHardeningNeeded` | Software mitigations recommended | ⚠️ Acceptable |
| `OutOfDate` | Patches available but not applied | ⚠️ Risk |
| `Revoked` | Platform keys revoked | ❌ Compromised |

### 6.2 Example

```json
"attester_tcb_status": "OutOfDate",
"attester_tcb_date": "2025-05-14T00:00:00Z",
"attester_advisory_ids": [
    "INTEL-SA-01192",
    "INTEL-SA-01245",
    "INTEL-SA-01312",
    "INTEL-SA-01313"
]
```

---

## 7. Collateral (HIGHLY LINKABLE!) 🔴

**This is the primary source of platform linkability.** These fields are derived from 
the PCK certificate and uniquely identify the physical platform.

### 7.1 Primary Linkable Fields

| Field | Description | Privacy Risk | Linkability |
|-------|-------------|--------------|-------------|
| `fmspc` | Family-Model-Stepping + Platform Config | 🔴 HIGH | Identifies platform family (thousands) |
| `qeidhash` | Quoting Enclave ID hash | 🔴 HIGH | Unique per QE version on platform |
| `pceid` | PCE Identity | 🔴 HIGH | Platform Certification Enclave ID |

### 7.2 FMSPC Structure

```
FMSPC: 00806F050000
       │ │ ││ ││ ││
       │ │ ││ ││ └┴── Platform Configuration
       │ │ ││ └┴───── Stepping + Revision
       │ │ └┴──────── CPU Model
       │ └─────────── CPU Family
       └───────────── Reserved/Flags
```

### 7.3 Secondary Collateral Fields

| Field | Description | Privacy Risk |
|-------|-------------|--------------|
| `qeidcerthash` | QE certificate hash | 🟡 MEDIUM |
| `qeidcrlhash` | QE CRL hash | 🟡 MEDIUM |
| `quotehash` | Quote structure hash | 🟢 LOW |
| `tcbinfocerthash` | TCB info certificate hash | 🟡 MEDIUM |
| `tcbinfocrlhash` | TCB info CRL hash | 🟡 MEDIUM |
| `tcbinfohash` | TCB info hash | 🟡 MEDIUM |
| `tcbevaluationdatanumber` | TCB evaluation version | 🟡 MEDIUM |

### 7.4 Example

```json
"tdx_collateral": {
    "fmspc": "00806F050000",
    "qeidhash": "aa16bb279885496b5ef36ec880d9cae3...",
    "qeidcerthash": "8b4d5f2e3a1c9d...",
    "qeidcrlhash": "f3a2b1c4d5e6...",
    "quotehash": "9e8d7c6b5a4f...",
    "tcbinfocerthash": "1a2b3c4d5e6f...",
    "tcbinfocrlhash": "a1b2c3d4e5f6...",
    "tcbinfohash": "0f1e2d3c4b5a...",
    "tcbevaluationdatanumber": 20
}
```

---

## 8. Complete Token Payload Example

```json
{
    "iss": "https://portal.trustauthority.intel.com",
    "iat": 1736048673,
    "exp": 1736048973,
    "nbf": 1736048673,
    "jti": "448d929c-dadb-4cb9-b3f7-2f2ba8b98765",
    
    "tdx": {
        // Core TD Measurements (SAFE)
        "tdx_mrtd": "a5844e88897b70c318bef929ef4dfd6c7304c52c4bc9c3f3...",
        "tdx_rtmr0": "cdd12631746b633b87592779e3118c959c8d9e306792ba9a...",
        "tdx_rtmr1": "160767baf7423a37bcfbc903877d36c174831818b56aed33...",
        "tdx_rtmr2": "4e1d7c0083277d4b617cee58f0b9d76c4a48ce36b1e25cb6...",
        "tdx_rtmr3": "000000000000000000000000000000000000000000000000...",
        "tdx_report_data": "6f635064ec14cdb35553c8183bdd49163114796d...",
        
        // TDX Module (VERSION-LINKABLE)
        "tdx_mrseam": "bfb360ac8e6233a1bca1433caf7382d95c165b4a77fb00bf...",
        "tdx_mrsignerseam": "0000000000000000000000000000000000000000...",
        "tdx_seamsvn": 264,
        
        // TD Owner
        "tdx_mrowner": "000000000000000000000000000000000000000000...",
        "tdx_mrownerconfig": "000000000000000000000000000000000000...",
        
        // TD Attributes
        "tdx_xfam": "e700060000000000",
        "tdx_is_debuggable": false,
        "tdx_td_attributes_septve_disable": true,
        
        // TCB Info (PLATFORM-LINKABLE)
        "attester_tcb_status": "OutOfDate",
        "attester_tcb_date": "2025-05-14T00:00:00Z",
        "attester_advisory_ids": ["INTEL-SA-01192", "INTEL-SA-01245", ...],
        
        // Collateral (HIGHLY LINKABLE - PCK-derived!)
        "tdx_collateral": {
            "fmspc": "00806F050000",
            "qeidhash": "aa16bb279885496b5ef36ec880d9cae3...",
            "tcbevaluationdatanumber": 20,
            ...
        }
    }
}
```

---

## 9. Privacy Classification Summary

| Category | Fields | Privacy Risk | Action |
|----------|--------|--------------|--------|
| **TD Measurements** | MRTD, RTMRs, Report Data | 🟢 LOW | ✅ Safe to share |
| **TD Owner** | MROWNER, MROWNERCONFIG | 🟢 LOW | ✅ Safe to share |
| **TD Attributes** | XFAM, Debug, etc. | 🟢 LOW | ✅ Safe to share |
| **TDX Module** | MRSEAM, SEAMSVN | 🟡 MEDIUM | ⚠️ Consider masking |
| **TCB Info** | Status, Date, Advisories | 🟡 MEDIUM | ⚠️ Use ZK proofs |
| **Collateral** | FMSPC, QE Hash, etc. | 🔴 HIGH | ❌ Must anonymize |

---

## 10. Extracting Fields in Python

```python
from tdx_remote_attestation import TDXAttestor

attestor = TDXAttestor()
token = attestor.get_attestation_token()

# Safe fields (TD-specific)
safe = {
    'mrtd': token.mrtd,
    'rtmrs': token.rtmrs,
    'report_data': token.report_data,
}

# Platform-linkable fields (should be removed/anonymized)
linkable = token.get_platform_linkable_fields()
# Returns: tcb_status, tcb_date, advisory_ids, seamsvn, collateral

# Full token dict
all_fields = token.to_dict()
```
