# PCK Certificate Linkability Analysis

## Executive Summary

Intel's DCAP (Datacenter Attestation Primitives) attestation scheme exposes platform privacy 
through the **Platform Configuration Key (PCK) certificate**. This document analyzes how 
PCK-derived identifiers leak into TDX attestation tokens and enable cross-attestation linkability.

---

## 1. Background: What is the PCK?

### 1.1 PCK Certificate Definition

The **Platform Configuration Key (PCK)** certificate is:
- A unique X.509 certificate issued by Intel for each SGX/TDX platform
- Contains the public key corresponding to the platform's attestation key
- Encodes platform-specific identifiers (FMSPC, CPU SVN, PCE SVN)
- Used to verify the authenticity of the Quoting Enclave's signature

### 1.2 PCK in the Attestation Chain

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     TDX Attestation Signature Chain                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  TDX Quote ─┬─► Signed by Attestation Key (AK)                             │
│             │                                                               │
│             └─► AK certified by PCK Certificate  ◄── PLATFORM UNIQUE!      │
│                           │                                                 │
│                           └─► PCK certified by Intel Root CA               │
│                                                                             │
│  Result: Anyone verifying the quote can see the PCK certificate            │
│          and link the quote to a specific physical platform                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Where PCK Information Leaks in TDX Attestation

### 2.1 Attestation Flow and Leak Points

```
                                        LEAK POINTS
                                            │
┌──────────────────────────────────────────┼──────────────────────────────────┐
│                                          ▼                                  │
│  [TD Guest]                                                                 │
│      │                                                                      │
│      │ 1. Generate TDREPORT                                                 │
│      │    (contains MRTD, RTMRs, report_data)                              │
│      ▼                                                                      │
│  [Quoting Enclave (QE)]                                                     │
│      │                                                                      │
│      │ 2. Sign TDREPORT with Attestation Key ◄─── LEAK #1: QE identity     │
│      │    Include PCK certificate chain                in quote signature  │
│      ▼                                                                      │
│  [TDX Quote]                                                                │
│      │                                                                      │
│      │ Contains:                                                            │
│      │ - TD measurements (safe)                                             │
│      │ - QE certification data (LINKABLE!) ◄────── LEAK #2: PCK-derived    │
│      │ - PCK certificate chain                     identifiers in quote    │
│      ▼                                                                      │
│  [Intel Trust Authority]                                                    │
│      │                                                                      │
│      │ 3. Verify quote, extract claims                                      │
│      │    Embed collateral in JWT ◄────────────── LEAK #3: Collateral      │
│      ▼                                             in returned token       │
│  [JWT Token]                                                                │
│      │                                                                      │
│      │ Contains:                                                            │
│      │ - tdx_collateral.fmspc                                              │
│      │ - tdx_collateral.qeidhash                                           │
│      │ - attester_tcb_date                                                 │
│      │ - attester_advisory_ids                                             │
│      ▼                                                                      │
│  [Verifier receives token]                                                  │
│                                                                             │
│      Verifier can now link this attestation to any other                   │
│      attestation from the same platform!                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Code Location in tdx_remote_attestation.py

The leak occurs through the `trustauthority-cli` call:

```python
# Lines 354-361 in tdx_remote_attestation.py
cmd = ["sudo", "trustauthority-cli", "token", "--tdx", "-c", self.config_path]
result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

# The returned token contains PCK-derived identifiers:
# - payload['tdx']['tdx_collateral']['fmspc']
# - payload['tdx']['tdx_collateral']['qeidhash']
# - payload['tdx']['attester_tcb_date']
# - payload['tdx']['attester_advisory_ids']
```

---

## 3. Empirical Evidence: Same Platform Detection

### 3.1 Multiple Attestation Runs

Running `tdx_remote_attestation.py` multiple times on the same platform shows:

| Field | Run 1 | Run 2 | Run 3 | Same? |
|-------|-------|-------|-------|-------|
| FMSPC | `00806F050000` | `00806F050000` | `00806F050000` | ✅ YES |
| QE ID Hash | `aa16bb279885...` | `aa16bb279885...` | `aa16bb279885...` | ✅ YES |
| TCB Date | `2025-05-14` | `2025-05-14` | `2025-05-14` | ✅ YES |
| Advisory IDs | `[SA-01192, ...]` | `[SA-01192, ...]` | `[SA-01192, ...]` | ✅ YES |
| MRTD | `a5844e88897b...` | `a5844e88897b...` | `a5844e88897b...` | ✅ YES (same TD) |
| Report Data | `6f635064ec14...` | `657f993a888b...` | `69ded82f4c42...` | ❌ NO (nonce) |
| Token ID (JTI) | `448d929c-...` | `d99875b1-...` | `f637eeb4-...` | ❌ NO (unique) |

### 3.2 Linkability Attack Demonstration

An adversary observing two tokens can determine they came from the same platform:

```python
def are_same_platform(token1, token2):
    """Determine if two TDX tokens came from the same physical platform"""
    
    # Extract linkable fields
    fmspc1 = token1.collateral.get('fmspc')
    fmspc2 = token2.collateral.get('fmspc')
    
    qe1 = token1.collateral.get('qeidhash')
    qe2 = token2.collateral.get('qeidhash')
    
    # If FMSPC matches, very likely same platform family
    # If QE hash matches, definitely same Quoting Enclave = same platform
    return fmspc1 == fmspc2 and qe1 == qe2
```

---

## 4. Understanding FMSPC

### 4.1 FMSPC Structure

**FMSPC** = Family-Model-Stepping + Platform Configuration

Format: 6 bytes (12 hex characters), e.g., `00806F050000`

| Bytes | Meaning | Example |
|-------|---------|---------|
| 0-1 | Reserved/Flags | `00` |
| 2 | Family | `80` (Core family) |
| 3 | Model | `6F` (specific CPU model) |
| 4 | Stepping + Revision | `05` |
| 5 | Platform Config | `00` |

### 4.2 What FMSPC Reveals

- **CPU Generation**: Which Intel processor generation
- **Model Variant**: Specific SKU within generation
- **Platform Configuration**: OEM-specific settings
- **Approximate Fleet Size**: Number of similar platforms

### 4.3 Privacy Impact

FMSPC alone may identify thousands of platforms (low k-anonymity), but combined with:
- TCB Date (when patches applied)
- Advisory IDs (which vulnerabilities affect this platform)
- QE ID Hash (specific Quoting Enclave version)

...the anonymity set shrinks dramatically, potentially to a single platform.

---

## 5. Attack Scenarios

### 5.1 Cross-Service Tracking

```
┌─────────────────────────────────────────────────────────────────┐
│ Scenario: User runs different VMs on same TDX host              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  VM-A (Medical Data)     VM-B (Financial)     VM-C (Research)  │
│       │                       │                     │          │
│       ▼                       ▼                     ▼          │
│   Attestation A          Attestation B         Attestation C   │
│  FMSPC: 00806F050000     FMSPC: 00806F050000   FMSPC: 00806F.. │
│  QE: aa16bb27...         QE: aa16bb27...       QE: aa16bb27... │
│                                                                 │
│  ⚠️ All three VMs linkable as running on same physical host!   │
│                                                                 │
│  Attack: Verifier learns user's medical, financial, and        │
│          research workloads are co-located                      │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Temporal Tracking

```
┌─────────────────────────────────────────────────────────────────┐
│ Scenario: Same TD attests over time                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Day 1          Day 30         Day 60         Day 90           │
│    │               │              │              │              │
│    ▼               ▼              ▼              ▼              │
│  Token-1        Token-2        Token-3        Token-4          │
│  FMSPC: 00806F  FMSPC: 00806F  FMSPC: 00806F  FMSPC: 00806F    │
│                                                                 │
│  ⚠️ Platform location can be tracked across months!            │
│                                                                 │
│  Attack: Build movement patterns, uptime statistics,           │
│          maintenance windows, workload changes                  │
└─────────────────────────────────────────────────────────────────┘
```

### 5.3 Co-residency Detection

```
┌─────────────────────────────────────────────────────────────────┐
│ Scenario: Cloud provider hosts multiple tenant VMs              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Tenant A                  Tenant B                             │
│  (Victim)                  (Attacker)                           │
│     │                         │                                 │
│     ▼                         ▼                                 │
│  Attestation:              Attestation:                         │
│  FMSPC: 00806F050000       FMSPC: 00806F050000                  │
│  QE: aa16bb27...           QE: aa16bb27...                      │
│                                                                 │
│  ⚠️ Attacker knows they're on the same physical host!          │
│                                                                 │
│  Attack: Launch side-channel attacks, timing attacks,          │
│          microarchitectural attacks with higher success rate    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. Comparison with Privacy-Preserving Alternatives

### 6.1 EPID (Enhanced Privacy ID)

| Aspect | DCAP (Current) | EPID (Deprecated) |
|--------|---------------|-------------------|
| Platform Linkability | Yes (PCK is unique) | No (group signatures) |
| Revocation | Per-platform | Group-based |
| Deployment | Third-party verifiers | Intel IAS only |
| Performance | ~400ms | ~600ms |
| Privacy | Poor | Strong |

### 6.2 Desired Properties for Private Attestation

1. **Unlinkability**: Different attestations cannot be correlated
2. **TCB Proof**: Prove TCB status without revealing exact version
3. **Measurement Proof**: Prove specific MRTD without revealing platform
4. **Revocation**: Support per-platform revocation without compromising privacy

---

## 7. Recommendations for Hierarchical TEE Protocol

### 7.1 Immediate Mitigations

1. **Strip Collateral Before External Verification**
   ```python
   def sanitize_token_for_external(token):
       # Remove platform-linkable fields before sharing
       safe_claims = {
           'mrtd': token.mrtd,
           'rtmrs': token.rtmrs,
           'report_data': token.report_data,
           'tcb_status': token.tcb_status,  # May need ZKP
           'is_debuggable': token.is_debuggable,
       }
       return safe_claims
   ```

2. **Proxy-Based Attestation**
   - Trusted intermediary (SGX controller) re-signs attestations
   - Platform identity hidden from final verifier

3. **Batch/Aggregate Attestations**
   - Combine multiple platform attestations
   - Only prove "at least k platforms attested"

### 7.2 Other esearch Directions

1. **Zero-Knowledge Proofs for TCB**
   - Prove "TCB >= minimum threshold" without revealing exact version
   - Range proofs for SEAM SVN, TCB date
   - Too slow

3. **Trusted Shuffling Service**
   - Mix attestations from multiple platforms
   - Break correlation between input and output

---

## 8. References

1. Intel DCAP Developer Guide
2. "Practical Issues with TLS Client Certificate Authentication" (related privacy concerns)
3. "Privacy-Preserving Remote Attestation for Systems without Trusted Hardware" (academic)
4. Intel SGX EPID Deprecation Notice
5. TDX Module Architecture Specification
