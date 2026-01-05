# Mitigation Strategies for Platform Linkability

This document outlines potential approaches to preserve platform privacy in TDX/DCAP attestation
while maintaining the security guarantees required for remote attestation.

---

## 1. Overview of the Problem

### Current State (DCAP)
```
TD Quote → Contains PCK-derived identifiers → Platform linkable
```

### Desired State
```
TD Quote → Privacy-preserving transformation → Platform unlinkable
           ↓
         Still proves:
         ✓ Valid TDX hardware
         ✓ Specific MRTD/RTMRs
         ✓ TCB meets minimum requirements
```

---

## 2. Mitigation Categories

| Category | Approach | Complexity | Privacy Guarantee |
|----------|----------|------------|-------------------|
| **Simple** | Strip/Mask fields | Low | Partial |
| **Architectural** | Proxy attestation | Medium | Good |
| **Cryptographic** | ZK proofs | High | Strong |
| **Systemic** | Group signatures | Very High | Excellent |

---

## 3. Simple Mitigations

### 3.1 Field Stripping

Remove platform-linkable fields before sharing tokens externally.

**Implementation:**

```python
def strip_linkable_fields(token: TDXAttestationToken) -> dict:
    """
    Create a sanitized token with platform-linkable fields removed.
    
    WARNING: This reduces verifiability - external parties cannot
    verify the original Intel signature after modification.
    """
    return {
        # Safe to share
        'mrtd': token.mrtd,
        'rtmrs': token.rtmrs,
        'report_data': token.report_data,
        'is_debuggable': token.is_debuggable,
        
        # TCB - reduced granularity
        'tcb_acceptable': token.tcb_status in ['UpToDate', 'SWHardeningNeeded'],
        
        # Removed: FMSPC, QE hash, advisory IDs, collateral, etc.
    }
```

**Pros:**
- Simple to implement
- No infrastructure changes

**Cons:**
- Breaks original signature verification
- External verifier must trust the stripping party
- Some linkability may remain through other fields

### 3.2 TCB Bucketing

Replace exact TCB values with broader categories.

```python
TCB_BUCKETS = {
    'secure': ['UpToDate'],
    'acceptable': ['SWHardeningNeeded'],
    'outdated': ['OutOfDate'],
    'revoked': ['Revoked', 'ConfigurationNeeded']
}

def bucket_tcb_status(status: str) -> str:
    for bucket, statuses in TCB_BUCKETS.items():
        if status in statuses:
            return bucket
    return 'unknown'
```

### 3.3 Advisory ID Generalization

Replace specific advisory IDs with vulnerability categories.

```python
def generalize_advisories(advisory_ids: list) -> dict:
    """Convert specific advisories to general vulnerability classes"""
    categories = {
        'speculative_execution': [],
        'memory_safety': [],
        'side_channel': [],
        'other': []
    }
    
    CLASSIFICATION = {
        'INTEL-SA-01192': 'speculative_execution',
        'INTEL-SA-01245': 'memory_safety',
        # ... more mappings
    }
    
    for adv in advisory_ids:
        cat = CLASSIFICATION.get(adv, 'other')
        categories[cat].append(adv)
    
    return {
        'speculative_execution_affected': len(categories['speculative_execution']) > 0,
        'memory_safety_affected': len(categories['memory_safety']) > 0,
        # Don't reveal specific IDs
    }
```

---

## 4. Architectural Mitigations

### 4.1 Trusted Proxy Attestation

Use a trusted intermediary to verify attestations and issue privacy-preserving credentials.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Proxy Attestation Architecture                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [TDX Platform]                                                             │
│       │                                                                     │
│       │ 1. Full attestation token                                          │
│       │    (contains FMSPC, QE hash, etc.)                                 │
│       ▼                                                                     │
│  [Trusted Attestation Proxy]                                               │
│       │                                                                     │
│       │ 2. Verify original token                                           │
│       │ 3. Strip platform identifiers                                      │
│       │ 4. Re-sign with proxy key                                          │
│       ▼                                                                     │
│  [Privacy-Preserving Token]                                                 │
│       │                                                                     │
│       │ Contains:                                                           │
│       │ - MRTD, RTMRs (TD measurements)                                    │
│       │ - TCB bucket (not exact status)                                    │
│       │ - Proxy signature                                                   │
│       ▼                                                                     │
│  [External Verifier]                                                        │
│       │                                                                     │
│       │ Trusts proxy, cannot link to platform                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Implementation Sketch:**

```python
class AttestationProxy:
    """Trusted proxy that strips platform identifiers"""
    
    def __init__(self, signing_key):
        self.signing_key = signing_key
        self.verified_tokens = []  # For audit
    
    def process_attestation(self, original_token: str) -> str:
        # 1. Verify original Intel signature
        verified, claims = self.verify_intel_token(original_token)
        if not verified:
            raise ValueError("Invalid attestation")
        
        # 2. Extract safe claims only
        safe_claims = {
            'mrtd': claims['tdx']['tdx_mrtd'],
            'rtmrs': {
                k: claims['tdx'][f'tdx_{k}']
                for k in ['rtmr0', 'rtmr1', 'rtmr2', 'rtmr3']
            },
            'report_data': claims['tdx']['tdx_report_data'],
            'tcb_acceptable': claims['tdx']['attester_tcb_status'] != 'Revoked',
            'debug_disabled': not claims['tdx']['tdx_is_debuggable'],
            'proxy_timestamp': time.time(),
            'proxy_id': self.proxy_id,
        }
        
        # 3. Sign with proxy key
        return jwt.encode(safe_claims, self.signing_key, algorithm='RS256')
```

**Pros:**
- Strong privacy if proxy is trusted
- Maintains verifiability through proxy signature
- Can add rate limiting, audit logging

**Cons:**
- Single point of trust (proxy)
- Proxy sees all platform identities
- Additional infrastructure required

### 4.2 Hierarchical Proxy Chain

For hierarchical TEE composition, use the SGX layer as a privacy proxy.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Hierarchical Privacy Architecture                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [TDX VM (Outer Layer)]                                                     │
│       │                                                                     │
│       │ TDX attestation (full, with platform IDs)                          │
│       ▼                                                                     │
│  [SGX Enclave (Inner Layer - Privacy Proxy)]                               │
│       │                                                                     │
│       │ 1. Verify TDX token inside enclave                                 │
│       │ 2. Extract only safe fields                                        │
│       │ 3. Include in SGX report_data                                      │
│       │ 4. Generate SGX quote                                              │
│       ▼                                                                     │
│  [Composite Attestation]                                                    │
│       │                                                                     │
│       │ SGX quote containing:                                              │
│       │ - SGX MRENCLAVE (identifies proxy code)                            │
│       │ - TDX MRTD (in report_data)                                        │
│       │ - TCB status (bucketed)                                            │
│       │ - NO platform identifiers                                          │
│       ▼                                                                     │
│  [External Verifier]                                                        │
│                                                                             │
│       Verifies SGX quote → trusts proxy code → accepts TDX claims          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Advantage:** Trust is in the **code** (MRENCLAVE), not in an operator.

---

## 5. Cryptographic Mitigations

### 5.1 Zero-Knowledge Proofs for TCB

Prove TCB meets requirements without revealing exact version.

**Goal:** Prove "TCB date ≥ 2024-01-01" without revealing actual date.

```python
# Conceptual implementation (requires ZK library)
from zkp import RangeProof

def create_tcb_proof(tcb_date: str, minimum_date: str) -> bytes:
    """
    Create ZK proof that tcb_date >= minimum_date
    without revealing actual tcb_date
    """
    tcb_days = date_to_days(tcb_date)
    min_days = date_to_days(minimum_date)
    
    # Range proof: tcb_days is in range [min_days, infinity)
    proof = RangeProof.create(
        secret=tcb_days,
        lower_bound=min_days
    )
    
    return proof.serialize()

def verify_tcb_proof(proof: bytes, minimum_date: str) -> bool:
    """Verify TCB meets minimum without learning actual value"""
    min_days = date_to_days(minimum_date)
    return RangeProof.verify(proof, lower_bound=min_days)
```

### 5.2 Set Membership Proofs for FMSPC

Prove platform is in an allowed set without revealing which one.

```python
# Prove FMSPC ∈ {allowed_set} without revealing which member

ALLOWED_FMSPCS = [
    "00806F050000",  # Sapphire Rapids
    "00806F060000",  # Sapphire Rapids variant
    "00906D000000",  # Emerald Rapids
    # ... more allowed platforms
]

def create_membership_proof(fmspc: str, allowed_set: list) -> bytes:
    """
    ZK proof that fmspc is in allowed_set
    without revealing which element
    """
    # Merkle proof or accumulator-based proof
    pass
```

### 5.3 Blind Signatures for Attestation Credentials

1. Platform blinds its attestation
2. Authority signs blindly
3. Platform unblinds to get valid credential
4. Credential is unlinkable to signing session

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Blind Signature Flow                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [Platform]                        [Signing Authority]                      │
│       │                                   │                                 │
│       │ 1. Create attestation claim       │                                 │
│       │    m = (MRTD, RTMRs, TCB_OK)     │                                 │
│       │                                   │                                 │
│       │ 2. Blind the message              │                                 │
│       │    m' = Blind(m, r)              │                                 │
│       │                                   │                                 │
│       │ ────── Send blinded m' ─────────► │                                 │
│       │                                   │                                 │
│       │                                   │ 3. Verify original attestation  │
│       │                                   │    (out of band, sees platform) │
│       │                                   │                                 │
│       │                                   │ 4. Sign blinded message         │
│       │                                   │    s' = Sign(m')               │
│       │                                   │                                 │
│       │ ◄───── Return signature s' ─────  │                                 │
│       │                                   │                                 │
│       │ 5. Unblind signature              │                                 │
│       │    s = Unblind(s', r)            │                                 │
│       │                                   │                                 │
│       │ Now (m, s) is a valid credential  │                                 │
│       │ that cannot be linked to          │                                 │
│       │ the signing session               │                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Systemic Mitigations

### 6.1 Group Signatures (EPID-like)

The most comprehensive solution: platforms join groups and sign attestations
with keys that prove group membership without identifying the signer.

**Properties:**
- **Anonymity**: Verifier cannot identify which group member signed
- **Unlinkability**: Different signatures cannot be correlated
- **Traceability**: Group manager can revoke misbehaving members
- **Non-frameability**: Even group manager cannot forge signatures

**Challenge:** Requires Intel to move away from DCAP model.

### 6.2 Anonymous Credential Systems

Issue anonymous credentials based on attestation, reuse credentials without re-attesting.

```
Phase 1: Credential Issuance (done once per TD)
┌──────────────────────────────────────────────────────────────────┐
│ Platform attests → Authority verifies → Issues anonymous cred   │
└──────────────────────────────────────────────────────────────────┘

Phase 2: Credential Use (done many times)
┌──────────────────────────────────────────────────────────────────┐
│ Platform shows cred → Verifier accepts → No new attestation     │
│ Each showing is unlinkable to issuance and other showings       │
└──────────────────────────────────────────────────────────────────┘
```

**Implementations:**
- Idemix (IBM)
- U-Prove (Microsoft)
- BBS+ signatures

---

## 7. Practical Recommendations

### 7.1 Short-Term (Immediate)

1. **Implement field stripping** in `tdx_remote_attestation.py`
2. **Add proxy service** that SGX enclave can use
3. **Document which fields** external verifiers actually need

### 7.2 Medium-Term (3-6 months)

1. **Deploy hierarchical proxy** using SGX as privacy layer
2. **Implement TCB bucketing** for external-facing tokens
3. **Research ZK library integration** for range proofs

### 7.3 Long-Term (Research)

1. **Explore group signature schemes** for TDX
2. **Propose DCAP extensions** to Intel for privacy modes
3. **Publish findings** to influence industry standards

---

## 8. Implementation Status

| Mitigation | Status | File |
|------------|--------|------|
| Strip linkable fields | ✅ Ready | `token.get_platform_linkable_fields()` |
| TCB bucketing | 📋 Planned | -- |
| Proxy service | 📋 Planned | -- |
| ZK proofs | 🔬 Research | -- |
| Group signatures | 🔬 Research | -- |

---

## 9. References

1. "Anonymous Attestation with User-Controlled Linkability" - Enhanced Privacy ID (EPID)
2. "Direct Anonymous Attestation" - TCG specification
3. "Bulletproofs: Short Proofs for Confidential Transactions" - Range proofs
4. "BBS+ Signatures" - Used in anonymous credentials
5. Intel TDX Architecture Specification
6. "Privacy-Preserving Remote Attestation for Systems without Trusted Hardware"
