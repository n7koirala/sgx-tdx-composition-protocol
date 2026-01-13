# SGX-TDX Composition Protocol: Revised Security Analysis

> **Version 2** - Updated based on clarified threat model and design assumptions.

---

## Updated Threat Model Assumptions

Based on clarifications, the protocol operates under these assumptions:

| Assumption | Status |
|------------|--------|
| Proper JWKS signature verification of Intel Trust Authority tokens | ✅ Assumed |
| MRTD whitelist for verified TDX images | ✅ Implemented |
| TDX VM only accessible by SGX controller | ✅ Architectural constraint |
| Cloud provider is honest-but-curious | Implicit |

---

## 1. Revised Security Assessment

With proper JWT verification and MRTD whitelisting in place, the security baseline is significantly improved. The remaining questions focus on:

1. **VM Image Verification at Launch** - How does SGX verify the VM image before approving launch?
2. **Runtime Security** - How to protect against tampering during application execution?
3. **Attack Surface through Unlinkability** - Does hiding platform identity reduce attack surface?

---

## 2. VM Image Verification: Closing the Gaps

### 2.1 The Verification Flow

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                     VM Launch Verification Protocol                             │
├────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  Company X wants to run a CVM                                                   │
│       │                                                                         │
│       │ 1. Submit VM manifest (image hash, kernel hash, initrd hash)            │
│       ▼                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐           │
│  │  SGX Controller                                                  │           │
│  │                                                                  │           │
│  │  2. Verify manifest against public registry                      │           │
│  │     • Check image hash matches published hash                   │           │
│  │     • Verify kernel/initrd are from trusted sources             │           │
│  │     • Optionally: verify reproducible build attestation         │           │
│  │                                                                  │           │
│  │  3. Pre-compute expected MRTD                                    │           │
│  │     • MRTD = f(TDVF, VM config, initial memory layout)          │           │
│  │                                                                  │           │
│  │  4. Add expected MRTD to whitelist                               │           │
│  │                                                                  │           │
│  │  5. Authorize TDX launch                                         │           │
│  └─────────────────────────────────────────────────────────────────┘           │
│       │                                                                         │
│       ▼                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐           │
│  │  TDX Platform                                                    │           │
│  │                                                                  │           │
│  │  6. Launch TD with specified images                              │           │
│  │  7. TDX hardware measures boot chain → MRTD                      │           │
│  │  8. Runtime extends RTMRs                                        │           │
│  └─────────────────────────────────────────────────────────────────┘           │
│       │                                                                         │
│       ▼                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐           │
│  │  SGX Controller (Post-Launch Verification)                       │           │
│  │                                                                  │           │
│  │  9. Request TDX attestation                                      │           │
│  │  10. Verify MRTD matches pre-computed expected value             │           │
│  │  11. Verify RTMRs match expected boot chain                      │           │
│  │  12. If mismatch → terminate TD, reject attestation              │           │
│  └─────────────────────────────────────────────────────────────────┘           │
│                                                                                 │
└────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Key Components Needed

#### A. Image Manifest Schema

```json
{
  "vm_image": {
    "name": "ubuntu-24.04-cvm",
    "source": "https://canonical.com/cvm-images/...",
    "hash_algorithm": "sha384",
    "hash": "abc123..."
  },
  "kernel": {
    "version": "6.8.0-45-generic",
    "source": "https://kernel.ubuntu.com/...",
    "hash": "def456..."
  },
  "initrd": {
    "hash": "ghi789..."
  },
  "tdvf": {
    "version": "edk2-stable202308",
    "hash": "jkl012..."
  },
  "expected_mrtd": "computed-mrtd-value...",
  "expected_rtmr0": "firmware-measurement...",
  "reproducibility_attestation": "optional-link-to-reproducible-build-proof"
}
```

#### B. Public Registry for Known-Good Images

**Option 1: Transparency Log (like Certificate Transparency)**
- Append-only log of approved VM images
- Anyone can verify an image was properly approved
- SGX controller checks image against log before approval

**Option 2: Smart Contract Registry**
- Immutable record of approved images on a blockchain
- Company X's image must be in registry before launch

**Option 3: Signed Manifest from Trusted Authority**
- A trusted third party (or consortium) signs approved image manifests
- SGX controller verifies signature before approving launch

### 2.3 MRTD Pre-Computation

**The Gap**: How does SGX know what MRTD to expect *before* the TD launches?

**Solution**: MRTD is deterministic given the same inputs:
- TDVF (firmware) image
- VM configuration (CPU count, memory, etc.)
- Initial memory layout

**Process**:
1. Company X provides manifest with all inputs
2. SGX controller (or an offline tool) computes expected MRTD
3. After TD launch, actual MRTD is compared to expected
4. Any mismatch indicates tampering or misconfiguration

**Challenge**: MRTD computation requires understanding TDX's measurement algorithm. Intel provides [MRTD calculation tools](https://github.com/intel/tdx-tools) that can be adapted.

### 2.4 Ensuring No Backdoors

| Threat | Detection Method |
|--------|------------------|
| **Malicious kernel module** | RTMR1 will differ from expected (kernel is measured) |
| **Modified initrd** | RTMR1 will differ from expected |
| **Rootkit in VM image** | MRTD will differ from expected |
| **Runtime binary injection** | RTMR2/3 for runtime measurements |
| **Memory-only malware** | Not measured (see Section 3) |

**Recommendation**: For high-assurance scenarios, require:
1. **Reproducible builds** - Same source → same binary → same hash
2. **Public source code** - Company X's kernel/image must be open-source
3. **Independent verification** - Third party builds from source and verifies hash

---

## 3. Runtime Security: Beyond Network Isolation

Freezing the VM and blocking all connections except SGX is a strong starting point. Here are additional runtime protection mechanisms:

### 3.1 Available Mechanisms

| Mechanism | Protection | Limitation |
|-----------|------------|------------|
| **Network Isolation** | No external attack surface | Can't receive legitimate traffic |
| **RTMR Runtime Extension** | Detect runtime code changes | Only measures what's explicitly extended |
| **Memory Encryption (MKTME)** | Protect memory from host | Already built into TDX |
| **Sealed Storage** | Encrypt data to specific MRTD | Data bound to specific VM configuration |
| **SGX-TDX Secure Channel** | Encrypt all SGX↔TDX communication | Requires additional implementation |
| **Attestation Refresh** | Detect drift over time | Periodic overhead |

### 3.2 RTMR-Based Runtime Integrity

The RTMRs can be extended during runtime to create a chain of measurements:

```
┌────────────────────────────────────────────────────────────────┐
│  Runtime Measurement Chain                                      │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [RTMR2 - Application Measurements]                             │
│       │                                                         │
│       ├── App binary hash (at load time)                        │
│       ├── Configuration file hash                               │
│       ├── Dynamic library hashes                                │
│       └── Checkpoint hash (periodic)                            │
│                                                                 │
│  [RTMR3 - User-Defined Measurements]                            │
│       │                                                         │
│       ├── Input data hash (optional)                            │
│       ├── State transition hash                                 │
│       └── Output commitment before release                      │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

**Implementation**: Modify the guest application to extend RTMRs at key points:
```c
// Extend RTMR2 with application hash
tdx_extend_rtmr(RTMR_INDEX_2, app_binary_hash, sizeof(app_binary_hash));

// Extend RTMR3 with state checkpoint
tdx_extend_rtmr(RTMR_INDEX_3, state_checkpoint_hash, sizeof(state_checkpoint_hash));
```

### 3.3 SGX-Witnessed Execution

**Concept**: SGX enclave periodically "witnesses" the TDX VM's state:

```
┌────────────────────────────────────────────────────────────────┐
│  Periodic Witness Protocol                                      │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Every T seconds:                                               │
│                                                                 │
│  1. SGX Controller → TDX: "Report current state"                │
│                                                                 │
│  2. TDX VM:                                                     │
│     • Extend RTMR3 with current memory fingerprint              │
│     • Generate fresh TDX quote                                  │
│     • Return quote to SGX                                       │
│                                                                 │
│  3. SGX Controller:                                             │
│     • Verify quote                                              │
│     • Check RTMRs match expected evolution                      │
│     • If anomaly → terminate TD                                 │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

### 3.4 Memory Protection Mechanisms

| Mechanism | Built into TDX? | Notes |
|-----------|-----------------|-------|
| Memory encryption (TME-MK) | ✅ Yes | All TD memory encrypted |
| Integrity protection | ✅ Yes | Tampering detected |
| DMA protection | ✅ Yes | Devices can't access TD memory |
| MSR filtering | ✅ Yes | Host can't read TD MSRs |
| Interrupt injection control | ✅ Yes | Host can't inject arbitrary interrupts |

### 3.5 What TDX Cannot Protect Against

| Threat | TDX Protection | Additional Mitigation |
|--------|---------------|----------------------|
| **Denial of Service** | ❌ None | Redundancy, monitoring |
| **Timing side-channels** | ⚠️ Partial | Constant-time code |
| **Power/EM side-channels** | ❌ None | Physical security |
| **Memory-only malware** | ❌ Not measured | Runtime attestation |
| **Speculative execution attacks** | ⚠️ Partial | Microcode updates, compiler mitigations |

---

## 4. Attack Surface Reduction Through Unlinkability

This is an insightful observation. Let me analyze it thoroughly.

### 4.1 TDX Attacks Requiring Co-Residency

Many practical attacks on confidential VMs require the attacker to know (or arrange) that they are on the same physical host as the victim:

| Attack Class | Co-Residency Needed? | Detection Method |
|--------------|---------------------|------------------|
| **Cache timing attacks** | ✅ Yes | FMSPC/QE hash match |
| **TLB-based attacks** | ✅ Yes | Same |
| **Memory bus contention** | ✅ Yes | Same |
| **Power analysis (shared PSU)** | ✅ Yes | Same |
| **CrossVM Rowhammer** | ✅ Yes | Same |
| **I/O timing attacks** | ✅ Yes | Same |
| **Network-based attacks** | ❌ No | Network reachability |
| **Cryptographic attacks** | ❌ No | Algorithmic weakness |

### 4.2 How Unlinkability Breaks the Attack Chain

```
┌────────────────────────────────────────────────────────────────────────────────┐
│  STANDARD TDX: Co-Residency Detection Attack                                   │
├────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  [Attacker VM]                        [Victim VM]                               │
│       │                                    │                                    │
│       │ 1. Request attestation             │ 1. Request attestation             │
│       ▼                                    ▼                                    │
│  Token: FMSPC=00806F, QE=aa16bb...    Token: FMSPC=00806F, QE=aa16bb...         │
│                                                                                 │
│  2. Attacker compares: FMSPC match? QE match? → YES                             │
│                                                                                 │
│  3. Attacker knows: "I am co-located with victim"                               │
│                                                                                 │
│  4. Attacker launches: cache timing attack, TLB attack, etc.                    │
│                                                                                 │
├────────────────────────────────────────────────────────────────────────────────┤
│  SGX-TDX COMPOSITION: Co-Residency Detection Blocked                           │
├────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  [Attacker VM]                        [Victim VM]                               │
│       │                                    │                                    │
│       │ 1. Request attestation             │ 1. Request attestation             │
│       ▼                                    ▼                                    │
│  SGX Quote: MRENCLAVE=xyz...          SGX Quote: MRENCLAVE=xyz...               │
│  (TDX platform IDs stripped)          (TDX platform IDs stripped)               │
│                                                                                 │
│  2. Attacker compares: MRENCLAVE match? → YES (same enclave code)               │
│     But: different SGX platforms, different TDX platforms?                      │
│     → CANNOT DETERMINE                                                          │
│                                                                                 │
│  3. Attacker cannot confirm co-location                                         │
│                                                                                 │
│  4. Attack difficulty increased:                                                │
│     • Must attempt attack blindly (low success rate)                            │
│     • Cannot target specific victim                                             │
│     • Cannot confirm attack success through token comparison                    │
│                                                                                 │
└────────────────────────────────────────────────────────────────────────────────┘
```

### 4.3 Quantifying the Security Benefit

**Threat Model Shift**:

| Scenario | Standard TDX | SGX-TDX Composition |
|----------|-------------|---------------------|
| Attacker knows victim's platform | ✅ Possible via attestation | ❌ Not possible |
| Attacker can arrange co-residency | ✅ Cloud placement + detection | ⚠️ Placement yes, detection no |
| Attacker can confirm co-residency | ✅ Token comparison | ❌ No linkable identifiers |
| Targeted attacks possible | ✅ Yes | ⚠️ Only if attacker has side-channel already |

**Attack Success Probability Model**:

Let:
- `P_c` = Probability of achieving co-residency (depends on cloud provider)
- `P_d` = Probability of detecting co-residency (1.0 for standard TDX, ~0 for SGX-TDX)
- `P_a` = Probability of attack success given co-residency + detection

Standard TDX attack success: `P_c × P_d × P_a = P_c × 1.0 × P_a`

SGX-TDX attack success: `P_c × P_d × P_a = P_c × ≈0 × P_a`

**Conclusion**: By eliminating detection capability, the protocol effectively converts targeted attacks into blind attacks, significantly reducing practical attack success.

### 4.4 Remaining Attack Vectors

Even with unlinkability, some attacks remain:

| Attack | Still Possible? | Why |
|--------|-----------------|-----|
| **Blind side-channel** | ⚠️ Yes (lower success) | Attacker launches speculatively |
| **Insider cloud operator** | ⚠️ Yes | Physical access, knows placement |
| **Network timing** | ⚠️ Yes | Can measure latency |
| **Denial of Service** | ⚠️ Yes | Doesn't require co-location |

### 4.5 Architectural Advantage of SGX Controller

The SGX controller adds another layer of attack surface reduction:

```
┌────────────────────────────────────────────────────────────────┐
│  Additional Protection: SGX as Gatekeeper                       │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Network Isolation:                                          │
│     • TDX VM has no public network access                       │
│     • All I/O goes through SGX controller                       │
│     • Reduces network-based attack surface to zero              │
│                                                                 │
│  2. Request Filtering:                                          │
│     • SGX can inspect/sanitize requests before forwarding       │
│     • Rate limiting prevents timing side-channels               │
│     • Can detect anomalous access patterns                      │
│                                                                 │
│  3. Output Verification:                                        │
│     • SGX can verify TDX outputs before releasing               │
│     • Prevent data exfiltration through covert channels         │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

---

## 5. Revised Security Verdict

Given the clarified assumptions, here is the updated assessment:

### Security Improvements over Standalone TDX

| Aspect | Improvement | Mechanism |
|--------|-------------|-----------|
| **Platform Unlinkability** | ✅ Strong | SGX strips FMSPC, QE hash |
| **Co-Residency Detection Prevention** | ✅ Strong | No linkable identifiers |
| **Targeted Attack Difficulty** | ✅ Significant | Cannot confirm target |
| **Network Attack Surface** | ✅ Eliminated | SGX-only access |
| **Attestation Verification Policy** | ✅ Custom | SGX enforces MRTD/TCB rules |

### Security Properties Unchanged

| Aspect | Notes |
|--------|-------|
| **Memory Isolation** | TDX provides this, SGX adds nothing |
| **Quote Authenticity** | Both use Intel ITA |
| **Runtime Integrity** | Depends on RTMR usage |

### Potential Concerns

| Concern | Mitigation |
|---------|------------|
| **SGX side-channel attacks** | SGX enclave only handles metadata, not sensitive computation |
| **TCB expansion** | SGX TCB is well-audited (Gramine), limited functionality |
| **SGX EPC limits** | Enclave only stores verification logic, not data |

---

## 6. Summary: Is SGX-TDX Better Than TDX Alone?

### Revised Answer: **Yes, for specific threat models**

| Criterion | Verdict | Explanation |
|-----------|---------|-------------|
| **Privacy** | ✅ Better | Platform unlinkability |
| **Security vs. Targeted Attacks** | ✅ Better | Breaks co-residency detection |
| **Security vs. Blind Attacks** | ≈ Same | Still depends on TDX isolation |
| **Security vs. Insider Threat** | ≈ Same | Operator has physical access |
| **Scalability** | ✅ Better | Reduces ITA bottleneck |
| **Operational Complexity** | ⚠️ Higher | Two TEE layers to manage |

### Key Insight

> The SGX-TDX composition is not about adding more isolation—TDX already provides VM-level isolation. It's about **adding privacy and policy enforcement** that TDX alone cannot provide, while **breaking the attack chain** that requires co-residency detection.

---

## 7. Remaining Gaps to Address

1. **MRTD Pre-Computation Tool**: Need tooling to compute expected MRTD from manifest
2. **Image Registry Design**: Choose between transparency log, smart contract, or signed manifests
3. **RTMR Extension Protocol**: Define what/when to extend during runtime
4. **Witness Protocol Overhead**: Benchmark periodic attestation refresh
5. **Formal Threat Model Document**: Write explicitly who the adversary is and their capabilities
