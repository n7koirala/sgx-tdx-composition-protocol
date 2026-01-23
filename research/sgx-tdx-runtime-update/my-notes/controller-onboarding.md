# Controller Onboarding and Trust

## The Trust Problem

> When a new controller wants to join the system, how do existing controllers know it's legitimate?

---

## Onboarding Mechanisms

### 1. Remote Attestation (Recommended) ⭐

```
New Controller (NC) joins:

┌──────────────┐                    ┌──────────────────────────────┐
│     NC       │                    │    Existing Controllers      │
│  (wants to   │                    │    (A, B, C)                 │
│   join)      │                    │                              │
└──────┬───────┘                    └──────────────┬───────────────┘
       │                                           │
       │  1. Generate SGX Quote                    │
       │     (includes MRENCLAVE)                  │
       │                                           │
       │  2. Send JoinRequest{quote, pubkey}       │
       │─────────────────────────────────────────▶│
       │                                           │
       │                            3. Each controller verifies:
       │                               - Quote valid (Intel IAS)
       │                               - MRENCLAVE matches expected
       │                               - TCB up to date
       │                                           │
       │  4. Collect approvals (majority needed)   │
       │◀─────────────────────────────────────────│
       │                                           │
       │  5. If approved: added to peer list       │
       │                                           │
```

**Why Attestation?**
- Proves NC runs genuine SGX enclave
- Proves NC runs expected controller code (MRENCLAVE)
- Prevents rogue controllers from joining

### 2. Approval Policies

| Policy | Requirement | Use Case |
|--------|-------------|----------|
| **Any** | 1 controller approves | Low security, fast onboarding |
| **Majority** | >50% approve (2/3, 3/5) | **Recommended balance** |
| **Unanimous** | 100% approve | High security, slow |
| **Weighted** | Voting weights per controller | Trust hierarchies |

### 3. Vouching + Attestation (Hybrid)

```
Admin tells Controller A: "Vouch for new Controller D"

1. A attests D (verifies SGX quote)
2. A signs vouching certificate for D
3. A broadcasts cert to B, C
4. B, C independently verify D's attestation
5. If majority verify → D admitted
```

---

## Controller Registry

```python
@dataclass
class ControllerInfo:
    controller_id: str
    public_key: str
    endpoint: str           # host:port
    sgx_quote: bytes        # Latest attestation
    mr_enclave: str         # Expected measurement
    joined_at: float
    vouched_by: List[str]   # Approvers
    status: str             # 'active', 'pending', 'revoked'

class ControllerRegistry:
    controllers: Dict[str, ControllerInfo]
    
    def add_controller(self, info, approvals) -> bool:
        required = len(self.controllers) // 2 + 1
        if len(approvals) >= required:
            self.controllers[info.controller_id] = info
            return True
        return False
    
    def revoke_controller(self, controller_id, approvers):
        # Also requires majority to revoke
        required = len(self.controllers) // 2 + 1
        if len(approvers) >= required:
            self.controllers[controller_id].status = 'revoked'
```

---

## Revocation

A controller may need to be revoked if:
- Compromised (side-channel attack detected)
- TCB outdated (security patches needed)
- Misbehaving (invalid entries, DoS)

**Revocation Process:**
1. Any controller proposes revocation with evidence
2. Majority vote required
3. Revoked controller removed from peer list
4. Revoked controller's pending commands rejected

---

## Periodic Re-Attestation

Controllers should re-attest periodically to prove:
- Still running expected code
- TCB still up to date
- Not compromised

```python
# Every 24 hours
def periodic_attestation():
    for peer in self.peers:
        quote = peer.get_fresh_quote()
        if not verify_quote(quote):
            propose_revocation(peer)
```
