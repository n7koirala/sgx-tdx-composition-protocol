# Multi-Controller Architecture for SGX-TDX Runtime Update System

## Goals

1. **No Single Point of Failure (SPOF)**: System remains operational if any controller fails
2. **Scalability**: Handle large numbers of ASPs (runtime updates) and end-users (attestation requests)

---

## Architecture Options Comparison

| Architecture | No SPOF | Scalability | Complexity | Hash-Chain Consistency | Best Use Case |
|--------------|---------|-------------|------------|------------------------|---------------|
| Single Controller | ❌ | ❌ | Very Low | ✅ Trivial | Testing/Dev |
| Primary + Overflow | ❌ | ⚠️ Medium | Low | ✅ Single writer | Simple production |
| **Active-Active** | ✅ | ✅ High | Medium | ⚠️ Needs sync | **Recommended** |
| BFT Consensus | ✅ | ⚠️ Limited | High | ✅ Consensus | Byzantine threats |

---

## Option 1: Single Controller

```
ASP/Users ──────▶ [Controller A] ──────▶ CVM
                        │
                  Hash-Chain Log
```

### Strengths
- Simplest implementation
- No coordination overhead
- Trivial hash-chain consistency

### Weaknesses
- **SPOF**: If controller dies, entire system down
- **No scalability**: Single point handles all load
- **No redundancy**: No backup for recovery

### When to Use
- Development and testing only

---

## Option 2: Primary + Overflow (Vertical Scaling)

```
                    ┌─────────────────┐
   ASP/Users ──────▶│ Primary (A)     │
                    │ threshold=100   │
                    └────────┬────────┘
                             │
                  overflow   │   direct
              ┌──────────────┼───────────┐
              ▼              ▼           ▼
         [Ctrl B]       [Ctrl C]       CVM
         (backup)       (backup)
              │              │
              └──────────────┘
                     │
                     ▼
           Sync back to Primary
           (Primary owns log)
```

### Strengths
- Simple single entry point (no load balancer needed)
- Primary owns hash-chain (no distributed log issues)
- Easy to understand and implement

### Weaknesses
- **SPOF**: Primary is still single point of failure
- **Bottleneck**: All responses flow through primary
- **Failover needed**: If primary dies, manual intervention required

### When to Use
- Small to medium deployments
- When simplicity is prioritized over HA

---

## Option 3: Active-Active (Recommended) ⭐

```
        ┌──────────────────────────────────────┐
        │         DNS Round-Robin / VIP         │
        │       gateway.example.com             │
        └─────────────────┬────────────────────┘
                          │
         ┌────────────────┼────────────────┐
         ▼                ▼                ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │ Ctrl A   │◄──▶│ Ctrl B   │◄──▶│ Ctrl C   │
    │  (SGX)   │sync│  (SGX)   │sync│  (SGX)   │
    └────┬─────┘    └────┬─────┘    └────┬─────┘
         │               │               │
         └───────────────┼───────────────┘
                         ▼
                    ┌──────────┐
                    │   CVM    │
                    └──────────┘
```

### Strengths
- **No SPOF**: Any controller can handle requests
- **Horizontal scalability**: Add controllers to increase capacity
- **Automatic failover**: Dead controller removed from DNS/VIP
- **Load distribution**: Requests spread across controllers

### Weaknesses
- **Sync complexity**: Hash-chain entries must be synchronized
- **Conflict potential**: Concurrent appends need resolution
- **Network overhead**: Peer-to-peer sync traffic

### Key Mechanisms

**1. Client Routing (DNS Round-Robin)**
```
gateway.example.com → 
    10.0.0.1   (Ctrl A)
    10.0.0.2   (Ctrl B)
    10.0.0.3   (Ctrl C)
```

**2. Hash-Chain Sync (Broadcast on Append)**
```python
def append_entry(entry):
    # Append locally
    self.log.append(entry)
    # Broadcast to peers
    for peer in self.peers:
        peer.apply_entry(entry)
```

**3. Conflict Resolution (Deterministic Tiebreaker)**
```python
def resolve_conflict(entry_a, entry_b):
    # Same seq, different controllers: lower ID wins
    return entry_a if entry_a.controller_id < entry_b.controller_id else entry_b
```

### When to Use
- Production systems requiring HA
- Systems needing to scale with load
- When controller failure must not cause downtime

---

## Option 4: BFT Consensus (Byzantine Fault Tolerant)

```
                    ┌─────────────────┐
   ASP/Users ──────▶│   Any Ctrl      │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  BFT Consensus  │
                    │  (2f+1 agree)   │
                    └────────┬────────┘
                             │
    ┌────────────────────────┼────────────────────────┐
    ▼                        ▼                        ▼
[Ctrl A]                [Ctrl B]                [Ctrl C]
    │                        │                        │
    └────────────────────────┼────────────────────────┘
                             ▼
                           CVM
```

### Strengths
- **Byzantine tolerance**: Handles malicious controllers (f out of 3f+1)
- **Strong consistency**: Consensus before execution
- **Tamper-proof**: No single controller can corrupt log

### Weaknesses
- **Complexity**: Requires PBFT or similar protocol
- **Latency**: Consensus round before each command
- **Scalability limited**: O(n²) message complexity
- **Overkill**: If you trust your own SGX enclaves

### When to Use
- Multi-party deployments (different organizations)
- When controllers might be compromised
- Regulatory/compliance requirements for consensus

---

## Recommended Architecture: Active-Active

For your goals (no SPOF + scalability), **Active-Active** is the best balance:

| Requirement | How Active-Active Addresses It |
|-------------|-------------------------------|
| No SPOF | Any controller can serve, others take over |
| Scalability | Add more controllers = more capacity |
| Consistency | Hash-chain sync ensures same view |
| Simplicity | Simpler than BFT, more robust than Primary |

---

## Implementation Roadmap

### Phase 1: Multi-Instance (Current Code)
- Run multiple controller instances on different ports
- Each maintains its own hash-chain

### Phase 2: Peer Discovery
```python
PEERS = [
    ("ctrl-a", "10.0.0.1", 8445),
    ("ctrl-b", "10.0.0.2", 8446),
    ("ctrl-c", "10.0.0.3", 8447),
]
```

### Phase 3: Entry Broadcast
- On append, broadcast to all peers
- Peers apply or request missing entries

### Phase 4: Client Routing
- DNS round-robin or VIP (keepalived)
- Health checks remove dead controllers

### Phase 5: Controller Onboarding
- New controller must be attested by existing controllers
- Majority approval required to join
