# Hash-Chain Synchronization in Multi-Controller Setup

## Problem

With multiple controllers, each can append to the hash-chain. How do we keep them synchronized?

---

## Single-ASP-per-CVM Simplification

Your architecture has **one ASP per CVM**, meaning:
- Commands for a CVM come sequentially (from ASP's perspective)
- No concurrent conflicting commands for same CVM
- Sync is simpler than general distributed log

---

## Sync Protocol

### On Append (Broadcast)

```
Controller A appends entry:

    ┌──────────┐                   ┌──────────┐
    │  Ctrl A  │                   │  Ctrl B  │
    │          │                   │          │
    │ append() │                   │          │
    │   seq=5  │                   │  seq=4   │
    │          │                   │          │
    │          │──── broadcast ───▶│ apply()  │
    │          │     {entry}       │  seq=5   │
    │          │                   │          │
    │          │◀─── ACK ──────────│          │
    └──────────┘                   └──────────┘
```

### On Startup (Catch-Up)

```
Controller C restarts:

1. C checks local head: seq=3, hash=0xAAA
2. C queries peers for their heads
3. Peer A responds: seq=7, hash=0xGGG
4. C requests entries 4, 5, 6, 7 from A
5. C applies entries, now synced
```

### On Conflict (Rare)

If two controllers append with same seq:

```
Ctrl A appends: seq=5, controller=A, hash=0xAAA
Ctrl B appends: seq=5, controller=B, hash=0xBBB

Conflict! Same seq, different entries.

Resolution (deterministic tiebreaker):
- Lower controller_id wins
- If A < B: A's entry is canonical
- B rolls back and applies A's entry
```

---

## Implementation

### TransitionLogManager with Sync

```python
class SyncableTransitionLog(HashChainedLog):
    def __init__(self, cvm_id, storage_dir, controller_id, peers):
        super().__init__(cvm_id, storage_dir, controller_id)
        self.peers = peers
    
    def append(self, entry) -> TransitionEntry:
        # Append locally
        result = super().append(entry)
        
        # Broadcast to peers
        for peer in self.peers:
            try:
                peer.apply_entry(result)
            except:
                pass  # Will catch up later
        
        return result
    
    def sync_from_peers(self):
        # Find peer with longest chain
        best_peer = None
        best_seq = len(self.entries)
        
        for peer in self.peers:
            state = peer.get_sync_state()
            if state['seq'] > best_seq:
                best_peer = peer
                best_seq = state['seq']
        
        if best_peer:
            # Get missing entries
            missing = best_peer.get_entries_since(len(self.entries))
            for entry in missing:
                self.apply_entry(entry)
```

---

## Consistency Guarantees

| Guarantee | Provided? | Notes |
|-----------|-----------|-------|
| **Eventual consistency** | ✅ Yes | All controllers converge |
| **Total order** | ✅ Yes | Sequence numbers + tiebreaker |
| **Durability** | ✅ Yes | Persisted to disk |
| **Availability** | ✅ Yes | Any controller can serve |

---

## Edge Cases

### Network Partition

```
A ←──X──→ B, C     (A isolated)

- A continues to serve clients, append locally
- B, C serve clients, append to their synced log
- When partition heals:
  - Higher seq wins, or
  - Conflict resolution by controller_id
```

### Stale Read

```
Client reads from A (seq=5)
B just appended seq=6

Client sees stale data (seq=5)

Mitigation: Read from multiple controllers, take highest seq
```

### Out-of-Order Receipt

```
A sends seq=5 to B
A sends seq=6 to B (arrives first due to network)

B receives seq=6 first, can't apply (missing seq=5)
B buffers seq=6, requests seq=5 from A
B applies seq=5, then seq=6
```
