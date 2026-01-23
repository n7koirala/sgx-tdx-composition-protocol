# Hash-Chained Transition Log

## Overview

The hash-chained transition log provides a tamper-evident, append-only record of all runtime updates made to Confidential VMs (CVMs). Each entry in the log includes the cryptographic hash of the previous entry, creating an unbreakable chain that can be verified and synchronized across multiple SGX controllers.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Hash-Chained Log Structure                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐          │
│  │ Entry 0         │    │ Entry 1         │    │ Entry 2         │          │
│  │ seq: 0          │    │ seq: 1          │    │ seq: 2          │          │
│  │ prev: 0x000...  │───▶│ prev: 0xAAA...  │───▶│ prev: 0xBBB...  │───▶ ...  │
│  │ cmd: apt update │    │ cmd: pip install│    │ cmd: restart    │          │
│  │ asp: security   │    │ asp: ml-team    │    │ asp: security   │          │
│  │ hash: 0xAAA...  │    │ hash: 0xBBB...  │    │ hash: 0xCCC...  │          │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘          │
│                                                                              │
│  Properties:                                                                 │
│  • Each entry's hash depends on ALL previous entries (via prev_hash)        │
│  • Modifying any entry breaks the chain                                      │
│  • Head hash (latest entry_hash) summarizes entire history                  │
│  • Controllers sync by comparing head hashes                                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Structure

### TransitionEntry

Each entry in the log contains:

| Field | Type | Description |
|-------|------|-------------|
| `seq` | int | Monotonic sequence number (0-indexed) |
| `prev_hash` | str | SHA-256 hash of previous entry (64 zeros for genesis) |
| `cvm_id` | str | Target CVM identifier |
| `command` | str | Command that was executed |
| `command_hash` | str | SHA-256 hash of command |
| `asp_id` | str | ASP who authorized this command |
| `asp_signature` | str | ASP's cryptographic signature |
| `controller_id` | str | Which SGX controller executed this |
| `timestamp` | float | Unix timestamp of execution |
| `result_success` | bool | Whether command succeeded |
| `result_exit_code` | int | Exit code from command |
| `result_rtmr` | str | TDX RTMR after execution (optional) |
| `entry_hash` | str | SHA-256 hash of this entry |

### Hash Computation

```python
entry_hash = SHA256({
    seq, prev_hash, cvm_id, command, command_hash,
    asp_id, asp_signature, controller_id, timestamp,
    result_success, result_exit_code, result_rtmr
})
```

## Multi-Controller Synchronization

### Sync Protocol

```
Controller A                          Controller B
     │                                      │
     │──── "My state: hash=0xCCC, seq=3" ──▶│
     │                                      │
     │◀─── "My state: hash=0xBBB, seq=2" ───│
     │                                      │
     │──── "Here's entry 3: {...}" ────────▶│
     │                                      │
     │◀─── "Applied, now at 0xCCC, seq=3" ──│
     │                                      │
```

### Conflict Resolution

With single-ASP-per-CVM model, conflicts are rare. If they occur:
1. Primary controller for CVM gets priority
2. Secondary controllers retry with updated prev_hash

## API Reference

### HashChainedLog

```python
# Create log for a CVM
log = HashChainedLog(cvm_id="192.168.1.10", storage_dir="/app/logs/transitions", 
                     controller_id="sgx-ctrl-1")

# Append a new entry
entry = log.append(
    command="apt-get update",
    asp_id="security-team",
    asp_signature="base64signature...",
    result_success=True,
    result_exit_code=0
)

# Get sync state for comparison
state = log.get_sync_state()
# {"cvm_id": "192.168.1.10", "head_hash": "abc123...", "seq": 5}

# Get entries for syncing
entries = log.get_entries_since(seq=3)

# Verify entire chain
valid, failed_at, msg = log.verify_chain()
```

### TransitionLogManager

```python
# Manages logs for multiple CVMs
manager = TransitionLogManager(storage_dir="/app/logs/transitions",
                               controller_id="sgx-ctrl-1")

# Record a transition (creates log if needed)
entry = manager.record_transition(
    cvm_id="192.168.1.10",
    command="echo hello",
    asp_id="my-asp",
    asp_signature="sig...",
    result_success=True,
    result_exit_code=0
)

# Get stats across all CVMs
stats = manager.get_stats()
# {"total_cvms": 3, "total_transitions": 42, "cvms": {...}}
```

## Storage Format

Logs are stored as JSON Lines (`.jsonl`) files:

```
/app/logs/transitions/
├── transition_log_192_168_1_10.jsonl
├── transition_log_192_168_1_11.jsonl
└── transition_log_192_168_1_12.jsonl
```

Each line is a JSON object representing one TransitionEntry:

```json
{"seq": 0, "prev_hash": "00000...", "cvm_id": "192.168.1.10", "command": "apt update", ...}
{"seq": 1, "prev_hash": "abc123...", "cvm_id": "192.168.1.10", "command": "pip install", ...}
```

## Security Properties

| Property | Guarantee |
|----------|-----------|
| **Tamper-evident** | Modifying any entry changes its hash, breaking the chain |
| **Append-only** | New entries must link to previous via prev_hash |
| **Non-repudiation** | ASP signature proves who authorized each command |
| **Ordering** | Sequence numbers + hash chain prevent reordering |
| **Detectability** | Chain verification detects any tampering |

## Integration with Gateway

The transition log is automatically updated when commands are executed:

```python
# In gateway_server.py _handle_execute_command():
transition_entry = self.transition_log_manager.record_transition(
    cvm_id=cmd.target_vm,
    command=cmd.command,
    asp_id=cmd.asp_id,
    asp_signature=cmd.signature,
    result_success=result.success,
    result_exit_code=result.exit_code
)
```
