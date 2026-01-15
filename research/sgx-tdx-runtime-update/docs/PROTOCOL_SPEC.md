# Protocol Specification

## Message Formats

### 1. SignedCommand

Command payload created and signed by an ASP.

```json
{
  "asp_id": "string",           // ASP identifier (matches registry)
  "target_vm": "string",        // Target TDX VM IP/hostname
  "command": "string",          // Shell command to execute
  "timestamp": 1705356000.123,  // Unix timestamp (seconds)
  "nonce": "base64-string",     // 32-byte random nonce
  "signature": "base64-string"  // Signature of above fields
}
```

**Signature Computation:**
```python
signable_data = json.dumps({
    "asp_id": asp_id,
    "target_vm": target_vm,
    "command": command,
    "timestamp": timestamp,
    "nonce": nonce
}, sort_keys=True).encode('utf-8')

signature = sign(signable_data, ASP_PRIVATE_KEY)
```

### 2. CommandResult

Result of command execution on TDX VM.

```json
{
  "success": true,
  "exit_code": 0,
  "stdout": "command output...",
  "stderr": "",
  "execution_time_ms": 1234.5,
  "timestamp": 1705356001.456
}
```

### 3. AuditLogEntry

Audit log entry stored in sealed enclave storage.

```json
{
  "log_id": "log-20260115221234-abc12345",
  "asp_id": "company-a",
  "target_vm": "146.148.46.72",
  "command": "apt-get update",
  "command_timestamp": 1705356000.123,
  "execution_timestamp": 1705356001.456,
  "result": { /* CommandResult */ },
  "enclave_signature": "base64-string"
}
```

### 4. GatewayRequest

Request wrapper for gateway communication.

```json
{
  "request_type": "execute_command | get_logs | get_stats",
  "payload": "JSON string of inner payload"
}
```

### 5. GatewayResponse

Response from the gateway.

```json
{
  "success": true,
  "message": "Command executed",
  "data": "JSON string of result data"
}
```

## Communication Protocol

### TLS Configuration

- **Protocol**: TLS 1.2+
- **Authentication**: Mutual TLS (mTLS)
- **Server Certificate**: Gateway presents `server.crt`
- **Client Certificate**: ASP client presents `asp_client.crt`
- **CA Verification**: Both sides verify against `ca.crt`

### Message Framing

Messages are framed with a delimiter for TCP stream processing:

```
<message_bytes>\n---END---\n
```

### Command Execution Flow

```
ASP Client                          SGX Gateway                      TDX VM
    │                                    │                              │
    │  1. TLS ClientHello               │                              │
    │ ──────────────────────────────────>│                              │
    │                                    │                              │
    │  2. TLS Handshake (mTLS)          │                              │
    │ <──────────────────────────────────>                              │
    │                                    │                              │
    │  3. GatewayRequest                │                              │
    │     (execute_command + SignedCmd)  │                              │
    │ ──────────────────────────────────>│                              │
    │                                    │                              │
    │                                    │  4. Verify signature         │
    │                                    │     Check policy             │
    │                                    │                              │
    │                                    │  5. SSH connect              │
    │                                    │ ─────────────────────────────>│
    │                                    │                              │
    │                                    │  6. Execute command          │
    │                                    │ ─────────────────────────────>│
    │                                    │                              │
    │                                    │  7. Return stdout/stderr     │
    │                                    │ <─────────────────────────────│
    │                                    │                              │
    │                                    │  8. Log with signature       │
    │                                    │     (sealed storage)         │
    │                                    │                              │
    │  9. GatewayResponse               │                              │
    │     (CommandResult)                │                              │
    │ <──────────────────────────────────│                              │
    │                                    │                              │
```

## Validation Rules

### Command Validation

| Check | Rule | Error |
|-------|------|-------|
| Timestamp freshness | `now - timestamp < 300s` | "Command expired" |
| Future timestamp | `timestamp - now < 60s` | "Command in future" |
| Nonce uniqueness | Not in used_nonces set | "Replay attack detected" |
| ASP registered | `asp_id in asp_registry` | "Unknown ASP" |
| VM authorized | `target_vm in asp.allowed_vms` | "Not authorized for VM" |
| Signature valid | Verify with ASP public key | "Invalid signature" |

### Nonce Management

- Nonces are stored in memory for replay protection
- Maximum cache size: 10,000 nonces
- When cache full, oldest 5,000 are evicted
- Production should use TTL-based expiration

## Cryptographic Details

### Supported Key Types

| Type | Algorithm | Size |
|------|-----------|------|
| RSA | RSA-PKCS1v15-SHA256 | 2048/4096 bits |
| ECDSA | ECDSA-SHA256 | P-256 curve |

### Signature Format

- Signatures are computed over sorted JSON of signable fields
- Encoded as Base64 for transmission
- Hash algorithm: SHA-256

### Sealed Storage

- Uses SGX sealing with `_sgx_mrenclave` key
- Audit logs encrypted with enclave-specific key
- Only same enclave (same MRENCLAVE) can read
