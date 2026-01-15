# API Reference

## Gateway Server API

The SGX Gateway exposes a TLS/mTLS endpoint for receiving commands.

### Endpoint

```
Host: <GATEWAY_IP>
Port: 8445 (default)
Protocol: TLS 1.2+ with mutual authentication
```

### Request Types

#### 1. Execute Command

Execute a signed command on a TDX VM.

**Request:**
```json
{
  "request_type": "execute_command",
  "payload": "<SignedCommand JSON>"
}
```

**SignedCommand Payload:**
```json
{
  "asp_id": "company-a",
  "target_vm": "146.148.46.72",
  "command": "apt-get update",
  "timestamp": 1705356000.123,
  "nonce": "base64-encoded-32-bytes",
  "signature": "base64-encoded-signature"
}
```

**Success Response:**
```json
{
  "success": true,
  "message": "Command executed",
  "data": "{\"success\": true, \"exit_code\": 0, \"stdout\": \"...\", \"stderr\": \"\", \"execution_time_ms\": 1234.5}"
}
```

**Error Response:**
```json
{
  "success": false,
  "message": "Command rejected: Invalid signature",
  "data": null
}
```

---

#### 2. Get Logs

Retrieve audit logs with optional filtering.

**Request:**
```json
{
  "request_type": "get_logs",
  "payload": "{\"target_vm\": \"146.148.46.72\"}"
}
```

**Filter Options:**
| Field | Type | Description |
|-------|------|-------------|
| `asp_id` | string | Filter by ASP identifier |
| `target_vm` | string | Filter by target VM |
| `start_time` | float | Filter logs after this timestamp |
| `end_time` | float | Filter logs before this timestamp |

**Response:**
```json
{
  "success": true,
  "message": "Retrieved 5 log entries",
  "data": "[{\"log_id\": \"...\", ...}, ...]"
}
```

---

#### 3. Get Stats

Get gateway statistics.

**Request:**
```json
{
  "request_type": "get_stats",
  "payload": ""
}
```

**Response:**
```json
{
  "success": true,
  "message": "Statistics retrieved",
  "data": "{\"requests\": 100, \"executed\": 95, \"rejected_auth\": 3, ...}"
}
```

---

## ASP Client CLI

### Commands

#### generate-keys

Generate a new ASP key pair.

```bash
python3 asp_client.py generate-keys \
    --asp-id <ASP_ID> \
    --key-type <rsa|ec> \
    --key-size <2048|4096> \
    --output-dir <DIR>
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--asp-id` | Yes | - | ASP identifier |
| `--key-type` | No | rsa | Key algorithm |
| `--key-size` | No | 2048 | Key size (RSA only) |
| `--output-dir` | No | . | Output directory |

**Output Files:**
- `<asp_id>_private.pem` - Private key (keep secure!)
- `<asp_id>_public.pem` - Public key (add to registry)

---

#### execute

Execute a command on a TDX VM.

```bash
python3 asp_client.py execute \
    --asp-id <ASP_ID> \
    --private-key <KEY_FILE> \
    --gateway <HOST> \
    --port <PORT> \
    --target-vm <VM_IP> \
    --command <COMMAND> \
    --ca-cert <CA_FILE> \
    --client-cert <CERT_FILE> \
    --client-key <KEY_FILE>
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--asp-id` | Yes | - | ASP identifier |
| `--private-key` | Yes | - | Path to ASP private key |
| `--gateway` | Yes | - | Gateway hostname/IP |
| `--port` | No | 8445 | Gateway port |
| `--target-vm` | Yes | - | Target TDX VM IP |
| `--command` | Yes | - | Shell command to execute |
| `--ca-cert` | No | - | CA certificate for TLS |
| `--client-cert` | No | - | Client certificate (mTLS) |
| `--client-key` | No | - | Client key (mTLS) |

---

#### get-logs

Retrieve audit logs from gateway.

```bash
python3 asp_client.py get-logs \
    --gateway <HOST> \
    --port <PORT> \
    --target-vm <VM_IP> \
    --ca-cert <CA_FILE> \
    --client-cert <CERT_FILE> \
    --client-key <KEY_FILE>
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--gateway` | Yes | - | Gateway hostname/IP |
| `--port` | No | 8445 | Gateway port |
| `--target-vm` | No | - | Filter by target VM |
| `--asp-id` | No | - | Filter by ASP (optional) |

---

## Python Library API

### common.protocol

#### SignedCommand

```python
from common.protocol import SignedCommand, generate_nonce

# Create command
cmd = SignedCommand(
    asp_id="company-a",
    target_vm="146.148.46.72",
    command="apt-get update",
    timestamp=time.time(),
    nonce=generate_nonce()
)

# Get data to sign
signable_data = cmd.get_signable_data()  # bytes

# Validate structure
is_valid, error = cmd.validate(max_age_seconds=300)

# Serialize
json_str = cmd.to_json()
cmd2 = SignedCommand.from_json(json_str)
```

#### CommandResult

```python
from common.protocol import CommandResult

result = CommandResult(
    success=True,
    exit_code=0,
    stdout="output...",
    stderr="",
    execution_time_ms=1234.5
)
```

#### AuditLogEntry

```python
from common.protocol import AuditLogEntry, generate_log_id

entry = AuditLogEntry(
    log_id=generate_log_id(),
    asp_id="company-a",
    target_vm="146.148.46.72",
    command="apt-get update",
    command_timestamp=1705356000.0,
    execution_timestamp=time.time(),
    result=result
)

# Get data to sign
signable_data = entry.get_signable_data()
```

---

### common.crypto

#### verify_signature

```python
from common.crypto import verify_signature

is_valid, error = verify_signature(
    public_key_pem="-----BEGIN PUBLIC KEY-----\n...",
    data=b"data that was signed",
    signature_b64="base64-encoded-signature"
)

if is_valid:
    print("Signature valid")
else:
    print(f"Invalid: {error}")
```

#### sign_data

```python
from common.crypto import sign_data

signature_b64, error = sign_data(
    private_key_pem="-----BEGIN PRIVATE KEY-----\n...",
    data=b"data to sign"
)

if error:
    print(f"Signing failed: {error}")
```

#### generate_key_pair

```python
from common.crypto import generate_key_pair

private_pem, public_pem, error = generate_key_pair(
    key_type="rsa",  # or "ec"
    key_size=2048
)
```

---

## Configuration Files

### asp_registry.json

```json
{
  "description": "ASP Registry",
  "version": "1.0",
  "asp_registry": [
    {
      "asp_id": "company-a",
      "name": "Company A Inc.",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIBI...\n-----END PUBLIC KEY-----",
      "allowed_vms": ["146.148.46.72", "10.0.0.5"]
    },
    {
      "asp_id": "company-b",
      "name": "Company B Ltd.",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIBI...\n-----END PUBLIC KEY-----",
      "allowed_vms": ["192.168.1.100"]
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `asp_id` | string | Unique ASP identifier |
| `name` | string | Human-readable name |
| `public_key_pem` | string | PEM-encoded public key |
| `allowed_vms` | string[] | List of authorized VM IPs |
