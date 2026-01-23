# TDX Runtime Update Server

Server component that runs on the TDX VM (Confidential VM) to receive and execute runtime update commands from SGX controllers.

## Overview

The TDX Runtime Server listens for commands from authorized SGX controllers via TLS-encrypted connections. When a command is received, it is executed locally, logged, and the result is returned to the controller.

## Architecture

```
┌─────────────────┐                    ┌─────────────────────┐
│   SGX Gateway   │                    │      TDX VM         │
│   (Controller)  │                    │                     │
│                 │   TLS (port 8446)  │  ┌───────────────┐  │
│  TDXExecutor    │ ──────────────────▶│  │  TDX Server   │  │
│                 │                    │  │               │  │
│                 │ ◀──────────────────│  │  - Execute    │  │
│                 │   CommandResponse  │  │  - Log        │  │
│                 │                    │  └───────────────┘  │
└─────────────────┘                    └─────────────────────┘
```

## Quick Start

### 1. Generate TLS certificates (on TDX VM)

```bash
cd tdx-server
chmod +x generate_certs.sh
./generate_certs.sh . <TDX_VM_IP>
```

Or use certificates from the shared CA:
```bash
# Copy CA cert from SGX gateway
scp sgx-machine:/path/to/certs/ca.crt .
```

### 2. Start the TDX Server

```bash
python3 tdx_server.py \
    --port 8446 \
    --cert tdx_server.crt \
    --key tdx_server.key \
    --ca-cert ca.crt \
    --log-dir ./logs
```

### 3. Verify connectivity (from SGX machine)

```bash
# The SGX gateway will automatically connect when processing commands
```

## Command Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--port` | 8446 | Port to listen on |
| `--cert` | (required) | TLS certificate file |
| `--key` | (required) | TLS private key file |
| `--ca-cert` | None | CA cert for client verification (mTLS) |
| `--log-dir` | ./logs | Directory for execution logs |

## Protocol

### Request Format (from SGX Controller)

```json
{
    "command": "apt-get update",
    "asp_id": "security-team",
    "controller_id": "sgx-controller-1",
    "request_id": "uuid-string",
    "timestamp": 1706012345.123
}
```

### Response Format (to SGX Controller)

```json
{
    "request_id": "uuid-string",
    "success": true,
    "exit_code": 0,
    "stdout": "...",
    "stderr": "",
    "execution_time_ms": 1234.5,
    "timestamp": 1706012346.456
}
```

## Logging

All command executions are logged to `logs/tdx_execution_log.jsonl`:

```json
{
    "request_id": "uuid-string",
    "command": "apt-get update",
    "asp_id": "security-team",
    "controller_id": "sgx-controller-1",
    "request_timestamp": 1706012345.123,
    "exit_code": 0,
    "success": true,
    "execution_time_ms": 1234.5,
    "response_timestamp": 1706012346.456
}
```

## Security

- **TLS encryption**: All communication is encrypted
- **mTLS (optional)**: Client certificate verification when CA cert is provided
- **Local logging**: All commands are logged before execution
- **Sandboxed execution**: Commands run with the TDX server's privileges

## Files

| File | Description |
|------|-------------|
| `tdx_server.py` | Main server implementation |
| `generate_certs.sh` | Certificate generation script |
| `logs/tdx_execution_log.jsonl` | Local execution log |
