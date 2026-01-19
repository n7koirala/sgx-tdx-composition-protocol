# SGX-TDX Runtime Update System

Secure command execution on TDX VMs through an SGX enclave gateway with ASP authentication and audit logging.

## Architecture

```
┌─────────────┐    signed command    ┌─────────────────┐    SSH    ┌──────────┐
│  ASP Client │ ─────────────────────▶ │  SGX Gateway   │ ──────────▶ │  TDX VM  │
│  (signs)    │                       │  (verifies)    │           │ (executes)│
└─────────────┘                       └─────────────────┘           └──────────┘
                                              │
                                       ┌──────▼──────┐
                                       │  Audit Logs │
                                       │  (signed)   │
                                       └─────────────┘
```

## Components

| Component | Description |
|-----------|-------------|
| `sgx-gateway/` | SGX enclave server that verifies signatures and executes commands |
| `asp-client/` | CLI tool for ASPs to sign and send commands to the gateway |
| `common/` | Shared protocol definitions and cryptographic utilities |
| `config/` | ASP registry mapping public keys to allowed VMs |
| `certs/` | TLS certificates, SSH keys, and signing keys |
| `keys/` | ASP key pairs (private keys for signing) |
| `logs/` | Audit logs in JSONL format |

## Quick Start

### 1. Generate TLS certificates

```bash
cd certs
chmod +x generate_certs.sh
./generate_certs.sh <GATEWAY_IP>
```

### 2. Generate enclave keys

```bash
cd sgx-gateway
make gen-keys
```

This creates:
- `certs/enclave_ssh_key` - SSH key for accessing TDX VMs
- `certs/enclave_signing_key.pem` - Key for signing audit logs

### 3. Generate ASP keys

```bash
cd asp-client
python3 asp_client.py generate-keys --asp-id my-asp --output-dir ../keys
```

This creates `keys/my-asp_private.pem` and `keys/my-asp_public.pem`.

### 4. Configure ASP registry

Edit `config/asp_registry.json` with the ASP's public key. **Important**: The public key must use `\n` escape sequences for newlines in JSON:

```json
{
  "asp_registry": [
    {
      "asp_id": "my-asp",
      "name": "My Company",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----\n",
      "allowed_vms": ["146.148.46.72"]
    }
  ]
}
```

> **Tip**: Copy the exact content from `keys/my-asp_public.pem` and replace literal newlines with `\n`.

### 5. Add SSH key to TDX VM

```bash
cat certs/enclave_ssh_key.pub
# Add this to TDX VM's ~/.ssh/authorized_keys
```

### 6. Build and start the SGX Gateway

```bash
cd sgx-gateway
make clean && make all
make run-sgx
```

You should see:
```
[SECURE] Waiting for signed commands from ASPs...
```

### 7. Execute a command from ASP client

```bash
cd asp-client
python3 asp_client.py execute \
    --asp-id my-asp \
    --private-key ../keys/my-asp_private.pem \
    --gateway localhost \
    --target-vm 146.148.46.72 \
    --command "echo hello" \
    --ca-cert ../certs/ca.crt \
    --client-cert ../certs/asp_client.crt \
    --client-key ../certs/asp_client.key
```

## Security Properties

| Property | Description |
|----------|-------------|
| **ASP Authentication** | Commands are signed with ASP private keys |
| **Signature Verification** | Gateway verifies signatures against registered public keys |
| **Policy Enforcement** | ASPs can only access their allowed VMs |
| **Replay Protection** | Cryptographic nonces prevent command replay |
| **Audit Logging** | All commands are logged with enclave signatures |
| **mTLS** | Mutual TLS authentication between client and gateway |

## Troubleshooting

### "Waiting for signed commands" banner not appearing

The manifest needs `PYTHONUNBUFFERED=1` to flush output immediately. Check that `gateway.manifest.template` includes:
```toml
loader.env.PYTHONUNBUFFERED = "1"
```

Then rebuild: `make clean && make all`

### "Could not deserialize key data" error

The public key in `asp_registry.json` has incorrect formatting. Ensure:
1. The key uses `\n` for newlines (not literal newlines)
2. The key matches the content of the `.pem` file exactly

### "Invalid signature" error

The public key in the registry doesn't match the private key being used. Verify they match:
```bash
# Extract public key from private key and compare
openssl rsa -in keys/my-asp_private.pem -pubout 2>/dev/null | diff - keys/my-asp_public.pem
```

If they don't match, update `asp_registry.json` with the correct public key.

## Audit Log Format

Logs are stored in `logs/audit_log.jsonl` as JSON Lines:

```json
{
  "log_id": "log-20260119142214-d08b8907d4902802",
  "asp_id": "my-asp",
  "target_vm": "146.148.46.72",
  "command": "echo hello",
  "command_timestamp": 1768832533.43,
  "execution_timestamp": 1768832534.71,
  "result": {
    "success": true,
    "exit_code": 0,
    "stdout": "hello\n",
    "stderr": "",
    "execution_time_ms": 414.8
  },
  "enclave_signature": "Eo/m/6ZKB8mj..."
}
```

## Makefile Targets

```bash
cd sgx-gateway

make all        # Build and sign the enclave
make run-sgx    # Run in SGX mode
make run-direct # Run in Gramine direct mode (no SGX)
make run-python # Run as plain Python (for debugging)
make gen-keys   # Generate SSH and signing keys
make check-setup # Verify SGX and dependencies
make clean      # Clean build artifacts
```
