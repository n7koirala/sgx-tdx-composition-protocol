# SGX-TDX Runtime Update System

Secure command execution on TDX VMs through an SGX enclave gateway with ASP authentication and audit logging.

## Architecture

```
[ASP] --signed command--> [SGX Gateway] --SSH--> [TDX VM]
                               |
                         [Audit Logs]
                         (signed & sealed)
```

## Components

| Component | Description |
|-----------|-------------|
| `sgx-gateway/` | SGX enclave server that verifies and executes commands |
| `asp-client/` | Tool for ASPs to sign and send commands |
| `common/` | Shared protocol and crypto utilities |
| `config/` | ASP registry (public keys → allowed VMs) |
| `certs/` | TLS certificates and keys |

## Quick Start

### 1. Generate certificates and keys

```bash
cd certs
chmod +x generate_certs.sh
./generate_certs.sh <GATEWAY_IP>

cd ../sgx-gateway
make gen-keys
```

### 2. Configure ASP registry

Edit `config/asp_registry.json` with actual ASP public keys:
```json
{
  "asp_registry": [
    {
      "asp_id": "my-asp",
      "name": "My Company",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
      "allowed_vms": ["146.148.46.72"]
    }
  ]
}
```

### 3. Add SSH key to TDX VM

```bash
cat certs/enclave_ssh_key.pub
# Add this to TDX VM's ~/.ssh/authorized_keys
```

### 4. Start the SGX Gateway

```bash
cd sgx-gateway
make all
make run-sgx
```

### 5. Generate ASP keys and execute command

```bash
cd asp-client

# Generate key pair
python3 asp_client.py generate-keys --asp-id my-asp --output-dir ../keys

# Execute a command
python3 asp_client.py execute \
    --asp-id my-asp \
    --private-key ../keys/my-asp_private.pem \
    --gateway <GATEWAY_IP> \
    --target-vm 146.148.46.72 \
    --command "echo hello" \
    --ca-cert ../certs/ca.crt \
    --client-cert ../certs/asp_client.crt \
    --client-key ../certs/asp_client.key
```

## Security Properties

1. **ASP Authentication**: Commands are signed with ASP private keys
2. **Command Verification**: Gateway verifies signatures against registered public keys
3. **Policy Enforcement**: ASPs can only access their allowed VMs
4. **Replay Protection**: Nonces prevent command replay
5. **Audit Logging**: All commands are logged with enclave signatures
6. **Sealed Storage**: Logs are encrypted with SGX sealing keys

## Audit Log Verification

End users can verify that commands were legitimately executed:

```bash
# Get logs from gateway
python3 asp_client.py get-logs --gateway <GATEWAY_IP>

# Each log entry contains:
# - Command details
# - Execution result
# - Enclave signature (verifiable with enclave's public key)
```
