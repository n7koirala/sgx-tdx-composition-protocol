# End-to-End Protocol Flow

This document describes the complete flow of a runtime update command from ASP to TDX VM execution.

## Components

| Component | Location | Purpose |
|-----------|----------|---------|
| **ASP Client** | `asp-client/` | Signs and sends commands |
| **SGX Gateway** | `sgx-gateway/` | Verifies, logs, and forwards commands |
| **TDX Server** | `tdx-server/` | Executes commands on CVM |

## Protocol Sequence

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────┐
│ ASP Client  │     │  SGX Gateway    │     │  TDX Server │
│             │     │  (Controller)   │     │   (CVM)     │
└──────┬──────┘     └────────┬────────┘     └──────┬──────┘
       │                     │                      │
       │  1. SignedCommand   │                      │
       │  (mTLS, port 8445)  │                      │
       │────────────────────▶│                      │
       │                     │                      │
       │                     │ 2. Verify signature  │
       │                     │    against ASP       │
       │                     │    registry          │
       │                     │                      │
       │                     │ 3. Check ASP         │
       │                     │    authorization     │
       │                     │    for target VM     │
       │                     │                      │
       │                     │ 4. Log to audit log  │
       │                     │    and transition    │
       │                     │    log (hash-chain)  │
       │                     │                      │
       │                     │  5. CommandRequest   │
       │                     │  (TLS, port 8446)    │
       │                     │─────────────────────▶│
       │                     │                      │
       │                     │                      │ 6. Execute
       │                     │                      │    command
       │                     │                      │    locally
       │                     │                      │
       │                     │                      │ 7. Log
       │                     │                      │    execution
       │                     │                      │
       │                     │  8. CommandResponse  │
       │                     │◀─────────────────────│
       │                     │                      │
       │  9. GatewayResponse │                      │
       │◀────────────────────│                      │
       │                     │                      │
```

## Step-by-Step Details

### 1. ASP Client Signs and Sends Command

```python
# asp_client.py
cmd = SignedCommand(
    asp_id="my-asp",
    target_vm="146.148.46.72",
    command="apt-get update",
    timestamp=time.time(),
    nonce=generate_nonce(),
    signature=sign(private_key, signable_data)
)
# Send via mTLS to SGX Gateway
```

### 2-3. SGX Gateway Verifies Command

```python
# gateway_server.py
def verify_command(cmd):
    # Check ASP is registered
    asp = self.asp_registry[cmd.asp_id]
    
    # Check ASP can access target VM
    if cmd.target_vm not in asp.allowed_vms:
        return False, "Not authorized"
    
    # Verify signature
    verify_signature(asp.public_key_pem, signable_data, cmd.signature)
    
    # Check replay (nonce)
    if cmd.nonce in self.used_nonces:
        return False, "Replay detected"
```

### 4. SGX Gateway Logs Command

```python
# Audit log (traditional)
audit_logger.log_command(asp_id, target_vm, command, result)

# Transition log (hash-chained for multi-controller)
transition_log.record_transition(
    cvm_id=target_vm,
    command=command,
    asp_id=asp_id,
    asp_signature=signature,
    result_success=result.success,
    result_exit_code=result.exit_code
)
```

### 5. SGX Gateway Sends to TDX Server

```python
# tdx_executor.py
request = CommandRequest(
    command=command,
    asp_id=asp_id,
    controller_id="sgx-controller-1",
    request_id=uuid4(),
    timestamp=time.time()
)
# Send via TLS to TDX Server on port 8446
```

### 6-7. TDX Server Executes and Logs

```python
# tdx_server.py
def execute_command(command):
    result = subprocess.run(command, shell=True, capture_output=True)
    log_execution(request, response)
    return response
```

### 8-9. Response Propagates Back

```
TDX Server → CommandResponse → SGX Gateway → GatewayResponse → ASP Client
```

## Running the Full Protocol

### Terminal 1: TDX Server (on TDX VM)

```bash
cd tdx-server
python3 tdx_server.py --cert tdx_server.crt --key tdx_server.key
```

### Terminal 2: SGX Gateway (on SGX machine)

```bash
cd sgx-gateway
make clean && make all
make run-sgx
```

### Terminal 3: ASP Client (any machine)

```bash
cd asp-client
python3 asp_client.py execute \
    --asp-id my-asp \
    --private-key ../keys/my-asp_private.pem \
    --gateway <SGX_GATEWAY_IP> \
    --target-vm <TDX_VM_IP> \
    --command "echo hello" \
    --ca-cert ../certs/ca.crt \
    --client-cert ../certs/asp_client.crt \
    --client-key ../certs/asp_client.key
```

## Logs Generated

| Location | Content |
|----------|---------|
| SGX: `logs/audit_log.jsonl` | All commands with enclave signature |
| SGX: `logs/transitions/*.jsonl` | Hash-chained transition log per CVM |
| TDX: `logs/tdx_execution_log.jsonl` | Local execution history |

## Security Properties

| Property | Implementation |
|----------|---------------|
| **ASP Authentication** | RSA signature verification |
| **Authorization** | ASP registry with allowed_vms |
| **Replay Protection** | Cryptographic nonces |
| **Tamper-Evident Logging** | Hash-chained transition log |
| **Encrypted Transport** | TLS 1.2+ (mTLS optional) |
| **Audit Trail** | Signed audit logs |
