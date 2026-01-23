# Command Execution Modes: TDX Server vs SSH

The SGX Gateway supports two methods for executing commands on TDX VMs.

## Execution Flow

```
ASP Command → SGX Gateway → TDX VM

                           ┌─────────────────────────┐
                           │ Try TDX Server (8446)   │
                           └───────────┬─────────────┘
                                       │
                                       ▼
                              ┌────────────────┐
                              │  Connected?    │
                              └───────┬────────┘
                                  ┌───┴───┐
                                  │       │
                              YES ▼       ▼ NO
                           ┌─────────┐  ┌──────────────┐
                           │ Execute │  │ Fallback SSH │
                           │ via TDX │  │ (port 22)    │
                           └─────────┘  └──────────────┘
```

## Comparison

| Aspect | TDX Server | SSH |
|--------|------------|-----|
| **Port** | 8446 | 22 |
| **Requires** | TDX server running | SSH daemon + key auth |
| **Connection** | TLS | SSH |
| **Logging** | Local + remote | Remote only |
| **Latency** | Lower (custom protocol) | Higher (SSH overhead) |
| **Complexity** | Needs server process | Built-in to OS |

## Option 1: TDX Server (Recommended for Production)

### Pros
- Custom protocol designed for this use case
- Local logging on TDX before execution (audit trail)
- Finer control over what commands can run
- Can add command allowlists, rate limiting
- Faster response (no SSH handshake overhead)

### Cons
- Requires running an additional service on TDX
- Need to manage TDX server lifecycle
- Additional certificates to manage

### Setup
```bash
# On TDX VM
cd tdx-server
./generate_certs.sh
python3 tdx_server.py --cert tdx_server.crt --key tdx_server.key
```

## Option 2: SSH (Simpler, Works Out-of-Box)

### Pros
- No additional software needed
- SSH is already configured and tested
- Standard, well-understood protocol
- Works through firewalls that allow SSH

### Cons
- No local logging on TDX side
- Less control over execution environment
- SSH connection overhead per command
- Harder to add command restrictions

### Setup
```bash
# Ensure SSH key is authorized on TDX VM
cat enclave_ssh_key.pub >> ~/.ssh/authorized_keys
```

## Current Behavior

The gateway:
1. First attempts TDX server connection (30s timeout)
2. If TDX server unavailable, falls back to SSH
3. Logs the execution method used

### Verbose Output Example

```
[1] Connection from 129.74.154.215:55056
  ✓ Command verified for ASP my-asp
    Target: 146.148.46.72
    Command: echo hello...
    Attempting TDX server connection to 146.148.46.72:8446...
    TDX server unavailable: Connection refused...
    Falling back to SSH...
    [SSH] Connecting to 146.148.46.72 as nkoirala...
    [SSH] Connected! Executing command...
    [SSH] Command completed (exit_code=0, 234.5ms)
    [SSH] stdout: hello
  ✓ Executed (exit_code=0)
```

## Recommendation

| Scenario | Use |
|----------|-----|
| **Development/Testing** | SSH (simpler) |
| **Production** | TDX Server (more control) |
| **Mixed environment** | Both (fallback works automatically) |
