# Deployment Guide

## Prerequisites

### SGX Machine (Gateway)

- Intel SGX-enabled CPU
- Ubuntu 20.04/22.04
- Gramine 1.9+
- Python 3.8+
- DCAP driver installed
- AESM service running

### TDX VM

- Intel TDX-enabled VM
- SSH server running
- Python 3.8+ (for any local scripts)

### ASP Workstation

- Python 3.8+
- `cryptography` library (`pip install cryptography`)
- Network access to SGX gateway

---

## Step 1: Generate Certificates and Keys

### On SGX Machine

```bash
cd /path/to/sgx-tdx-runtime-update

# Generate TLS certificates
cd certs
./generate_certs.sh <GATEWAY_IP>

# Generate enclave keys
cd ../sgx-gateway
make gen-keys
```

This creates:
- `certs/ca.crt` - Certificate authority
- `certs/server.crt/key` - Gateway TLS certificate
- `certs/asp_client.crt/key` - ASP client certificate (mTLS)
- `certs/enclave_ssh_key` - SSH key for TDX access
- `certs/enclave_signing_key.pem` - Key for signing audit logs

---

## Step 2: Configure TDX VM SSH Access

### On TDX VM

```bash
# Add enclave's public key to authorized_keys
cat >> ~/.ssh/authorized_keys << 'EOF'
<paste contents of enclave_ssh_key.pub>
EOF

# Verify SSH works from gateway
ssh -i /path/to/enclave_ssh_key user@<TDX_IP> "echo test"
```

### (Optional) Restrict SSH to Gateway IP

```bash
# On TDX VM - edit sshd_config
sudo vim /etc/ssh/sshd_config
# Add: AllowUsers nkoirala@<GATEWAY_IP>
sudo systemctl restart sshd
```

Or use cloud firewall:
```bash
gcloud compute firewall-rules update allow-ssh \
    --source-ranges=<GATEWAY_IP>/32
```

---

## Step 3: Register ASPs

### Generate ASP Keys

On ASP's workstation:
```bash
cd asp-client
python3 asp_client.py generate-keys \
    --asp-id company-a \
    --output-dir ./keys
```

This creates:
- `keys/company-a_private.pem` - Keep secure!
- `keys/company-a_public.pem` - Send to gateway admin

### Add to Registry

On SGX gateway, edit `config/asp_registry.json`:
```json
{
  "asp_registry": [
    {
      "asp_id": "company-a",
      "name": "Company A Inc.",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIBI...\n-----END PUBLIC KEY-----",
      "allowed_vms": ["146.148.46.72"]
    }
  ]
}
```

> **Important**: After modifying the registry, rebuild the enclave (`make clean && make all`) since it's a trusted file.

---

## Step 4: Build and Start Gateway

### On SGX Machine

```bash
cd sgx-gateway

# Check setup
make check-setup

# Build enclave
make all

# View enclave measurements
make view-sig
# Record MRENCLAVE for verification

# Start gateway
make run-sgx
```

Expected output:
```
======================================================================
SGX Gateway Server - Secure Runtime Update System
======================================================================
Protocol Version: 1.0
Port:             8445
ASPs Registered:  1
mTLS:             Enabled
======================================================================

[SECURE] Waiting for signed commands from ASPs...
```

---

## Step 5: Execute Commands (ASP Side)

### On ASP Workstation

```bash
cd asp-client

# Execute a command
python3 asp_client.py execute \
    --asp-id company-a \
    --private-key ./keys/company-a_private.pem \
    --gateway <GATEWAY_IP> \
    --port 8445 \
    --target-vm 146.148.46.72 \
    --command "apt-get update" \
    --ca-cert ../certs/ca.crt \
    --client-cert ../certs/asp_client.crt \
    --client-key ../certs/asp_client.key
```

### Expected Output

```
Executing command on 146.148.46.72...
  Command: apt-get update
  Nonce: abc123...
  Signed: ✓

Sending to gateway 10.0.0.1:8445...

============================================================
✓ Command executed successfully
  Exit code: 0
  Execution time: 2345.6ms

STDOUT:
Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease
...
```

---

## Step 6: Retrieve Audit Logs

### On ASP Workstation

```bash
python3 asp_client.py get-logs \
    --gateway <GATEWAY_IP> \
    --port 8445 \
    --ca-cert ../certs/ca.crt \
    --client-cert ../certs/asp_client.crt \
    --client-key ../certs/asp_client.key
```

### Verify Log Signatures

```python
from common.crypto import verify_signature

# Load enclave public key
with open('enclave_signing_key_pub.pem') as f:
    enclave_pub_key = f.read()

# For each log entry
is_valid, error = verify_signature(
    enclave_pub_key,
    log_entry.get_signable_data(),
    log_entry.enclave_signature
)
print(f"Log {log_entry.log_id}: {'Valid' if is_valid else 'INVALID'}")
```

---

## Production Considerations

### 1. Disable Debug Mode

Edit `gateway.manifest.template`:
```toml
sgx.debug = false
```

Rebuild enclave.

### 2. Secure Key Storage

- Store `enclave_ssh_key` in sealed storage
- Never expose `enclave_signing_key.pem` outside enclave
- Use HSM for CA key if possible

### 3. Network Security

```bash
# Allow only ASP IPs to gateway port
gcloud compute firewall-rules create allow-gateway \
    --allow tcp:8445 \
    --source-ranges=<ASP_IP_RANGE> \
    --target-tags=sgx-gateway
```

### 4. Logging and Monitoring

- Forward enclave logs to SIEM
- Alert on authentication failures
- Monitor command execution patterns

### 5. Backup

- Regularly export sealed audit logs
- Backup ASP registry (version control)
- Document MRENCLAVE for each release

---

## Troubleshooting

### "Unknown CA" Error

Certificates not matching. Regenerate all certs from same CA:
```bash
cd certs
rm -f *.crt *.key
./generate_certs.sh <GATEWAY_IP>
```

### "SSH Connection Failed"

1. Verify SSH key is in TDX `authorized_keys`
2. Check firewall allows SSH from gateway
3. Verify username in `command_executor.py`

### "Signature Verification Failed"

1. Ensure ASP registry has correct public key (no extra whitespace)
2. Verify ASP is using matching private key
3. Check timestamp is not expired

### "ASP Not Authorized for VM"

Edit `asp_registry.json` and add VM IP to `allowed_vms`.
Rebuild enclave after changes.
