# Security Analysis

## Threat Model

### Assets to Protect

1. **TDX VM Integrity**: Prevent unauthorized command execution
2. **ASP Confidentiality**: Protect private signing keys
3. **Audit Log Integrity**: Ensure logs cannot be tampered with
4. **Command Confidentiality**: Protect commands in transit

### Adversaries

| Adversary | Capabilities | Goals |
|-----------|-------------|-------|
| Malicious Cloud Admin | Root on hypervisor, network access | Execute commands, read data |
| Rogue ASP | Valid credentials for own VMs | Access other ASPs' VMs |
| Network Attacker | Intercept/modify network traffic | Inject commands, replay attacks |
| Malicious Insider | Access to some enclave components | Bypass verification |

## Security Controls

### 1. Command Authentication

**Threat**: Attacker forges commands from ASP

**Control**: Cryptographic signatures
```
SignedCommand.signature = sign(command_data, ASP_PRIVATE_KEY)
```

**Verification**:
```python
verify_signature(asp.public_key_pem, signable_data, cmd.signature)
```

**Residual Risk**: If ASP private key is compromised, attacker can sign valid commands.

---

### 2. Authorization (Policy Enforcement)

**Threat**: ASP executes commands on VMs they don't own

**Control**: ASP Registry with allowed_vms list
```json
{
  "asp_id": "company-a",
  "allowed_vms": ["146.148.46.72", "10.0.0.5"]
}
```

**Verification**:
```python
if cmd.target_vm not in asp.allowed_vms:
    reject("Not authorized for VM")
```

**Residual Risk**: Registry misconfiguration could grant excessive access.

---

### 3. Replay Attack Prevention

**Threat**: Attacker captures and replays a valid signed command

**Controls**:
1. **Timestamp**: Commands expire after 5 minutes
2. **Nonce**: Each command has unique 32-byte random nonce

**Verification**:
```python
# Timestamp check
if time.time() - cmd.timestamp > 300:
    reject("Command expired")

# Nonce check
if cmd.nonce in used_nonces:
    reject("Nonce already used")
used_nonces.add(cmd.nonce)
```

**Residual Risk**: Replay within 5-minute window if nonce not yet seen.

---

### 4. Transport Security (mTLS)

**Threat**: Man-in-the-middle attack on command transmission

**Control**: Mutual TLS with certificate validation
- Gateway verifies client certificate
- Client verifies gateway certificate
- Both signed by trusted CA

```python
# Gateway side
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations(ca_cert_file)

# Client side
context.load_cert_chain(client_cert_file, client_key_file)
```

**Residual Risk**: CA compromise would allow MITM.

---

### 5. Enclave Integrity (SGX)

**Threat**: Cloud admin modifies gateway code

**Control**: SGX enclave with measured execution
- ASP Registry is in `sgx.trusted_files` (measured into MRENCLAVE)
- Gateway code is measured
- Any modification changes MRENCLAVE

**Verification**:
```bash
gramine-sgx-sigstruct-view gateway.sig
# Verify MRENCLAVE matches expected value
```

---

### 6. Audit Log Integrity

**Threat**: Attacker modifies audit logs to hide actions

**Controls**:
1. **Enclave Signature**: Each log entry signed by enclave key
2. **Sealed Storage**: Logs encrypted with SGX sealing key

```python
log_entry.enclave_signature = sign(log_data, ENCLAVE_PRIVATE_KEY)
# Stored in /sealed/logs/ (encrypted by SGX)
```

**Verification**:
```python
# End user verifies log with enclave public key
verify_signature(enclave_public_key, log_data, log.enclave_signature)
```

---

### 7. SSH Channel Security

**Threat**: Unauthorized SSH access to TDX VM

**Control**: Enclave-only SSH key
- Private key stored inside enclave (`/app/certs/enclave_ssh_key`)
- TDX VM only accepts this key in `authorized_keys`
- Firewall restricts SSH to SGX IP

**Residual Risk**: If enclave is compromised, SSH key is accessible.

---

## Attack Scenarios

### Scenario 1: Malicious Cloud Admin

**Attack**: Admin with hypervisor access tries to execute commands on TDX VM.

**Defense**:
1. Cannot connect to gateway without valid ASP client certificate (mTLS)
2. Cannot forge signed commands without ASP private key
3. Cannot modify gateway code (measured by SGX)
4. Cannot read enclave memory (SGX protection)

**Result**: Attack blocked.

---

### Scenario 2: Replay Attack

**Attack**: Attacker captures `apt-get update` command and replays it later.

**Defense**:
1. Command expires after 5 minutes (timestamp check)
2. Nonce is recorded; second attempt rejected

**Result**: Attack blocked (unless replayed within 5 min AND nonce not yet seen).

---

### Scenario 3: Rogue ASP

**Attack**: ASP A tries to execute commands on ASP B's VM.

**Defense**:
1. Gateway checks `allowed_vms` for ASP A
2. ASP B's VM not in ASP A's list
3. Request rejected with "Not authorized for VM"

**Result**: Attack blocked.

---

### Scenario 4: Log Tampering

**Attack**: Attacker modifies audit logs to hide malicious commands.

**Defense**:
1. Logs are stored in sealed storage (encrypted)
2. Each entry has enclave signature
3. Modification detected during verification

**Result**: Tampering detected.

---

## Recommendations

### Production Hardening

1. **Disable debug mode**: Set `sgx.debug = false` in manifest
2. **Use hardware random**: Ensure /dev/urandom available in enclave
3. **Rotate keys**: Implement key rotation for ASP and enclave keys
4. **Log rotation**: Archive and seal old logs periodically
5. **Rate limiting**: Add per-ASP rate limits for commands
6. **Command allowlist**: Restrict allowed commands (no arbitrary shell)

### Monitoring

1. Log all authentication failures
2. Alert on unusual command patterns
3. Monitor enclave health
4. Track nonce cache size

### Key Management

| Key | Storage | Backup |
|-----|---------|--------|
| ASP Private Key | ASP's secure storage | Offline backup |
| ASP Public Key | In enclave registry | Version controlled |
| Enclave SSH Key | Inside enclave | Sealed backup |
| Enclave Signing Key | Inside enclave | Sealed backup |
| TLS Certificates | Filesystem | Secure backup |
