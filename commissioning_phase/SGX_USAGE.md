# SGX Controller - Usage Guide

## Overview

The SGX Controller is a Flask-based server that runs inside an Intel SGX enclave using Gramine. It provisions and manages TDX Confidential VMs on Google Cloud Platform with hardware-enforced security guarantees.

## Security Properties (When Running in SGX)

✅ **Private SSH keys** generated and stored inside SGX enclave (never leave hardware-protected memory)
✅ **ASP signature verification** enforced for all privileged operations
✅ **IMA-based launch integrity** verification detects post-boot tampering
✅ **SGX remote attestation** (DCAP) allows clients to verify enclave authenticity
✅ **Multi-layer SSH hardening** prevents unauthorized access to CVMs
✅ **Cryptographic audit trail** with SHA-256 hashed command logs

---

## Prerequisites

### 1. Hardware & Software
- **Intel SGX-capable CPU** (check: `ls /dev/sgx_enclave`)
- **Gramine 1.9+** installed (`gramine-sgx --version`)
- **AESM service** running (`systemctl status aesmd`)
- **Python 3.12** with dependencies installed globally

### 2. Python Dependencies (Installed Globally)
```bash
sudo pip3 install --break-system-packages --ignore-installed blinker flask paramiko cryptography google-cloud-compute google-auth python-dotenv requests
```

### 3. GCP Configuration
- Create `gcp_config.env` from template
- Set up GCP authentication:
  ```bash
  gcloud auth application-default login
  ```

### 4. ASP Keys
```bash
python3 generate_asp_keys.py
```

### 5. IMA Reference Manifest (Optional)
```bash
python3 generate_reference_manifest.py
```

---

## Build the SGX Enclave

```bash
cd /home/nkoirala/sgx-tdx-composition-protocol/commissioning_phase

# Check setup
make check-setup

# Build manifest and sign for SGX
make all
```

**Output:**
```
✓ Manifest signed successfully!

SGX Enclave Measurements:
    mr_signer: 3ca59c440a720c7bb9dd4c86da5567bb98570a964b0f74ed553e6b2c44e87cbf
    mr_enclave: 3000dcee25b7b3904d617ef444b7bb4425210b80684a3a23608b97232cc54b32
    isv_prod_id: 1
    isv_svn: 1
```

**MRENCLAVE** is the cryptographic measurement of the enclave code and configuration. ASP clients verify this before trusting the controller.

---

## Run the Controller

### Option 1: Run in SGX Mode 

**Auto-detect Controller IP:**
```bash
make run-sgx
```

The controller will try (in order):
1. `$CONTROLLER_IP` environment variable
2. GCP metadata service (if running on GCP instance)
3. HTTP request to api.ipify.org
4. HTTPS request to api.ipify.org (may fail in SGX)

**Explicit Controller IP (Recommended):**
```bash
make run-sgx CONTROLLER_IP=<your-external-ip>
```

Example:
```bash
make run-sgx CONTROLLER_IP=34.82.45.123 PORT=6037
```

**Why specify CONTROLLER_IP?**
- Firewall rules restrict SSH to this IP (`<controller_ip>/32`)
- Auto-detection may fail in SGX due to SSL limitations
- Explicit IP is more secure and reliable

### Option 2: Run in Direct Mode (Development/Testing)

**⚠️ WARNING:** No SGX protection, no hardware attestation, keys not isolated!

```bash
make run-direct
```

Use only for:
- Testing on machines without SGX hardware
- Debugging manifest configuration
- Verifying Python dependencies

---

## Verify SGX is Actually Running

### 1. Check Gramine Startup Messages
You should see:
```
Gramine is starting. Parsing TOML manifest file...
-------------------------------------------------------
Gramine detected the following SGX devices:
   /dev/sgx_enclave (device for enclaves)
-------------------------------------------------------
```

### 2. Check Process
```bash
ps aux | grep gramine-sgx
```

Should show:
```
/usr/lib/x86_64-linux-gnu/gramine/sgx/loader ... python3 -m commissioning_phase.sgx_controller ...
```

NOT just:
```
python3 -m commissioning_phase.sgx_controller -t sgx
```

### 3. Test Attestation
From ASP client:
```python
import requests
resp = requests.get("http://<controller-ip>:6037/quote")
quote = resp.json()["quote"]  # Should contain SGX DCAP quote
```

If running in direct mode, quote will be empty or you'll see warnings.

---

## Configuration Options

### Makefile Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `PORT` | 6037 | Flask server port |
| `CONTROLLER_IP` | (auto) | Controller's external IP for firewall rules |
| `LOG_LEVEL` | error | Gramine log level: error, warning, debug, trace |
| `SGX_DEBUG` | true | Debug enclave (set to false for production) |
| `ATTESTATION_METHOD` | dcap | Attestation: dcap (local) |

### Environment Variables (Passed to Enclave)

Set in `gcp_config.env`:
- `GCP_PROJECT_ID` - Google Cloud project
- `GCP_ZONE` - TDX-capable zone (e.g., us-central1-a)
- `VM_MACHINE_TYPE` - C3-series machine type
- `GCP_SERVICE_ACCOUNT_KEY` - Path to service account JSON (optional)

---

## Troubleshooting

### Issue: SSL Error Getting Controller IP

**Symptom:**
```
WARNING: Could not determine controller IP: SSLError(SSLError(0, 'unknown error (_ssl.c:3076)'))
WARNING: Using 0.0.0.0/0 as source range
```

**Solution:**
```bash
# Option 1: Specify IP explicitly
make run-sgx CONTROLLER_IP=$(curl -s http://api.ipify.org)

# Option 2: If running on GCP, metadata service will auto-detect
make run-sgx

# Option 3: Check if HTTP fallback is working (logs should show "HTTP")
# This should work in the updated version
```

### Issue: Import Error (Relative Imports)

**Symptom:**
```
ImportError: attempted relative import with no known parent package
```

**Solution:**
This means the controller is being run as a script instead of as a module. Ensure Makefile uses:
```makefile
gramine-sgx ./controller -m commissioning_phase.sgx_controller -t sgx
```

NOT:
```makefile
gramine-sgx ./controller /path/to/sgx_controller.py -t sgx
```

### Issue: Flask Not Found

**Symptom:**
```
ModuleNotFoundError: No module named 'flask'
```

**Solution:**
```bash
# Install globally
sudo pip3 install --break-system-packages --ignore-installed blinker flask paramiko cryptography google-cloud-compute google-auth python-dotenv requests

# Rebuild manifest
make clean && make all
```

### Issue: Blinker Version Conflict

**Symptom:**
```
ERROR: Cannot uninstall blinker 1.7.0, RECORD file not found
```

**Solution:**
```bash
sudo pip3 install --break-system-packages --ignore-installed blinker flask ...
```

The `--ignore-installed blinker` forces installation of Flask's required version (1.9.0) alongside the system version.

---

## Security Considerations

### Deployment Checklist

- [ ] Set `SGX_DEBUG = false` in Makefile (disables debug features)
- [ ] Specify `CONTROLLER_IP` explicitly (don't rely on auto-detection)
- [ ] Use GCP service account with minimal permissions
- [ ] Generate IMA reference manifest from known-good CVM
- [ ] Rotate ASP keys regularly
- [ ] Monitor sealed storage directory permissions (600)
- [ ] Review firewall rules (should be `<controller-ip>/32`, not `0.0.0.0/0`)
- [ ] Enable GCP audit logging for CVM operations
- [ ] Verify ASP clients check MRENCLAVE before trusting controller

### What's Protected by SGX

✅ **In SGX enclave (hardware-protected):**
- Controller RSA private key
- Ephemeral SSH private keys for CVMs
- ASP signature verification logic
- IMA verification logic
- In-memory CVM state (IPs, command history)

❌ **Outside SGX enclave (untrusted):**
- GCP API credentials (must trust host OS)
- Network traffic (use TLS)
- gcp_config.env (filesystem on host)
- ASP public keys (trusted files, measured in MRENCLAVE)

### Attack Scenarios

| Attack | SGX Protection | Mitigation |
|--------|----------------|------------|
| Steal SSH private key from memory | ✅ Protected | Keys in SGX encrypted memory |
| Modify controller code | ✅ Protected | MRENCLAVE changes, ASP verification fails |
| Inject malicious SSH key via IAM | ✅ Protected | 5-layer SSH hardening on CVM |
| Compromise GCP credentials | ❌ Not protected | Minimize service account permissions |
| Network MITM attack | ❌ Not protected | Use TLS for ASP-controller communication |
| Rollback CVM to older state | ✅ Partially protected | IMA detects changes, audit log tracks transitions |

---

## Differences: SGX Mode vs Direct Mode

| Aspect | `make run-sgx` | `make run-direct` |
|--------|---------------|------------------|
| **Runs in SGX enclave** | ✅ Yes | ❌ No (normal process) |
| **Private keys protected** | ✅ Hardware-isolated | ❌ In normal RAM |
| **Attestation available** | ✅ DCAP quote | ❌ No quote |
| **MRENCLAVE measured** | ✅ Yes | ❌ No |
| **Performance** | Slower (SGX overhead) | Faster |
| **Use case** | Production | Development/testing |

---

## Example Workflows

### Workflow 1: Launch CVM from SGX Controller

**Terminal 1: Start Controller**
```bash
cd commissioning_phase
make run-sgx CONTROLLER_IP=34.82.45.123
```

**Terminal 2: ASP Client**
```bash
cd commissioning_phase
python3 -c "
from asp_client import ASPClient
client = ASPClient('http://localhost:6037')
client.verify_controller()  # Checks SGX quote
response = client.start_cvm()
print(f'CVM ID: {response[\"state\"][\"cvm_id\"]}')
print(f'CVM IP: {response[\"state\"][\"ip\"]}')
"
```

### Workflow 2: Rebuild After Code Changes

```bash
# Clean old manifest
make clean

# Rebuild (MRENCLAVE will change!)
make all

# Note new MRENCLAVE
make view-sig

# Restart controller
make run-sgx

# ASP clients must update expected MRENCLAVE
```

### Workflow 3: Switch Between SGX and Direct Mode

```bash
# Test in direct mode (faster iteration)
make run-direct

# Once working, build for SGX
make all
make run-sgx
```

No code changes needed - the same Python code runs in both modes!

---

## Files Created

After building, you'll have:

```
commissioning_phase/
├── controller.manifest          # Generated manifest (9.7MB, includes all file hashes)
├── controller.manifest.sgx      # Signed manifest for SGX
├── controller.sig               # SGX signature structure (contains MRENCLAVE)
├── controller.manifest.template # Source template (you edit this)
├── Makefile                     # Build and run targets (you edit this)
├── sealed/
│   └── private_key              # Sealed controller RSA key (encrypted to MRENCLAVE)
```

**Important:** If you change code or manifest template, MRENCLAVE changes and sealed keys become inaccessible!

---

## Additional Commands

```bash
# View enclave measurements
make view-sig

# Show build configuration
make info

# Clean generated files
make clean

# Help
make help
```

---

## Next Steps

1. **Test in direct mode first:** `make run-direct`
2. **Build for SGX:** `make all`
3. **Run in SGX:** `make run-sgx CONTROLLER_IP=<your-ip>`
4. **Verify SGX is active:** Check for Gramine messages
5. **Test ASP client:** Verify attestation quote
6. **Launch first CVM:** `asp_client.py start_cvm()`
7. **Check IMA verification:** Should see "Phase C': IMA verification PASSED"

<!-- For production deployment, review the Security Considerations section and set `SGX_DEBUG=false`. -->
