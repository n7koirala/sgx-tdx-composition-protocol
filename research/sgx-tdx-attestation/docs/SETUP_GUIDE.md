# SGX-TDX Hierarchical Attestation - End-to-End Setup Guide

This guide walks you through setting up and running the hierarchical attestation protocol from scratch.

For the protocol 1.2 DCAP path with vTPM PCR-10 and IMA-to-RTMR[3], follow
[VTPM_RTMR3_INTEGRATION.md](./VTPM_RTMR3_INTEGRATION.md). The ITA setup below
remains available but does not exercise the composed runtime predicate.

## Prerequisites

### SGX Machine (Your Lab)
- Intel SGX-enabled CPU
- Ubuntu 20.04/22.04
- Gramine installed (1.9+)
- SGX driver and AESM service running
- Python 3.8+

### TDX Machine (Google Cloud)
- TDX-enabled Confidential VM (e.g., `n2d-standard-2` with TDX)
- Ubuntu 22.04
- Intel TDX device (`/dev/tdx_guest`)
- `trustauthority-cli` installed and configured
- Python 3.8+

---

## Step 1: Set Up TDX Machine (Google Cloud CVM)

### 1.1 Create TDX Confidential VM

```bash
gcloud compute instances create tdx-attestation-vm \
    --zone=us-central1-a \
    --machine-type=n2d-standard-2 \
    --confidential-compute \
    --maintenance-policy=TERMINATE \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud
```

### 1.2 Verify TDX Device

```bash
ssh <TDX_VM_IP>
ls -la /dev/tdx_guest
# Should show: crw------- 1 root root 10, 125 ... /dev/tdx_guest
```

### 1.3 Install Intel Trust Authority CLI

```bash
# Download and install trustauthority-cli
# (Follow Intel's official installation guide)
wget https://download.01.org/intel-sgx/...
sudo dpkg -i trustauthority-cli*.deb

# Verify installation
which trustauthority-cli
```

### 1.4 Configure Trust Authority

Create `~/config.json` with your Intel Trust Authority API key:

```json
{
    "trustauthority_api_url": "https://api.trustauthority.intel.com",
    "trustauthority_api_key": "YOUR_API_KEY_HERE"
}
```

### 1.5 Test TDX Attestation

```bash
sudo trustauthority-cli token --tdx -c ~/config.json
# Should output a JWT token starting with "eyJ..."
```

---

## Step 2: Set Up SGX Machine (Lab)

### 2.1 Verify SGX Setup

```bash
# Check SGX device
ls -la /dev/sgx_enclave

# Check AESM service
sudo systemctl status aesmd

# Check Gramine
gramine-sgx --version
```

### 2.2 Install Dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip openssl
```

### 2.3 Generate SGX Signing Key (if not exists)

```bash
gramine-sgx-gen-private-key ~/.config/gramine/enclave-key.pem
```

---

## Step 3: Deploy the Code

### 3.1 Clone/Copy the Project

Ensure the `sgx-tdx-attestation` directory is on your SGX machine at:
```
/home/<user>/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/
```

### 3.2 Generate TLS Certificates

On the **SGX machine**:

```bash
cd /home/<user>/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/certs

# Generate certificates (replace with TDX VM's IP)
./generate_certs.sh 35.192.102.169
```

This creates:
- `ca.crt` - CA certificate
- `ca.key` - CA private key (keep secure)
- `server.crt` - TDX server certificate
- `server.key` - TDX server private key

### 3.3 Copy Files to TDX Machine

From the **SGX machine**:

```bash
TDX_IP="35.192.102.169"
TDX_USER="nkoirala"

# Create directory structure on TDX
ssh ${TDX_USER}@${TDX_IP} "mkdir -p ~/hierarchical-attestation/{certs,common,tdx-server}"

# Copy certificates
scp certs/{ca.crt,server.crt,server.key} ${TDX_USER}@${TDX_IP}:~/hierarchical-attestation/certs/

# Copy common module
scp common/*.py ${TDX_USER}@${TDX_IP}:~/hierarchical-attestation/common/

# Copy TDX server
scp tdx-server/*.py ${TDX_USER}@${TDX_IP}:~/hierarchical-attestation/tdx-server/
```

### 3.4 Verify TDX Files

SSH to TDX machine and verify:

```bash
ssh ${TDX_USER}@${TDX_IP}
ls -la ~/hierarchical-attestation/
# Should show: certs/, common/, tdx-server/

ls -la ~/hierarchical-attestation/certs/
# Should show: ca.crt, server.crt, server.key
```

---

## Step 4: Configure Firewall

### 4.1 Open Port 8443 on TDX VM

In Google Cloud Console or via gcloud:

```bash
gcloud compute firewall-rules create allow-tdx-attestation \
    --allow tcp:8443 \
    --source-ranges <SGX_MACHINE_IP>/32 \
    --target-tags <TDX_VM_TAG>
```

Or for testing (less secure):
```bash
gcloud compute firewall-rules create allow-tdx-attestation-all \
    --allow tcp:8443 \
    --source-ranges 0.0.0.0/0
```

---

## Step 5: Start TDX Attestation Server

On the **TDX machine**:

### 5.1 Test TDX Server

```bash
cd ~/hierarchical-attestation/tdx-server
python3 tdx_attestation_server.py --test
```

Expected output:
```
======================================================================
TDX Attestation Server - Self Test
======================================================================

[1] Checking TDX device...
    ✓ /dev/tdx_guest available

[2] Checking trustauthority-cli...
    ✓ Found at /usr/bin/trustauthority-cli

[3] Testing attestation token generation...
    ✓ Token generated (1234.5ms, 6009 bytes)

[4] Parsing token...
    ✓ MRTD: a5844e88897b70c318bef929ef4dfd6c...
    ✓ TCB Status: OutOfDate

======================================================================
✓ Self-test PASSED - Ready to serve attestation requests
======================================================================
```

### 5.2 Start the Server

```bash
python3 tdx_attestation_server.py --port 8443
```

Keep this terminal open. You should see:
```
======================================================================
TDX Hierarchical Attestation Server
======================================================================
Protocol Version: 1.2
Port:             8443
TLS Certificate:  ../certs/server.crt
Config:           /home/nkoirala/config.json
Started:          2026-01-07T21:00:00

Waiting for attestation challenges from SGX enclave...
```

---

## Step 6: Run SGX Enclave Verifier

On the **SGX machine**:

### 6.1 Quick Test (Pure Python, No Enclave)

First, test without SGX to verify connectivity:

```bash
cd /home/<user>/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/sgx-verifier

PYTHONPATH=.. python3 sgx_tdx_verifier.py \
    --tdx-host 35.192.102.169 \
    --tdx-port 8443 \
    --ca-cert ../certs/ca.crt \
    --verbose
```

### 6.2 Build SGX Enclave

```bash
cd /home/<user>/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/sgx-verifier

# Build the enclave (takes a few minutes)
make all
```

Expected output:
```
[1/2] Generating manifest (this may take a few minutes)...
      Gramine is hashing all trusted files...
      ✓ Manifest generated (8.1M)
[2/2] Signing manifest for SGX...
      ✓ Manifest signed

Enclave ready! Measurements:
mr_enclave:    abc123...
mr_signer:     def456...
isv_prod_id:   1
isv_svn:       0
```

### 6.3 Run Inside SGX Enclave

```bash
make run-sgx TDX_HOST=35.192.102.169 TDX_PORT=8443
```

Or run directly:
```bash
gramine-sgx ./verifier /app/sgx-verifier/sgx_tdx_verifier.py \
    --tdx-host 35.192.102.169 \
    --tdx-port 8443 \
    --ca-cert /app/certs/ca.crt \
    --verbose
```

---

## Step 7: Verify Results

### Successful Attestation

```
======================================================================
VERIFICATION RESULT
======================================================================

  ✓ Verdict: TRUSTED

  Time: 858.5 ms

  Checks:
    Issuer:  ✓
    Expiry:  ✓
    Nonce:   ✓

  TDX Measurements:
    MRTD:       a5844e88897b70c318bef929ef4dfd6c7304c52c4bc9c3f3...
    TCB Status: UpToDate
    Debuggable: False

======================================================================
```

### Failed Attestation Examples

**Nonce Binding Failed:**
```
  ✗ Verdict: UNTRUSTED
  Error: Nonce not properly bound in report_data
```

**Token Expired:**
```
  ✗ Verdict: UNTRUSTED
  Error: Token expired at 2026-01-07T20:00:00
```

---

## Step 8: Troubleshooting

See [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) for common issues.

### Quick Checks

1. **Connection Refused**
   - Is TDX server running? Check with `ps aux | grep tdx`
   - Is firewall open? Check `sudo iptables -L`
   - Is port correct? Default is 8443

2. **TLS Errors**
   - Are certificates copied correctly?
   - Is ca.crt on SGX machine matching the one that signed server.crt?

3. **Permission Denied in Enclave**
   - Rebuild with `make clean && make all`
   - Check manifest paths

4. **TDX Token Generation Failed**
   - Is `~/config.json` present with valid API key?
   - Is `/dev/tdx_guest` accessible?

---

## Summary

| Step | Location | Command |
|------|----------|---------|
| Generate certs | SGX machine | `./generate_certs.sh <TDX_IP>` |
| Copy files to TDX | SGX machine | `scp -r ... TDX_IP:~/hierarchical-attestation/` |
| Start TDX server | TDX machine | `python3 tdx_attestation_server.py --port 8443` |
| Build SGX enclave | SGX machine | `make all` |
| Run attestation | SGX machine | `make run-sgx TDX_HOST=<IP> TDX_PORT=8443` |
