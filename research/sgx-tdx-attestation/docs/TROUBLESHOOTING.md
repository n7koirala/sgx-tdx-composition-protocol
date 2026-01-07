# SGX-TDX Hierarchical Attestation - Troubleshooting Guide

This document covers common issues and their solutions.

---

## TDX Server Issues

### Issue: `/dev/tdx_guest` not found

**Symptom:**
```
RuntimeError: TDX device not found: /dev/tdx_guest
```

**Cause:** Not running on a TDX-enabled VM.

**Solution:**
1. Verify you're on a TDX Confidential VM
2. Check kernel support: `dmesg | grep -i tdx`
3. Load TDX module: `sudo modprobe tdx_guest`

---

### Issue: `trustauthority-cli` not found

**Symptom:**
```
RuntimeError: trustauthority-cli not found in PATH
```

**Solution:**
1. Install Intel Trust Authority CLI
2. Add to PATH: `export PATH=$PATH:/path/to/trustauthority-cli`
3. Verify: `which trustauthority-cli`

---

### Issue: Token generation failed - API error

**Symptom:**
```
Token generation failed: API rate limit exceeded
```

**Solution:**
1. Wait 1-2 minutes and retry
2. Check API key in `~/config.json`
3. Verify network connectivity to Intel API

---

### Issue: Certificate not found

**Symptom:**
```
RuntimeError: Certificate not found: ../certs/server.crt
```

**Solution:**
1. Generate certificates: `cd ../certs && ./generate_certs.sh <IP>`
2. Verify paths: `ls -la ../certs/`
3. Use absolute paths if needed

---

## SGX Verifier Issues

### Issue: Connection refused

**Symptom:**
```
Error: Connection refused to 35.192.102.169:8443
```

**Causes:**
1. TDX server not running
2. Firewall blocking port 8443
3. Wrong IP address

**Solutions:**
```bash
# On TDX machine - check if server is running
ps aux | grep tdx_attestation_server

# Check firewall
sudo iptables -L -n | grep 8443

# Verify port is listening
sudo netstat -tlnp | grep 8443
```

---

### Issue: TLS handshake failed

**Symptom:**
```
TLS error: [SSL: CERTIFICATE_VERIFY_FAILED]
```

**Causes:**
1. CA certificate mismatch
2. Expired certificates
3. Wrong CA cert path

**Solutions:**
```bash
# Verify certificates match
openssl x509 -in certs/server.crt -noout -issuer
openssl x509 -in certs/ca.crt -noout -subject
# These should match

# Check certificate expiry
openssl x509 -in certs/server.crt -noout -dates

# Regenerate if needed
cd certs && ./generate_certs.sh <TDX_IP>
```

---

### Issue: Permission denied in enclave

**Symptom:**
```
/usr/bin/python3: can't open file '/app/sgx-verifier/sgx_tdx_verifier.py': [Errno 13] Permission denied
```

**Causes:**
1. Manifest not rebuilt after file changes
2. Incorrect app_dir in manifest

**Solutions:**
```bash
# Rebuild manifest
make clean
make all

# Verify APP_DIR
make help | grep APP_DIR
```

---

### Issue: Nonce binding verification failed

**Symptom:**
```
Error: Nonce not properly bound in report_data
```

**Causes:**
1. Mismatched protocol.py between SGX and TDX
2. TDX server not passing nonce correctly
3. Encoding mismatch

**Solutions:**
```bash
# Sync protocol.py to TDX machine
scp common/protocol.py user@TDX_IP:~/hierarchical-attestation/common/

# Restart TDX server after sync
# (on TDX machine)
pkill -f tdx_attestation_server
python3 tdx_attestation_server.py --port 8443

# Run with verbose to see debug output
make run-sgx TDX_HOST=<IP> TDX_PORT=8443
# Look for [DEBUG] lines showing report_data content
```

---

### Issue: manifest conflicting options

**Symptom:**
```
error: PAL failed at parsing the manifest: Options loader.argv, loader.argv_src_file, 
and loader.insecure__use_cmdline_argv are mutually exclusive
```

**Solution:**
Remove `loader.argv` from manifest template if using `loader.insecure__use_cmdline_argv = true`.

---

### Issue: Quote generation timeout

**Symptom:**
```
Timeout during quote generation
```

**Causes:**
1. AESM service not running
2. DCAP quote provider misconfigured

**Solutions:**
```bash
# Check AESM
sudo systemctl status aesmd
sudo systemctl restart aesmd

# Check DCAP
dpkg -l | grep dcap
```

---

## Network Issues

### Issue: Cannot reach TDX VM from SGX machine

**Diagnosis:**
```bash
# Test TCP connectivity
nc -zv 35.192.102.169 8443

# Test with curl (should fail but shows connection)
curl -k https://35.192.102.169:8443

# Check routing
traceroute 35.192.102.169
```

### Issue: GCP firewall blocking connection

**Solution:**
```bash
# Create firewall rule
gcloud compute firewall-rules create allow-attestation \
    --allow tcp:8443 \
    --source-ranges <SGX_MACHINE_IP>/32

# Verify rule
gcloud compute firewall-rules list | grep attestation
```

---

## Debug Commands

### Check TDX attestation manually
```bash
# On TDX machine
sudo trustauthority-cli token --tdx -c ~/config.json -u "test123"
```

### Decode JWT token
```bash
# Split and decode payload
TOKEN="eyJ..."
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

### Test TLS connection
```bash
openssl s_client -connect 35.192.102.169:8443 -CAfile certs/ca.crt
```

### Check enclave measurements
```bash
gramine-sgx-sigstruct-view verifier.sig
```

---

## Getting Help

If issues persist:

1. Run with `--verbose` flag for detailed output
2. Check both TDX server and SGX verifier logs
3. Verify all files are synced between machines
4. Ensure protocol.py version matches on both sides
