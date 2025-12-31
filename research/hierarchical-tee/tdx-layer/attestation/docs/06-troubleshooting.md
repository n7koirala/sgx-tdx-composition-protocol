# Troubleshooting Guide

## Common Issues and Solutions

### 1. Rate Limiting (HTTP 429)

**Symptoms:**
```
Error: Request to "https://api.trustauthority.intel.com/appraisal/v2/attest" failed: 
StatusCode = 429, Response = {"message": "Too many requests, limit exceeded."}
```

**Cause:**
Intel Trust Authority has rate limits on API calls. Running `token` generation too frequently triggers this.

**Solutions:**

1. **Wait and retry:**
   ```python
   import time
   
   def get_token_with_retry(attestor, max_retries=3):
       for attempt in range(max_retries):
           try:
               return attestor.get_attestation_token()
           except RuntimeError as e:
               if "429" in str(e):
                   wait = 30 * (attempt + 1)
                   print(f"Rate limited, waiting {wait}s...")
                   time.sleep(wait)
               else:
                   raise
       raise RuntimeError("Max retries exceeded")
   ```

2. **Use evidence instead of token for testing:**
   ```python
   # This doesn't hit rate limits
   evidence = attestor.get_evidence()
   ```

3. **Cache tokens:**
   ```python
   # Tokens are valid for ~5 minutes
   if cached_token and cached_token.is_valid():
       return cached_token
   else:
       return attestor.get_attestation_token()
   ```

4. **Space out requests:**
   ```bash
   # Wait at least 30 seconds between token requests
   time.sleep(30)
   ```

---

### 2. TDX Device Not Found

**Symptoms:**
```
RuntimeError: TDX device not found: /dev/tdx_guest
```

**Cause:**
Not running inside a TDX-enabled VM.

**Solutions:**

1. **Verify you're in a TDX VM:**
   ```bash
   ls -la /dev/tdx*
   # Should show: /dev/tdx_guest
   ```

2. **Check dmesg for TDX:**
   ```bash
   dmesg | grep -i tdx
   ```

3. **On GCP, ensure you created a Confidential VM with Intel TDX**

---

### 3. Permission Denied

**Symptoms:**
```
PermissionError: Insufficient permissions for /dev/tdx_guest. Run as root.
```

**Solutions:**

1. **Run with sudo:**
   ```bash
   sudo python3 tdx_remote_attestation.py
   ```

2. **Or add user to appropriate group:**
   ```bash
   # Check device permissions
   ls -la /dev/tdx_guest
   # May need to create udev rules
   ```

---

### 4. Config File Not Found

**Symptoms:**
```
RuntimeError: Config file not found: /home/user/config.json
```

**Solutions:**

1. **Create the config file:**
   ```bash
   cat > ~/config.json << EOF
   {
     "trustauthority_api_url": "https://api.trustauthority.intel.com",
     "trustauthority_api_key": "your-api-key-here"
   }
   EOF
   ```

2. **Specify custom path:**
   ```python
   attestor = TDXAttestor(config_path="/path/to/config.json")
   ```

---

### 5. trustauthority-cli Not Found

**Symptoms:**
```
RuntimeError: trustauthority-cli not found in PATH
```

**Solutions:**

1. **Check if installed:**
   ```bash
   which trustauthority-cli
   ```

2. **Install if missing:**
   - Download from Intel Trust Authority portal
   - Or use package manager if available

3. **Add to PATH:**
   ```bash
   export PATH=$PATH:/path/to/trustauthority-cli
   ```

---

### 6. Token Expired

**Symptoms:**
```
Token verification failed: Token expired
```

**Cause:**
Intel TA tokens are valid for ~5 minutes.

**Solutions:**

1. **Generate a fresh token:**
   ```python
   token = attestor.get_attestation_token()
   ```

2. **Check expiry before using:**
   ```python
   if not token.is_valid():
       token = attestor.get_attestation_token()
   ```

---

### 7. Network Timeout to Verifier

**Symptoms:**
```
Connection timeout
Connection refused
```

**Cause:**
Verifier is not running or network issues.

**Solutions:**

1. **Check verifier is running:**
   ```bash
   # On verifier machine
   python3 tdx_verifier_service.py 9999
   ```

2. **Check firewall:**
   ```bash
   # On verifier machine
   sudo ufw allow 9999/tcp
   ```

3. **Test connectivity:**
   ```bash
   nc -zv <verifier_ip> 9999
   ```

---

### 8. Invalid JWT Format

**Symptoms:**
```
ValueError: Invalid JWT format (expected 3 parts)
```

**Cause:**
The token string is malformed or truncated.

**Solutions:**

1. **Check the raw output:**
   ```bash
   sudo trustauthority-cli token --tdx -c ~/config.json
   # Token starts with eyJ...
   ```

2. **Ensure you're extracting the token correctly:**
   ```python
   # Token is the last line starting with eyJ
   for line in output.split('\n'):
       if line.startswith('eyJ'):
           token = line
           break
   ```

---

### 9. TCB Status "OutOfDate"

**Symptoms:**
```
TCB Status: OutOfDate
```

**Cause:**
The platform firmware/software hasn't been updated with latest security patches.

**Impact:**
- Attestation still works
- Some verifiers may reject or flag this
- Known vulnerabilities may affect the platform

**Solutions:**

1. **For testing:** This is usually acceptable
2. **For production:** Update platform firmware
3. **Policy decision:** Your verifier can accept or reject based on TCB status

---

### 10. Binding Hash Mismatch

**Symptoms:**
Binding verification fails on verifier.

**Cause:**
- Timestamp in binding doesn't match
- SGX MRENCLAVE is different
- Different binding data format

**Solutions:**

1. **Use deterministic binding:**
   ```python
   # Don't include timestamp in binding
   binding_data = {
       "purpose": "hierarchical-tee-composition",
       "sgx_mrenclave": mrenclave
   }
   ```

2. **Ensure same MRENCLAVE is used everywhere**

3. **Debug by logging:**
   ```python
   print(f"Expected hash: {expected_hash[:32]}")
   print(f"Report data: {report_data}")
   ```

---

## Debugging Tips

### Enable Verbose Output

```bash
# CLI shows debug info by default
sudo trustauthority-cli token --tdx -c ~/config.json

# Output includes:
# [DEBUG] GET https://api.trustauthority.intel.com/appraisal/v2/nonce
# [DEBUG] POST https://api.trustauthority.intel.com/appraisal/v2/attest
```

### Decode JWT Manually

```python
import base64
import json

token = "eyJ..."
parts = token.split('.')

# Decode header
header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
print("Header:", json.dumps(header, indent=2))

# Decode payload
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
print("Payload:", json.dumps(payload, indent=2))
```

### Test Each Component

```bash
# 1. Test TDX device
sudo cat /dev/tdx_guest  # Should fail but confirms access

# 2. Test evidence generation (no network)
sudo trustauthority-cli evidence --tdx -c ~/config.json

# 3. Test token generation (with network)
sudo trustauthority-cli token --tdx -c ~/config.json

# 4. Test Python module
sudo python3 -c "from tdx_remote_attestation import TDXAttestor; TDXAttestor()"
```

### Check System Logs

```bash
# TDX kernel messages
dmesg | grep -i tdx

# Trust Authority CLI logs (if any)
journalctl -u trustauthority  # If running as service
```

---

## Known Limitations

1. **Rate Limits:** Intel TA limits token requests (~10-20 per minute)
2. **Root Required:** TDX device access requires root privileges
3. **Network Required:** Token generation needs internet access to Intel TA
4. **Token Expiry:** Tokens expire in ~5 minutes
5. **TCB Updates:** Platform may show "OutOfDate" if not recently updated

---

## Getting Help

1. **Intel TDX Documentation:** https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html
2. **Intel Trust Authority:** https://www.intel.com/content/www/us/en/security/trust-authority.html
3. **Linux TDX Documentation:** https://docs.kernel.org/arch/x86/tdx.html
