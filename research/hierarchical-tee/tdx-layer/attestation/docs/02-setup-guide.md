# TDX Attestation Setup Guide

## Prerequisites

### Hardware Requirements
- Intel CPU with TDX support (4th Gen Xeon Scalable or later)
- TDX-enabled BIOS/firmware
- Running inside a TDX-enabled VM (e.g., GCP Confidential VM)

### Software Requirements
- Linux kernel with TDX guest support (5.19+)
- Intel Trust Authority CLI (`trustauthority-cli`)
- Python 3.8+

## Current Environment

This TDX VM is running on:
- **Platform**: Google Cloud Platform (GCP)
- **VM Type**: Confidential VM with Intel TDX
- **TDX Device**: `/dev/tdx_guest`
- **Attestation Service**: Intel Trust Authority

## Verification Steps

### 1. Check TDX Device

```bash
# Verify TDX device exists
ls -la /dev/tdx_guest
# Expected: crw------- 1 root root 10, 121 ... /dev/tdx_guest
```

### 2. Check Intel Trust Authority CLI

```bash
# Verify CLI is installed
which trustauthority-cli
# Expected: /usr/local/bin/trustauthority-cli

# Check version
trustauthority-cli version
```

### 3. Check Configuration

```bash
# View config file
cat ~/config.json
```

Expected format:
```json
{
  "trustauthority_api_url": "https://api.trustauthority.intel.com",
  "trustauthority_api_key": "your-api-key-here"
}
```

### 4. Test Evidence Generation

```bash
# Generate TDX evidence (requires root)
sudo trustauthority-cli evidence --tdx -c ~/config.json
```

This should output a JSON with:
- `tdx.quote`: Base64-encoded TDX quote
- `verifier_nonce`: Nonce from Intel TA

### 5. Test Token Generation

```bash
# Get verified attestation token
sudo trustauthority-cli token --tdx -c ~/config.json
```

This should output:
- Debug logs showing HTTP requests
- JWT token starting with `eyJ...`

## Intel Trust Authority Configuration

### API Key
The API key in `~/config.json` is used to authenticate with Intel Trust Authority:
- Obtain from Intel Trust Authority portal
- Has rate limits (see Troubleshooting)
- Tied to your Intel account/organization

### Endpoints Used
- `GET /appraisal/v2/nonce` - Get challenge nonce
- `POST /appraisal/v2/attest` - Submit quote, get token

## File Permissions

```bash
# TDX device requires root access
sudo chmod 660 /dev/tdx_guest  # If needed

# Config file can be user-readable
chmod 644 ~/config.json
```

## Network Requirements

The TDX VM needs outbound HTTPS access to:
- `api.trustauthority.intel.com` (Intel Trust Authority)

## Python Module Setup

### Installation

No additional packages required. The module uses:
- `subprocess` - For calling trustauthority-cli
- `json`, `base64` - For parsing tokens
- `socket` - For network communication

### Quick Test

```bash
cd /home/nkoirala/sgx-tdx-composition-protocol/research/hierarchical-tee/tdx-layer/attestation
sudo python3 tdx_remote_attestation.py
```

Expected output:
```
======================================================================
TDX Remote Attestation Module - Demo
======================================================================

[1] Initializing TDX Attestor...
    ✓ TDX Attestor initialized successfully

[2] Generating TDX evidence (quote)...
    ✓ Evidence generated in ~200-500 ms
    Quote length: 10668 bytes (base64)

[3] Getting attestation token from Intel Trust Authority...
    ✓ Token received in ~400-500 ms
    Token length: 5934 bytes

[4] TDX Measurements:
    MRTD:        a5844e88897b70c318bef929ef4dfd6c...
    RTMR0:       cdd12631746b633b87592779e3118c95...
    Report Data: ...
    TCB Status:  OutOfDate
    Debuggable:  False

[5] Verifying token...
    ✓ Token appears valid
```

## Setting Up the Verifier (SGX Machine)

On your SGX machine (or any remote verifier):

```bash
# Copy the verifier service
scp tdx_verifier_service.py user@sgx-machine:~/

# Start the verifier
ssh user@sgx-machine
python3 tdx_verifier_service.py 9999
```

## Testing Remote Attestation

From this TDX VM:

```bash
sudo python3 tdx_attestation_client.py <SGX_MACHINE_IP> 9999
```

## Directory Structure After Setup

```
tdx-layer/attestation/
├── docs/
│   ├── README.md
│   ├── 01-overview.md
│   ├── 02-setup-guide.md (this file)
│   ├── 03-api-reference.md
│   ├── 04-usage-examples.md
│   ├── 05-sgx-integration.md
│   └── 06-troubleshooting.md
├── tdx_remote_attestation.py   # Main module
├── tdx_verifier_service.py     # Remote verifier
├── tdx_attestation_client.py   # Client script
├── tdx_attestation.py          # Legacy low-level
└── README.md                    # Quick reference
```
