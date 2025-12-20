# Gramine SGX Remote Attestation Demo

This directory contains a simple SGX remote attestation demo using the Gramine Library OS.
Unlike the SDK-based approach in `sgx_baseline/`, this uses Gramine's pseudo-filesystem
interface (`/dev/attestation`) to generate SGX quotes.

## Overview

Gramine provides a transparent way to run unmodified applications inside SGX enclaves.
For remote attestation, it exposes a special `/dev/attestation` pseudo-filesystem that
allows applications to:

1. Write custom user data to `/dev/attestation/user_report_data`
2. Read the attestation quote from `/dev/attestation/quote`
3. Verify the attestation type via `/dev/attestation/attestation_type`

## Prerequisites

- Gramine 1.9+ installed (check with `gramine-sgx --version`)
- Intel SGX DCAP configured and working
- AESM service running (`systemctl status aesmd`)
- Signing key generated (`~/.config/gramine/enclave-key.pem`)

## Files

| File | Description |
|------|-------------|
| `attestation_demo.py` | Python script that generates SGX quote inside Gramine enclave |
| `attestation.manifest.template` | Gramine manifest template for the Python app |
| `Makefile` | Build and run commands |
| `verify_quote.py` | Quote verification script (runs outside enclave) |
| `attestation.manifest` | Generated manifest (created by `make`) |
| `attestation.manifest.sgx` | Signed manifest for SGX (created by `make`) |
| `attestation.sig` | Enclave signature structure (created by `make`) |
| `quote.bin` | Generated SGX quote (created by `make run-sgx`) |

## Quick Start

```bash
# 1. Check your setup
make check-setup

# 2. Build the Gramine manifest and sign (takes a few minutes)
make

# 3. Run the attestation demo inside SGX enclave
make run-sgx

# 4. View the generated quote
make view-quote

# 5. Verify the quote
make verify

# 6. Clean up
make clean
```

## Performance Results

Tested on `tjws-06` with Gramine 1.9:

| Metric | Value |
|--------|-------|
| Average quote generation | 10.69 ms |
| Min | 10.59 ms |
| Max | 10.83 ms |
| Quote size | 1456 bytes |

To run the benchmark:
```bash
make benchmark
```

## How It Works

1. **Gramine wraps Python** - The Python interpreter runs inside an SGX enclave
2. **Quote generation** - The script writes user data to `/dev/attestation/user_report_data`
   and reads the quote from `/dev/attestation/quote`
3. **Quote saved** - The binary quote is saved to `quote.bin` for verification
4. **Verification** - Use `gramine-sgx-quote-view` or the `verify_quote.py` script

## Enclave Measurements

After building, you can view the enclave measurements:

```bash
$ gramine-sgx-sigstruct-view attestation.sig
Attributes:
    mr_signer: 3ca59c440a720c7bb9dd4c86da5567bb98570a964b0f74ed553e6b2c44e87cbf
    mr_enclave: 05b8e0fe8118ceb23099e92fb9be99d154a043d62626624cf0e9de40390cf0e3
    isv_prod_id: 0
    isv_svn: 0
    debug_enclave: True
```

## Comparison with SDK Approach

| Aspect | Intel SGX SDK | Gramine |
|--------|--------------|---------|
| Language | C/C++ only | Any (Python, Java, Go, etc.) |
| Complexity | High (ECALL/OCALL) | Low (file I/O) |
| Code changes | Significant | Minimal |
| Performance | Slightly faster | Small overhead (~10ms) |
| Flexibility | More control | Easier development |
| Quote generation | ~10ms with SDK | ~10ms with Gramine |

## For Hierarchical Attestation

This quote can be used in the hierarchical attestation flow:

1. **SGX enclave generates quote** (this demo)
2. **Quote is sent to TDX VM**
3. **TDX VM binds SGX quote with TDX token**
4. **Combined evidence sent to cloud verifier**

The user report data (64 bytes) can be used to bind the SGX quote to the TDX attestation:
- Include a hash of TDX-specific data in the user report data
- Or include a nonce/challenge for the hierarchical protocol

## Production Notes

⚠️ **This demo uses debug settings. For production:**

1. Set `sgx.debug = false` in the manifest
2. Remove `loader.insecure__use_cmdline_argv` or handle arguments securely
3. Review and minimize `sgx.allowed_files`
4. Use proper ISV product ID and SVN values
5. Implement proper quote verification with DCAP libraries

## Troubleshooting

### Manifest generation is slow
This is normal - Gramine hashes all trusted files (Python libraries, etc.). It takes 2-3 minutes.

### Quote generation fails
Check that:
- AESM service is running: `systemctl status aesmd`
- PCCS is configured: `cat /etc/sgx_default_qcnl.conf`
- SGX device is accessible: `ls -la /dev/sgx_enclave`

### "Attestation type: none"
Make sure `sgx.remote_attestation = "dcap"` is in the manifest template.
