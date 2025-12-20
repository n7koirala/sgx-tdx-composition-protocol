# SGX Remote Attestation with Gramine: A Complete Guide

This document provides a comprehensive, step-by-step guide on how to configure and implement
SGX remote attestation using the Gramine Library OS. It covers the theory, setup process,
code implementation, and verification.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Background Concepts](#2-background-concepts)
3. [Prerequisites](#3-prerequisites)
4. [Architecture Overview](#4-architecture-overview)
5. [Step-by-Step Setup](#5-step-by-step-setup)
6. [Code Walkthrough](#6-code-walkthrough)
7. [Building and Running](#7-building-and-running)
8. [Quote Verification](#8-quote-verification)
9. [Troubleshooting](#9-troubleshooting)
10. [Production Considerations](#10-production-considerations)

---

## 1. Introduction

### What is Gramine?

Gramine (formerly Graphene-SGX) is a **Library OS** that allows running unmodified Linux 
applications inside Intel SGX enclaves. Unlike the traditional Intel SGX SDK approach, 
Gramine doesn't require partitioning your application into trusted and untrusted components.

### Why Use Gramine for Remote Attestation?

| Traditional SGX SDK | Gramine Approach |
|---------------------|------------------|
| Requires C/C++ | Works with any language (Python, Java, Go, etc.) |
| Complex ECALL/OCALL interface | Simple file I/O operations |
| Significant code restructuring | Minimal code changes |
| Steep learning curve | Easier to adopt |
| Fine-grained control | Higher-level abstractions |

### What We'll Achieve

By the end of this guide, you'll have:
- A Python application running inside an SGX enclave
- The ability to generate SGX DCAP quotes
- A verification script to parse and validate quotes
- Understanding of how Gramine handles attestation

---

## 2. Background Concepts

### 2.1 Intel SGX Basics

**Intel Software Guard Extensions (SGX)** is a set of CPU instructions that allow:
- Creating isolated memory regions called **enclaves**
- Protecting code and data from even privileged software
- Proving enclave identity through **remote attestation**

### 2.2 Remote Attestation

Remote attestation allows a remote party to verify:
1. The enclave is running on genuine Intel hardware
2. The enclave code hasn't been tampered with (via MRENCLAVE)
3. The enclave was signed by a known party (via MRSIGNER)

### 2.3 DCAP vs EPID

Intel provides two attestation schemes:

| DCAP (Datacenter Attestation Primitives) | EPID (Enhanced Privacy ID) |
|------------------------------------------|----------------------------|
| For datacenter/cloud environments | For client machines |
| Third-party attestation servers | Intel Attestation Service |
| More flexible deployment | Privacy-preserving |
| **Currently supported** | **End of life (EOL)** |

Gramine supports **DCAP-based attestation**, which is the modern approach.

### 2.4 Key SGX Measurements

| Measurement | Description |
|-------------|-------------|
| **MRENCLAVE** | SHA-256 hash of enclave code, data, and layout. Changes if any code changes. |
| **MRSIGNER** | SHA-256 hash of the enclave signing key. Identifies who signed the enclave. |
| **ISV_PROD_ID** | Product ID set by the enclave developer (0-65535) |
| **ISV_SVN** | Security Version Number, incremented for security updates |

### 2.5 Gramine's /dev/attestation Interface

Gramine exposes attestation through a pseudo-filesystem:

```
/dev/attestation/
├── attestation_type     # "dcap" or "none"
├── user_report_data     # Write: 64 bytes of custom data
├── quote                # Read: The SGX quote
├── target_info          # For local attestation
├── my_target_info       # This enclave's target info
└── report               # SGX report (for local attestation)
```

The typical remote attestation flow:
1. Write 64 bytes to `/dev/attestation/user_report_data`
2. Read from `/dev/attestation/quote` → triggers quote generation
3. Send the quote to a remote verifier

---

## 3. Prerequisites

### 3.1 Hardware Requirements

- Intel CPU with SGX support (6th generation Core or newer)
- SGX enabled in BIOS/UEFI
- Sufficient EPC (Enclave Page Cache) memory

### 3.2 Software Requirements

Check your system meets these requirements:

```bash
# 1. Verify Gramine is installed
gramine-sgx --version
# Expected: Gramine 1.9 or higher

# 2. Check SGX device exists
ls -la /dev/sgx_enclave
# Expected: crw-rw---- 1 root sgx ...

# 3. Verify user is in SGX group
groups | grep sgx
# Should include 'sgx'

# 4. Check AESM service is running
systemctl status aesmd
# Expected: active (running)

# 5. Verify signing key exists
ls ~/.config/gramine/enclave-key.pem
# If missing, generate with: gramine-sgx-gen-private-key

# 6. Check DCAP libraries
ldconfig -p | grep dcap_quoteverify
# Expected: libsgx_dcap_quoteverify.so ...
```

### 3.3 PCCS Configuration

The Provisioning Certificate Caching Service (PCCS) provides Intel's attestation certificates.
Check your configuration:

```bash
cat /etc/sgx_default_qcnl.conf
```

Key settings:
```json
{
  "pccs_url": "https://api.trustedservices.intel.com/sgx/certification/v4/",
  "use_secure_cert": true
}
```

You can use:
- **Intel's direct API** (no local PCCS needed)
- **Local PCCS instance** (better performance, caching)

---

## 4. Architecture Overview

### 4.1 System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Host System (Linux)                          │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    SGX Enclave                                │  │
│  │  ┌─────────────────────────────────────────────────────────┐ │  │
│  │  │                  Gramine LibOS                          │ │  │
│  │  │  ┌──────────────────────────────────────────────────┐  │ │  │
│  │  │  │          attestation_demo.py                     │  │ │  │
│  │  │  │                                                  │  │ │  │
│  │  │  │  1. Write to /dev/attestation/user_report_data   │  │ │  │
│  │  │  │  2. Read from /dev/attestation/quote             │  │ │  │
│  │  │  │  3. Save quote.bin                               │  │ │  │
│  │  │  └──────────────────────────────────────────────────┘  │ │  │
│  │  │                         │                               │ │  │
│  │  │                    Gramine PAL                          │ │  │
│  │  └─────────────────────────┼───────────────────────────────┘ │  │
│  │                            │ EREPORT instruction             │  │
│  └────────────────────────────┼─────────────────────────────────┘  │
│                               │                                    │
│  ┌────────────────────────────▼─────────────────────────────────┐  │
│  │                  Quoting Enclave (QE)                         │  │
│  │  - Verifies EREPORT from application enclave                 │  │
│  │  - Signs the report with attestation key                     │  │
│  │  - Returns SGX Quote                                         │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                               │                                    │
│  ┌────────────────────────────▼─────────────────────────────────┐  │
│  │                  AESM Service                                 │  │
│  │  - Manages architectural enclaves (QE, PCE)                  │  │
│  │  - Handles quote generation requests                         │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Intel PCS / PCCS  │
                    │  (Certificate Chain)│
                    └─────────────────────┘
```

### 4.2 Quote Generation Flow

```
Application                 Gramine              Quoting Enclave        PCCS
    │                          │                       │                  │
    │ write(user_report_data)  │                       │                  │
    │─────────────────────────>│                       │                  │
    │                          │                       │                  │
    │ read(quote)              │                       │                  │
    │─────────────────────────>│                       │                  │
    │                          │ EREPORT              │                  │
    │                          │──────────────────────>│                  │
    │                          │                       │                  │
    │                          │                       │ Get certificates │
    │                          │                       │─────────────────>│
    │                          │                       │<─────────────────│
    │                          │                       │                  │
    │                          │ SGX Quote             │                  │
    │                          │<──────────────────────│                  │
    │                          │                       │                  │
    │ quote bytes              │                       │                  │
    │<─────────────────────────│                       │                  │
```

---

## 5. Step-by-Step Setup

### Step 1: Create Project Directory

```bash
mkdir -p gramine_attestation
cd gramine_attestation
```

### Step 2: Create the Python Attestation Script

Create `attestation_demo.py`:

```python
#!/usr/bin/env python3
"""
SGX Remote Attestation Demo using Gramine's /dev/attestation interface.
"""

import os
import sys
import time

ATTESTATION_DIR = "/dev/attestation"
USER_REPORT_DATA_SIZE = 64

def main():
    # Step 1: Verify we're inside an enclave
    if not os.path.exists(ATTESTATION_DIR):
        print("Error: Not running inside Gramine SGX enclave")
        return 1
    
    # Step 2: Check attestation type
    with open(f"{ATTESTATION_DIR}/attestation_type", "r") as f:
        att_type = f.read().strip()
    print(f"Attestation type: {att_type}")
    
    if att_type != "dcap":
        print("Error: DCAP attestation not available")
        return 1
    
    # Step 3: Write user report data (64 bytes)
    user_data = b"My-Custom-Data-For-Attestation".ljust(64, b'\x00')
    with open(f"{ATTESTATION_DIR}/user_report_data", "wb") as f:
        f.write(user_data)
    print(f"User report data written ({len(user_data)} bytes)")
    
    # Step 4: Read the quote (this triggers quote generation)
    start = time.time()
    with open(f"{ATTESTATION_DIR}/quote", "rb") as f:
        quote = f.read()
    elapsed = (time.time() - start) * 1000
    print(f"Quote generated in {elapsed:.2f} ms ({len(quote)} bytes)")
    
    # Step 5: Save the quote
    with open("quote.bin", "wb") as f:
        f.write(quote)
    print("Quote saved to quote.bin")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

### Step 3: Create the Gramine Manifest Template

Create `attestation.manifest.template`:

```toml
# Gramine Manifest for SGX Remote Attestation

# Entry point: the Python interpreter
libos.entrypoint = "{{ python_path }}"

# Enable command-line arguments
loader.insecure__use_cmdline_argv = true

# Environment variables
loader.env.LD_LIBRARY_PATH = "/lib:{{ arch_libdir }}:/usr/lib:/usr/{{ arch_libdir }}"
loader.env.HOME = "/home/user"
loader.log_level = "{{ log_level }}"

# Filesystem mounts
fs.mounts = [
    { path = "/lib", uri = "file:{{ gramine.runtimedir() }}" },
    { path = "{{ arch_libdir }}", uri = "file:{{ arch_libdir }}" },
    { path = "/usr/{{ arch_libdir }}", uri = "file:/usr/{{ arch_libdir }}" },
    { path = "/usr/lib", uri = "file:/usr/lib" },
    { path = "{{ python_path }}", uri = "file:{{ python_path }}" },
    { path = "/usr/lib/python{{ python_version }}", uri = "file:/usr/lib/python{{ python_version }}" },
    { path = "/usr/lib/python3/dist-packages", uri = "file:/usr/lib/python3/dist-packages" },
    { path = "/usr/lib/python3", uri = "file:/usr/lib/python3" },
    { path = "/etc", uri = "file:/etc" },
    { path = "/app", uri = "file:." },
    { type = "tmpfs", path = "/tmp" },
]

# ============ SGX Configuration ============

# Enable DCAP remote attestation (CRITICAL!)
sgx.remote_attestation = "dcap"

# Debug mode - set to false for production
sgx.debug = true

# Enclave size (Python needs at least 512MB)
sgx.enclave_size = "1G"

# Thread configuration
sgx.max_threads = 32

# ISV Product ID and Security Version
sgx.isvprodid = 0
sgx.isvsvn = 0

# ============ Trusted Files ============
# These files are measured and included in MRENCLAVE

sgx.trusted_files = [
    "file:{{ python_path }}",
    "file:{{ gramine.runtimedir() }}/",
    "file:{{ arch_libdir }}/",
    "file:/usr/{{ arch_libdir }}/",
    "file:/usr/lib/python{{ python_version }}/",
    "file:/usr/lib/python3/dist-packages/",
    "file:/usr/lib/python3/",
    "file:attestation_demo.py",
]

# ============ Allowed Files ============
# These files can be accessed but are NOT measured

sgx.allowed_files = [
    "file:/etc/nsswitch.conf",
    "file:/etc/hosts",
    "file:/etc/passwd",
    "file:/etc/group",
    "file:/etc/localtime",
    "file:quote.bin",  # Output file
]

# System configuration
sys.stack.size = "2M"
sys.enable_sigterm_injection = true
```

### Step 4: Create the Makefile

Create `Makefile`:

```makefile
PYTHON_VERSION := $(shell python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_PATH := $(shell which python3)
ARCH_LIBDIR := /lib/$(shell gcc -dumpmachine)
SGX_SIGNING_KEY ?= $(HOME)/.config/gramine/enclave-key.pem
LOG_LEVEL ?= error

all: attestation.manifest.sgx

# Generate manifest from template
attestation.manifest: attestation.manifest.template attestation_demo.py
	gramine-manifest \
		-Dlog_level=$(LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dpython_path=$(PYTHON_PATH) \
		-Dpython_version=$(PYTHON_VERSION) \
		$< $@

# Sign the manifest
attestation.manifest.sgx attestation.sig: attestation.manifest
	gramine-sgx-sign \
		--manifest $< \
		--key $(SGX_SIGNING_KEY) \
		--output $<.sgx

# Run inside SGX
run-sgx: all
	gramine-sgx ./attestation attestation_demo.py

# View quote
view-quote: quote.bin
	gramine-sgx-quote-view quote.bin

clean:
	rm -f attestation.manifest attestation.manifest.sgx attestation.sig quote.bin
```

### Step 5: Build the Enclave

```bash
# Generate manifest and sign
make

# This produces:
# - attestation.manifest      (generated manifest with file hashes)
# - attestation.manifest.sgx  (signed manifest)
# - attestation.sig           (signature structure)
```

**Note:** This step takes 2-3 minutes because Gramine hashes all trusted files
(Python interpreter, libraries, etc.).

### Step 6: Run the Attestation Demo

```bash
make run-sgx
```

Expected output:
```
Gramine is starting. Parsing TOML manifest file, this may take some time...
-----------------------------------------------------------------------------------------------------------------------
Gramine detected the following insecure configurations:

  - sgx.debug = true                           (this is a debug enclave)
  - loader.insecure__use_cmdline_argv = true   (forwarding command-line args)
  - sgx.allowed_files = [ ... ]                (some files passed through)

Gramine will continue application execution, but this configuration must not be used in production!
-----------------------------------------------------------------------------------------------------------------------

Attestation type: dcap
User report data written (64 bytes)
Quote generated in 10.69 ms (1456 bytes)
Quote saved to quote.bin
```

---

## 6. Code Walkthrough

### 6.1 The Attestation Script (attestation_demo.py)

```python
# The key operations are:

# 1. CHECK ATTESTATION AVAILABILITY
if not os.path.exists("/dev/attestation"):
    # Not running inside Gramine SGX enclave
    return

# 2. VERIFY ATTESTATION TYPE
with open("/dev/attestation/attestation_type", "r") as f:
    att_type = f.read().strip()  # Should be "dcap"

# 3. WRITE USER REPORT DATA
# This is 64 bytes that gets embedded in the quote
# Typically contains a hash of application-specific data
user_data = b"custom-data".ljust(64, b'\x00')
with open("/dev/attestation/user_report_data", "wb") as f:
    f.write(user_data)

# 4. READ THE QUOTE
# This triggers the actual quote generation:
# - Gramine executes EREPORT instruction
# - Communicates with Quoting Enclave
# - Returns signed quote
with open("/dev/attestation/quote", "rb") as f:
    quote = f.read()

# 5. SAVE/SEND THE QUOTE
# The quote can now be sent to a remote verifier
```

### 6.2 The Manifest (attestation.manifest.template)

Key configuration options explained:

```toml
# CRITICAL: Enable DCAP attestation
sgx.remote_attestation = "dcap"
# Without this, /dev/attestation/quote won't work

# Debug mode allows debugging but is INSECURE
sgx.debug = true
# Set to false for production

# Enclave memory size
sgx.enclave_size = "1G"
# Python needs substantial memory

# Files included in measurement (MRENCLAVE)
sgx.trusted_files = [
    "file:attestation_demo.py",
    # ... libraries
]
# Changes to these files change MRENCLAVE

# Files accessible but not measured
sgx.allowed_files = [
    "file:quote.bin",
]
# Can be modified without changing MRENCLAVE
```

### 6.3 Understanding the Quote Structure

An SGX DCAP quote (v3) contains:

```
┌────────────────────────────────────────────────────────────────────┐
│ Quote Header (48 bytes)                                            │
│ ├─ Version (2 bytes): 0x0003                                       │
│ ├─ Attestation Key Type (2 bytes): 0x0002 (ECDSA-256-P256)        │
│ ├─ Reserved (4 bytes)                                              │
│ ├─ QE SVN (2 bytes)                                                │
│ ├─ PCE SVN (2 bytes)                                               │
│ ├─ QE Vendor ID (16 bytes): Intel's UUID                          │
│ └─ User Data (20 bytes)                                            │
├────────────────────────────────────────────────────────────────────┤
│ Report Body (384 bytes)                                            │
│ ├─ CPU SVN (16 bytes)                                              │
│ ├─ Attributes (16 bytes): Flags like DEBUG, MODE64BIT              │
│ ├─ MRENCLAVE (32 bytes): Hash of enclave code/data                │
│ ├─ MRSIGNER (32 bytes): Hash of signing key                       │
│ ├─ ISV Prod ID (2 bytes)                                           │
│ ├─ ISV SVN (2 bytes)                                               │
│ └─ Report Data (64 bytes): YOUR USER REPORT DATA                  │
├────────────────────────────────────────────────────────────────────┤
│ Signature (variable size)                                          │
│ ├─ ECDSA signature over header + report body                      │
│ ├─ Attestation public key                                          │
│ └─ Certificate chain (QE cert → PCK cert → Intel root)            │
└────────────────────────────────────────────────────────────────────┘
```

---

## 7. Building and Running

### 7.1 Full Build Process

```bash
# 1. Check prerequisites
make check-setup

# 2. Clean any previous builds
make clean

# 3. Build (takes ~2-3 minutes)
make

# 4. View enclave measurements
gramine-sgx-sigstruct-view attestation.sig

# 5. Run the demo
make run-sgx

# 6. View the generated quote
make view-quote
```

### 7.2 What Happens During Build

1. **gramine-manifest**:
   - Processes the template
   - Resolves `{{ variable }}` placeholders
   - Computes SHA-256 hashes of all trusted files
   - Generates the final manifest (~8MB)

2. **gramine-sgx-sign**:
   - Calculates MRENCLAVE from manifest
   - Signs with your private key
   - Generates MRSIGNER from your public key
   - Creates `.manifest.sgx` and `.sig` files

### 7.3 What Happens During Runtime

1. **gramine-sgx** starts
2. Loads and parses the manifest
3. Creates the SGX enclave
4. Loads Gramine LibOS into enclave
5. Gramine sets up `/dev/attestation`
6. Your Python script executes
7. Writing to `/dev/attestation/user_report_data` stores the data
8. Reading `/dev/attestation/quote`:
   - Gramine calls EREPORT
   - Contacts Quoting Enclave via AESM
   - Returns the quote to your application

---

## 8. Quote Verification

### 8.1 Using Gramine's Tool

```bash
gramine-sgx-quote-view quote.bin
```

Output shows:
```
report_body       :
 mr_enclave       : 05b8e0fe8118ceb23099e92fb9be99d154a043d62626624cf0e9de40390cf0e3
 mr_signer        : 3ca59c440a720c7bb9dd4c86da5567bb98570a964b0f74ed553e6b2c44e87cbf
 isv_prod_id      : 0000
 isv_svn          : 0000
 report_data      : 48696572617263686963616c2d5445452d53... (your user data in hex)
```

### 8.2 Using the Python Verification Script

```bash
python3 verify_quote.py quote.bin
```

### 8.3 Full DCAP Verification

For cryptographic verification, use Intel's DCAP libraries:

```c
#include <sgx_dcap_quoteverify.h>

// Pseudocode
quote3_error_t ret = sgx_qv_verify_quote(
    quote_buffer,
    quote_size,
    NULL,  // Use default QVL
    current_time,
    &collateral_expiration_status,
    &quote_verification_result,
    NULL,
    &supp_data_size,
    NULL
);
```

This verifies:
- Quote signature is valid
- Certificates chain to Intel root
- TCB status (up to date vs outdated)

---

## 9. Troubleshooting

### Problem: "Failed to get target info from QE"

**Cause:** AESM service not running or misconfigured

**Solution:**
```bash
sudo systemctl restart aesmd
sudo systemctl status aesmd
```

### Problem: "Attestation type: none"

**Cause:** `sgx.remote_attestation` not set in manifest

**Solution:** Ensure your manifest has:
```toml
sgx.remote_attestation = "dcap"
```

### Problem: Quote generation fails with error

**Cause:** PCCS/PCS not accessible

**Solution:**
```bash
# Check QCNL config
cat /etc/sgx_default_qcnl.conf

# Test connectivity
curl -v https://api.trustedservices.intel.com/sgx/certification/v4/
```

### Problem: Manifest generation very slow

**Cause:** Gramine hashes all trusted files

**Solution:** This is normal (2-3 minutes). Reduce trusted files if possible.

### Problem: Enclave creation fails with "out of EPC"

**Cause:** Enclave too large for available EPC memory

**Solution:** Reduce `sgx.enclave_size` or `sgx.max_threads`

---

## 10. Production Considerations

### 10.1 Security Hardening

```toml
# 1. Disable debug mode
sgx.debug = false

# 2. Don't allow arbitrary command line
# Remove: loader.insecure__use_cmdline_argv = true

# 3. Minimize allowed files
sgx.allowed_files = []  # Only what's absolutely necessary

# 4. Set meaningful ISV values
sgx.isvprodid = 1  # Your product ID
sgx.isvsvn = 1     # Increment for security updates
```

### 10.2 Quote Verification Checklist

When verifying a quote, check:
- [ ] Quote signature is valid (DCAP verification)
- [ ] MRENCLAVE matches expected value
- [ ] MRSIGNER matches your signing key's hash
- [ ] Debug flag is FALSE
- [ ] ISV_PROD_ID and ISV_SVN are acceptable
- [ ] TCB status is acceptable
- [ ] User report data matches expected value

### 10.3 Key Management

- Keep your signing key (`enclave-key.pem`) secure
- Use different keys for development and production
- Consider using HSM for production keys

### 10.4 For Hierarchical Attestation

To use this quote in hierarchical attestation (SGX → TDX → Cloud):

1. Include TDX-related data in user report data
2. Send the SGX quote to the TDX VM
3. TDX VM creates a binding between SGX quote and TDX token
4. Combined evidence goes to the cloud verifier

Example user report data for binding:
```python
# Include hash of TDX public key or nonce
binding_data = hashlib.sha512(tdx_public_key + nonce).digest()
# Write to /dev/attestation/user_report_data
```

---

## Appendix: Quick Reference

### Commands

```bash
# Check setup
make check-setup

# Build
make clean && make

# Run
make run-sgx

# View quote
make view-quote

# View enclave measurements
gramine-sgx-sigstruct-view attestation.sig
```

### Key Files

| File | Purpose |
|------|---------|
| `attestation.manifest.template` | Configuration template |
| `attestation.manifest` | Generated manifest with hashes |
| `attestation.manifest.sgx` | Signed manifest for SGX |
| `attestation.sig` | Signature structure (MRENCLAVE, etc.) |
| `quote.bin` | Generated SGX quote |
| `~/.config/gramine/enclave-key.pem` | Your signing key |

### Performance Baseline

| Metric | Value |
|--------|-------|
| Quote generation time | ~10 ms |
| Quote size | ~1.4 KB (1456 bytes) |
| Manifest generation | 2-3 minutes |

---

*Document created: December 2024*
*Environment: Gramine 1.9, Ubuntu 22.04, Intel SGX DCAP*
