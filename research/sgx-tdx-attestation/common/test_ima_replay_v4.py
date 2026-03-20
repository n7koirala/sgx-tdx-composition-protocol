#!/usr/bin/env python3
"""
IMA PCR 10 Replay v4 — SHA-1 vs SHA-256 Bank Comparison

Verifies both PCR banks to isolate the exact issue:
- SHA-1 bank:   extend with SHA-1 template hash from binary log (direct)
- SHA-256 bank: extend with SHA-256(template_data) computed from binary log

If SHA-1 matches but SHA-256 doesn't, the extend formula is correct but
the SHA-256 template hash computation differs from what the kernel uses.

Also validates EVERY entry's SHA-1 to detect any data corruption.

Usage:
    sudo python3 test_ima_replay_v4.py
"""

import hashlib
import struct
import sys

IMA_BINARY_LOG_PATH = "/sys/kernel/security/ima/binary_runtime_measurements"
PCR10_SHA1_PATH = "/sys/class/tpm/tpm0/pcr-sha1/10"
PCR10_SHA256_PATH = "/sys/class/tpm/tpm0/pcr-sha256/10"


def parse_binary_log(data):
    """Parse IMA binary log entries."""
    offset = 0
    while offset < len(data):
        if offset + 4 > len(data): break
        pcr = struct.unpack_from('<I', data, offset)[0]; offset += 4
        
        if offset + 20 > len(data): break
        sha1_hash = data[offset:offset + 20]; offset += 20
        
        if offset + 4 > len(data): break
        name_len = struct.unpack_from('<I', data, offset)[0]; offset += 4
        if offset + name_len > len(data): break
        template_name = data[offset:offset + name_len].decode('ascii', errors='replace')
        offset += name_len
        
        if offset + 4 > len(data): break
        data_len = struct.unpack_from('<I', data, offset)[0]; offset += 4
        if offset + data_len > len(data): break
        template_data = data[offset:offset + data_len]; offset += data_len
        
        yield pcr, sha1_hash, template_name, template_data


def main():
    print("=" * 60)
    print("IMA PCR 10 Replay v4 — SHA-1 vs SHA-256 Bank")
    print("=" * 60)
    
    # Read actual PCR values for BOTH banks
    print("\n[1] Reading actual PCR 10 from both banks...")
    
    actual_sha1 = ""
    try:
        with open(PCR10_SHA1_PATH, 'r') as f:
            actual_sha1 = f.read().strip().lower()
        print(f"    SHA-1 bank:   {actual_sha1}")
    except Exception as e:
        print(f"    SHA-1 bank:   Error: {e}")
    
    try:
        with open(PCR10_SHA256_PATH, 'r') as f:
            actual_sha256 = f.read().strip().lower()
        print(f"    SHA-256 bank: {actual_sha256}")
    except Exception as e:
        print(f"    SHA-256 bank: Error: {e}")
    
    # Read binary IMA log
    print(f"\n[2] Reading binary IMA log...")
    with open(IMA_BINARY_LOG_PATH, 'rb') as f:
        binary_data = f.read()
    
    # Re-read PCR values (check stability)
    with open(PCR10_SHA1_PATH, 'r') as f:
        actual_sha1_after = f.read().strip().lower()
    with open(PCR10_SHA256_PATH, 'r') as f:
        actual_sha256_after = f.read().strip().lower()
    
    if actual_sha1 != actual_sha1_after or actual_sha256 != actual_sha256_after:
        print("    ⚠ PCR values changed during read!")
        actual_sha1 = actual_sha1_after
        actual_sha256 = actual_sha256_after
    else:
        print("    ✓ PCR values stable")
    
    # Replay BOTH banks simultaneously
    print(f"\n[3] Replaying IMA log for both PCR banks...")
    
    pcr10_sha1 = b'\x00' * 20    # SHA-1 PCR bank (20 bytes)  
    pcr10_sha256 = b'\x00' * 32  # SHA-256 PCR bank (32 bytes)
    
    entry_count = 0
    sha1_mismatches = 0
    
    for pcr, sha1_hash, template_name, template_data in parse_binary_log(binary_data):
        if pcr != 10:
            continue
        
        # Verify SHA-1 of template_data matches the logged hash
        sha1_computed = hashlib.sha1(template_data).digest()
        if sha1_computed != sha1_hash:
            sha1_mismatches += 1
            if sha1_mismatches <= 3:
                print(f"    *** SHA-1 MISMATCH at entry {entry_count + 1}! ***")
                print(f"        Template: {template_name}")
                print(f"        Logged:   {sha1_hash.hex()}")
                print(f"        Computed: {sha1_computed.hex()}")
                print(f"        Data len: {len(template_data)}")
        
        # SHA-1 bank: extend with the logged SHA-1 hash directly
        # PCR10_sha1 = SHA-1(PCR10_sha1 || SHA-1_template_hash)
        pcr10_sha1 = hashlib.sha1(pcr10_sha1 + sha1_hash).digest()
        
        # SHA-256 bank: extend with SHA-256(template_data) 
        sha256_tmpl = hashlib.sha256(template_data).digest()
        pcr10_sha256 = hashlib.sha256(pcr10_sha256 + sha256_tmpl).digest()
        
        entry_count += 1
    
    print(f"\n[4] Results ({entry_count} entries):")
    print(f"    SHA-1 data integrity: {entry_count - sha1_mismatches}/{entry_count} entries OK")
    
    # SHA-1 bank
    computed_sha1 = pcr10_sha1.hex()
    sha1_match = computed_sha1 == actual_sha1
    print(f"\n    SHA-1 PCR bank:")
    print(f"      Computed: {computed_sha1}")
    print(f"      Actual:   {actual_sha1}")
    print(f"      Match:    {'✓ YES' if sha1_match else '✗ NO'}")
    
    # SHA-256 bank  
    computed_sha256 = pcr10_sha256.hex()
    sha256_match = computed_sha256 == actual_sha256
    print(f"\n    SHA-256 PCR bank:")
    print(f"      Computed: {computed_sha256}")
    print(f"      Actual:   {actual_sha256}")
    print(f"      Match:    {'✓ YES' if sha256_match else '✗ NO'}")
    
    # Diagnosis
    print(f"\n[5] Diagnosis:")
    if sha1_match and sha256_match:
        print("    ✓ Both banks match! Algorithm is correct.")
    elif sha1_match and not sha256_match:
        print("    SHA-1 matches but SHA-256 doesn't.")
        print("    → The extend formula is correct.")
        print("    → The SHA-256 template hash computation differs from kernel.")
        print("    → Kernel may NOT be using SHA-256(template_data) for this bank.")
    elif not sha1_match and not sha256_match:
        print("    Neither bank matches!")
        print("    → Possible binary log read corruption or concurrent modification.")
        print(f"    → SHA-1 mismatches in data: {sha1_mismatches}")
    else:
        print("    SHA-256 matches but SHA-1 doesn't (unexpected!).")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
