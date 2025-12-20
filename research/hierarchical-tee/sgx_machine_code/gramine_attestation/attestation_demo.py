#!/usr/bin/env python3
"""
Gramine SGX Remote Attestation Demo

This script demonstrates how to perform SGX remote attestation using
Gramine's /dev/attestation pseudo-filesystem interface.

When run inside a Gramine SGX enclave, this script:
1. Checks the attestation type (should be 'dcap')
2. Writes custom user data to /dev/attestation/user_report_data
3. Reads the SGX quote from /dev/attestation/quote
4. Saves the quote to a file for later verification

Usage:
    gramine-sgx ./attestation_demo.py
"""

import os
import sys
import hashlib
import time
import struct
from pathlib import Path

# Constants
ATTESTATION_DIR = "/dev/attestation"
USER_REPORT_DATA_SIZE = 64  # SGX user report data is 64 bytes
SGX_QUOTE_MAX_SIZE = 8192   # Maximum quote size


def print_header():
    """Print demo header."""
    print("=" * 70)
    print("Gramine SGX Remote Attestation Demo")
    print("=" * 70)
    print()


def check_attestation_available():
    """Check if we're running inside a Gramine SGX enclave with attestation support."""
    if not os.path.exists(ATTESTATION_DIR):
        print("❌ Error: /dev/attestation not found!")
        print("   This script must be run inside a Gramine SGX enclave.")
        print("   Run with: gramine-sgx ./attestation_demo.py")
        return False
    
    print("✓ Running inside Gramine enclave")
    return True


def get_attestation_type():
    """Read the attestation type from Gramine."""
    type_path = os.path.join(ATTESTATION_DIR, "attestation_type")
    
    try:
        with open(type_path, "r") as f:
            att_type = f.read().strip()
        print(f"✓ Attestation type: {att_type}")
        return att_type
    except Exception as e:
        print(f"❌ Error reading attestation type: {e}")
        return None


def generate_user_report_data(custom_message: str = None):
    """
    Generate user report data to embed in the SGX quote.
    
    The user report data is typically a hash of application-specific data
    (like a public key or nonce) that ties the quote to the application.
    """
    if custom_message is None:
        # Create a unique identifier with timestamp
        custom_message = f"Gramine-RA-Demo-{int(time.time())}"
    
    # Create 64-byte user report data (padded or hashed)
    if len(custom_message) <= USER_REPORT_DATA_SIZE:
        # Pad short messages
        user_data = custom_message.encode('utf-8').ljust(USER_REPORT_DATA_SIZE, b'\x00')
    else:
        # Hash long messages
        user_data = hashlib.sha512(custom_message.encode('utf-8')).digest()
    
    return user_data, custom_message


def write_user_report_data(user_data: bytes):
    """Write user report data to the attestation pseudo-file."""
    report_data_path = os.path.join(ATTESTATION_DIR, "user_report_data")
    
    try:
        with open(report_data_path, "wb") as f:
            f.write(user_data)
        print(f"✓ User report data written ({len(user_data)} bytes)")
        return True
    except Exception as e:
        print(f"❌ Error writing user report data: {e}")
        return False


def read_sgx_quote():
    """
    Read the SGX quote from Gramine.
    
    After writing user_report_data, reading from /dev/attestation/quote
    triggers Gramine to:
    1. Generate an SGX EREPORT with the user data
    2. Send it to the Quoting Enclave
    3. Return the signed SGX Quote
    """
    quote_path = os.path.join(ATTESTATION_DIR, "quote")
    
    try:
        print("  Generating quote (communicating with Quoting Enclave)...")
        start_time = time.time()
        
        with open(quote_path, "rb") as f:
            quote = f.read()
        
        elapsed_time = (time.time() - start_time) * 1000  # Convert to ms
        print(f"✓ Quote generated in {elapsed_time:.2f} ms ({len(quote)} bytes)")
        return quote
    except Exception as e:
        print(f"❌ Error reading quote: {e}")
        return None


def parse_quote_header(quote: bytes):
    """
    Parse the SGX quote header to display key information.
    
    Quote structure (simplified):
    - Bytes 0-1: Version
    - Bytes 2-3: Attestation key type
    - Bytes 4-7: Reserved
    - Bytes 8-9: QE SVN
    - Bytes 10-11: PCE SVN
    - Bytes 12-27: QE Vendor ID
    - Bytes 28-47: User data
    - Bytes 48+: Report body
    """
    if len(quote) < 48:
        print("  Warning: Quote too short to parse header")
        return
    
    print("\nQuote Structure:")
    print("-" * 50)
    
    # Parse header fields
    version = struct.unpack("<H", quote[0:2])[0]
    att_key_type = struct.unpack("<H", quote[2:4])[0]
    
    print(f"  Version:           {version}")
    print(f"  Att Key Type:      {att_key_type} ({'ECDSA-256-P256' if att_key_type == 2 else 'Unknown'})")
    print(f"  Total Size:        {len(quote)} bytes")
    
    # Show first bytes of quote in hex
    print(f"  Header (hex):      {quote[:32].hex()}")
    
    # Extract MRENCLAVE from report body (offset varies by version)
    # In SGX DCAP quotes, report body starts at offset 48
    if len(quote) >= 112:
        # MRENCLAVE is at offset 64 from start of report body (48 + 64 = 112)
        # But actually in quote v3, the structure is different
        # Let's just show the general structure
        pass


def save_quote_to_file(quote: bytes, filename: str = "quote.bin"):
    """Save the quote to a binary file for later verification."""
    # Save to current working directory (outside enclave)
    # Gramine maps this to the host filesystem
    output_path = filename
    
    try:
        with open(output_path, "wb") as f:
            f.write(quote)
        print(f"✓ Quote saved to: {output_path}")
        return True
    except Exception as e:
        print(f"❌ Error saving quote: {e}")
        return False


def print_verification_instructions(quote_file: str):
    """Print instructions for verifying the generated quote."""
    print("\n" + "=" * 70)
    print("Verification Instructions")
    print("=" * 70)
    print(f"""
To verify this quote, you can use:

1. Gramine's quote viewer:
   $ gramine-sgx-quote-view {quote_file}

2. Intel DCAP verification (requires libsgx-dcap-quote-verify):
   - Use the quote verification APIs
   - Or use the verification script: python3 verify_quote.py {quote_file}

3. For hierarchical attestation:
   - Send this quote to the TDX VM
   - The TDX VM can bind it with the TDX token
   - Combined evidence goes to the cloud verifier
""")


def benchmark_quote_generation(iterations: int = 10):
    """Run multiple quote generations for benchmarking."""
    print(f"\nBenchmarking Quote Generation ({iterations} iterations)")
    print("-" * 50)
    
    times = []
    
    for i in range(iterations):
        # Generate unique user data each time
        user_data, _ = generate_user_report_data(f"benchmark-{i}-{time.time()}")
        
        # Write user data
        report_data_path = os.path.join(ATTESTATION_DIR, "user_report_data")
        with open(report_data_path, "wb") as f:
            f.write(user_data)
        
        # Time the quote generation
        quote_path = os.path.join(ATTESTATION_DIR, "quote")
        start = time.time()
        with open(quote_path, "rb") as f:
            quote = f.read()
        elapsed = (time.time() - start) * 1000
        times.append(elapsed)
        
        print(f"  [{i+1:2d}/{iterations}] {elapsed:7.2f} ms")
    
    avg = sum(times) / len(times)
    min_t = min(times)
    max_t = max(times)
    
    print(f"\n  Average: {avg:.2f} ms")
    print(f"  Min:     {min_t:.2f} ms")
    print(f"  Max:     {max_t:.2f} ms")
    print(f"  Quote size: {len(quote)} bytes")
    
    return avg


def main():
    """Main attestation demo flow."""
    print_header()
    
    # Step 1: Check if running in enclave
    print("[Step 1] Checking Attestation Environment")
    print("-" * 50)
    
    if not check_attestation_available():
        # Running outside enclave - show what would happen
        print("\n⚠ Running in simulation mode (outside enclave)")
        print("  When run inside Gramine SGX enclave, this script will:")
        print("  1. Access /dev/attestation pseudo-filesystem")
        print("  2. Write custom user data")
        print("  3. Generate an SGX DCAP quote")
        print("  4. Save the quote for verification")
        return 1
    
    # Step 2: Check attestation type
    print()
    print("[Step 2] Checking Attestation Type")
    print("-" * 50)
    
    att_type = get_attestation_type()
    if att_type != "dcap":
        print(f"⚠ Warning: Expected 'dcap', got '{att_type}'")
        if att_type == "none":
            print("  Remote attestation may not be properly configured.")
            print("  Check manifest: sgx.remote_attestation = \"dcap\"")
            return 1
    
    # Step 3: Generate and write user report data
    print()
    print("[Step 3] Generating User Report Data")
    print("-" * 50)
    
    user_data, message = generate_user_report_data("Hierarchical-TEE-SGX-Gramine-Demo")
    print(f"  Message: {message}")
    print(f"  Data (hex): {user_data[:16].hex()}...")
    
    if not write_user_report_data(user_data):
        return 1
    
    # Step 4: Get the SGX quote
    print()
    print("[Step 4] Generating SGX Quote")
    print("-" * 50)
    
    quote = read_sgx_quote()
    if quote is None:
        return 1
    
    # Step 5: Parse and display quote info
    parse_quote_header(quote)
    
    # Step 6: Save quote to file
    print()
    print("[Step 5] Saving Quote")
    print("-" * 50)
    
    if not save_quote_to_file(quote, "quote.bin"):
        return 1
    
    # Step 7: Optional benchmark
    print()
    run_benchmark = os.environ.get("RUN_BENCHMARK", "0") == "1"
    if run_benchmark:
        benchmark_quote_generation(10)
    
    # Print verification instructions
    print_verification_instructions("quote.bin")
    
    print("=" * 70)
    print("✓ Attestation Demo Complete!")
    print("=" * 70)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
