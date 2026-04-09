"""
Reference Manifest Generator for IMA-Based CVM Verification.

Connects to a known-good CVM via SSH, reads the IMA log, and generates
a reference manifest (allowlist) of all measured files and their hashes.

The manifest is used during commissioning Phase C' to verify that no
unexpected files were executed during CVM boot.

Usage:
    # Generate from a running CVM:
    python3 -m commissioning_phase.generate_reference_manifest \\
        --host <CVM_IP> --user cvm --key <SSH_PRIVATE_KEY_PATH>

    # Generate from a local IMA log file (for testing):
    python3 -m commissioning_phase.generate_reference_manifest \\
        --ima-log-file /path/to/ima_log.txt

    # Generate from a running CVM via the SGX controller:
    python3 -m commissioning_phase.generate_reference_manifest \\
        --controller-url http://<CONTROLLER>:6037 --cvm-id <CVM_ID>
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import paramiko

from .ima_verifier import parse_ima_ascii_log, IMAVerifier


def generate_manifest_from_log(raw_log: str, image_name: str = "ubuntu-2204-lts") -> dict:
    """Generate a reference manifest from a raw IMA log.

    Args:
        raw_log: Raw text from /sys/kernel/security/ima/ascii_runtime_measurements.
        image_name: Name of the image to record in the manifest.

    Returns:
        Manifest dict.
    """
    entries = parse_ima_ascii_log(raw_log)

    # Build the entries dict: hash -> list of file paths
    manifest_entries = {}
    for entry in entries:
        if entry.pcr != 10:
            continue
        if not entry.file_path or entry.file_path == "boot_aggregate":
            continue

        key = f"{entry.file_hash_algo}:{entry.file_hash}"
        if key not in manifest_entries:
            manifest_entries[key] = []
        if entry.file_path not in manifest_entries[key]:
            manifest_entries[key].append(entry.file_path)

    manifest = {
        "version": "1.0",
        "image": image_name,
        "description": "Reference manifest generated from a known-good CVM image.",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entry_count": len(manifest_entries),
        "file_count": sum(len(v) for v in manifest_entries.values()),
        "entries": manifest_entries,
    }

    return manifest


def read_ima_log_ssh(host: str, user: str, key_path: str) -> str:
    """Read the IMA log from a CVM via SSH.

    Args:
        host: CVM IP address or hostname.
        user: SSH username.
        key_path: Path to SSH private key.

    Returns:
        Raw IMA log text.
    """
    print(f"Connecting to {user}@{host}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    pkey = paramiko.RSAKey.from_private_key_file(key_path)
    client.connect(host, username=user, pkey=pkey, timeout=30)

    print("Reading IMA log...")
    _stdin, stdout, _stderr = client.exec_command(
        f"sudo cat {IMAVerifier.IMA_LOG_PATH}"
    )
    raw_log = stdout.read().decode("utf-8", errors="replace")

    client.close()
    print(f"Read {len(raw_log)} bytes ({raw_log.count(chr(10))} lines)")
    return raw_log


def main():
    parser = argparse.ArgumentParser(
        description="Generate IMA reference manifest from a known-good CVM"
    )

    # Source: SSH to CVM
    parser.add_argument("--host", help="CVM IP address for SSH connection")
    parser.add_argument("--user", default="cvm", help="SSH username (default: cvm)")
    parser.add_argument("--key", help="Path to SSH private key file")

    # Source: local file
    parser.add_argument("--ima-log-file", help="Path to local IMA log file (alternative to SSH)")

    # Output
    parser.add_argument(
        "--output", "-o",
        default=os.path.join(os.path.dirname(__file__), "reference_manifest.json"),
        help="Output manifest file path",
    )
    parser.add_argument("--image", default="ubuntu-2204-lts", help="Image name for manifest")

    args = parser.parse_args()

    # Read IMA log from source
    if args.ima_log_file:
        print(f"Reading IMA log from file: {args.ima_log_file}")
        with open(args.ima_log_file, "r") as f:
            raw_log = f.read()
    elif args.host and args.key:
        raw_log = read_ima_log_ssh(args.host, args.user, args.key)
    else:
        print("ERROR: Provide either --host + --key (SSH) or --ima-log-file (local)")
        sys.exit(1)

    # Generate manifest
    print("Generating reference manifest...")
    manifest = generate_manifest_from_log(raw_log, args.image)

    # Write output
    with open(args.output, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n{'='*60}")
    print(f"  Reference Manifest Generated")
    print(f"{'='*60}")
    print(f"  Output:     {args.output}")
    print(f"  Image:      {manifest['image']}")
    print(f"  Hashes:     {manifest['entry_count']}")
    print(f"  Files:      {manifest['file_count']}")
    print(f"  Generated:  {manifest['generated_at']}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
