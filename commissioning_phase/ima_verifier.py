"""
IMA (Integrity Measurement Architecture) Verifier for CVM Commissioning.

Implements Phase C' of the commissioning protocol: IMA-based launch
integrity verification. After the hardening script (Phase C) completes,
the controller uses this module to:

  1. Parse the CVM's IMA ASCII runtime measurements log
  2. Replay the PCR-10 chain and verify it matches the live PCR-10 value
  3. Check every IMA entry against a reference manifest (allowlist)
  4. Compute a hash of the full IMA log for TDX quote binding

This detects post-boot tampering (malicious services, trojanized libraries,
unauthorized kernel modules) that TDX hardware attestation alone cannot catch.

Usage (standalone verification against a running CVM):
    from commissioning_phase.ima_verifier import IMAVerifier
    verifier = IMAVerifier(manifest_path="reference_manifest.json")
    result = verifier.verify_cvm(cvm)
"""

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# IMA Log Entry
# ---------------------------------------------------------------------------

@dataclass
class IMAEntry:
    """A single entry from the IMA ASCII runtime measurements log.

    Format of each line in /sys/kernel/security/ima/ascii_runtime_measurements:
        PCR  template_hash  template_name  file_hash_algo:file_hash  file_path

    Example:
        10 abc123...  ima-ng  sha256:def456...  /usr/bin/bash
    """
    pcr: int
    template_hash: str  # hex string of the template hash
    template_name: str  # e.g., "ima-ng", "ima-sig"
    file_hash_algo: str  # e.g., "sha256"
    file_hash: str       # hex string of the file content hash
    file_path: str       # absolute path of the measured file


# ---------------------------------------------------------------------------
# IMA Log Parsing
# ---------------------------------------------------------------------------

def parse_ima_ascii_log(raw_log: str) -> List[IMAEntry]:
    """Parse the IMA ASCII runtime measurements log.

    Args:
        raw_log: Raw text from
                 /sys/kernel/security/ima/ascii_runtime_measurements

    Returns:
        List of IMAEntry objects, one per measurement.
    """
    entries = []
    for line in raw_log.strip().splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split(None, 4)  # Split into at most 5 parts
        if len(parts) < 5:
            # Some entries may have fewer fields (e.g., boot_aggregate)
            # Handle gracefully
            if len(parts) == 4:
                # boot_aggregate lines: PCR hash template_name file_hash_spec
                pcr_str, template_hash, template_name, file_hash_spec = parts
                file_path = ""
            else:
                continue

        else:
            pcr_str, template_hash, template_name, file_hash_spec, file_path = parts

        try:
            pcr = int(pcr_str)
        except ValueError:
            continue

        # Parse file_hash_spec (format: "algo:hash" or just "hash")
        if ":" in file_hash_spec:
            file_hash_algo, file_hash = file_hash_spec.split(":", 1)
        else:
            file_hash_algo = "sha256"
            file_hash = file_hash_spec

        entries.append(IMAEntry(
            pcr=pcr,
            template_hash=template_hash,
            template_name=template_name,
            file_hash_algo=file_hash_algo,
            file_hash=file_hash,
            file_path=file_path,
        ))

    return entries


# ---------------------------------------------------------------------------
# PCR-10 Replay
# ---------------------------------------------------------------------------

def replay_pcr10(entries: List[IMAEntry], hash_algo: str = "sha256") -> str:
    """Replay the PCR-10 extend chain from the IMA log entries.

    Starting from a zero-initialized register, for each entry e_i:
        pcr10[i] = H(pcr10[i-1] || template_hash_bytes[i])

    where H is SHA-256 (matching the SHA-256 PCR bank) and
    template_hash_bytes is the binary representation of the hex
    template_hash from the IMA log.

    For the SHA-256 bank, the template_hash in the ASCII log is NOT
    the SHA-256 hash — it's the SHA-1 hash (20 bytes). The SHA-256 bank
    extends with SHA-256(template_data), but since we only have the ASCII
    log (not binary), we use the SHA-1 bank for verification instead.

    NOTE: When using ASCII format, template_hash is SHA-1 (40 hex chars).
    We replay against the SHA-1 PCR bank for correctness.

    Args:
        entries: Parsed IMA entries.
        hash_algo: Hash algorithm for extend. "sha1" for SHA-1 bank
                   (template_hash from ASCII log is SHA-1).

    Returns:
        Hex string of the final replayed PCR-10 value.
    """
    if hash_algo == "sha1":
        pcr = b'\x00' * 20  # SHA-1: 20 bytes
        hash_func = hashlib.sha1
    else:
        pcr = b'\x00' * 32  # SHA-256: 32 bytes
        hash_func = hashlib.sha256

    for entry in entries:
        if entry.pcr != 10:
            continue

        # The template_hash in ASCII log is SHA-1 (40 hex chars)
        template_hash_bytes = bytes.fromhex(entry.template_hash)

        if hash_algo == "sha1":
            # SHA-1 bank: extend with the SHA-1 template hash directly
            # pcr10 = SHA-1(pcr10 || sha1_template_hash)
            pcr = hash_func(pcr + template_hash_bytes).digest()
        else:
            # SHA-256 bank: we can't accurately replay from ASCII log alone
            # because the ASCII log only contains SHA-1 template hashes.
            # For SHA-256 bank replay, the binary log is needed.
            # Fallback: use SHA-1 template hash padded/hashed for extend
            # This will NOT match the SHA-256 bank — use sha1 mode instead.
            pcr = hash_func(pcr + template_hash_bytes).digest()

    return pcr.hex()


def replay_pcr10_sha1(entries: List[IMAEntry]) -> str:
    """Replay PCR-10 using the SHA-1 bank (recommended for ASCII logs).

    The ASCII IMA log's template_hash field is always the SHA-1 hash
    of the template data. This matches the SHA-1 PCR bank.
    """
    return replay_pcr10(entries, hash_algo="sha1")


# ---------------------------------------------------------------------------
# Log Integrity Verification
# ---------------------------------------------------------------------------

def verify_log_integrity(entries: List[IMAEntry], actual_pcr10: str,
                          hash_algo: str = "sha1") -> Tuple[bool, str, str]:
    """Verify IMA log integrity by comparing replayed PCR-10 to actual value.

    Args:
        entries: Parsed IMA log entries.
        actual_pcr10: Actual PCR-10 value read from the TPM (hex string).
        hash_algo: Which PCR bank to verify against ("sha1" recommended
                   for ASCII log verification).

    Returns:
        Tuple of (match: bool, replayed: str, actual: str).
    """
    replayed = replay_pcr10(entries, hash_algo=hash_algo)
    actual_clean = actual_pcr10.strip().lower()
    replayed_clean = replayed.strip().lower()
    return replayed_clean == actual_clean, replayed_clean, actual_clean


# ---------------------------------------------------------------------------
# Reference Manifest Verification
# ---------------------------------------------------------------------------

def load_reference_manifest(manifest_path: str) -> dict:
    """Load a reference manifest from a JSON file.

    The manifest maps file content hashes to known-good file paths:
    {
        "version": "1.0",
        "image": "ubuntu-2204-lts",
        "entries": {
            "sha256:HASH": ["/path/to/file", ...],
            ...
        }
    }

    Args:
        manifest_path: Path to the reference_manifest.json file.

    Returns:
        Dict of hash -> list of file paths.
    """
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
    return manifest.get("entries", {})


def verify_reference_manifest(
    entries: List[IMAEntry],
    manifest: dict,
    strict: bool = False,
) -> Tuple[bool, List[dict]]:
    """Check every IMA entry against the reference manifest.

    Args:
        entries: Parsed IMA log entries.
        manifest: Dict of "algo:hash" -> list of file paths.
        strict: If True, any unknown entry causes failure.
                If False, only log violations but still return them.

    Returns:
        Tuple of (all_ok: bool, violations: list of dicts).
        Each violation: {"entry": IMAEntry, "reason": str}
    """
    violations = []

    for entry in entries:
        if entry.pcr != 10:
            continue

        # Skip boot_aggregate entries (these are TPM aggregate measurements)
        if entry.file_path == "boot_aggregate" or not entry.file_path:
            continue

        # Construct the manifest key
        manifest_key = f"{entry.file_hash_algo}:{entry.file_hash}"

        # Check if this hash is in the manifest
        if manifest_key not in manifest:
            violations.append({
                "file_path": entry.file_path,
                "file_hash": manifest_key,
                "reason": "Hash not found in reference manifest",
            })

    all_ok = len(violations) == 0
    return all_ok, violations


# ---------------------------------------------------------------------------
# IMA Log Hashing (for TDX Quote Binding)
# ---------------------------------------------------------------------------

def compute_ima_log_hash(raw_log: str) -> str:
    """Compute SHA-256 hash of the full IMA log.

    This hash is embedded into the TDX attestation quote's report_data
    field, creating a cryptographic binding between the IMA log and
    the hardware attestation.

    Args:
        raw_log: Raw text of the IMA ASCII runtime measurements.

    Returns:
        Hex string of SHA-256(ima_log).
    """
    return hashlib.sha256(raw_log.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# High-Level IMA Verifier
# ---------------------------------------------------------------------------

class IMAVerifier:
    """High-level IMA verifier for CVM commissioning.

    Orchestrates the full IMA verification pipeline:
    1. Read IMA log and PCR-10 from CVM via SSH
    2. Parse and replay the log
    3. Verify against reference manifest
    4. Request TDX quote with IMA log hash binding
    """

    # Paths on the CVM
    IMA_LOG_PATH = "/sys/kernel/security/ima/ascii_runtime_measurements"
    PCR10_SHA1_PATH = "/sys/class/tpm/tpm0/pcr-sha1/10"
    PCR10_SHA256_PATH = "/sys/class/tpm/tpm0/pcr-sha256/10"

    # TDX quote generation script (executed on CVM)
    TDX_QUOTE_SCRIPT = """
import hashlib, os, struct, sys, base64

report_data_hex = sys.argv[1]
report_data = bytes.fromhex(report_data_hex)

# Pad to 64 bytes (TDX report_data is 64 bytes)
report_data_padded = report_data.ljust(64, b'\\x00')

# Write report_data to configfs-tsm
tsm_report_dir = None
for i in range(100):
    path = f"/sys/kernel/config/tsm/report/report{i}"
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)
        tsm_report_dir = path
        break

if tsm_report_dir is None:
    print("ERROR: Could not create TSM report directory")
    sys.exit(1)

try:
    with open(os.path.join(tsm_report_dir, "inblob"), "wb") as f:
        f.write(report_data_padded)
    with open(os.path.join(tsm_report_dir, "outblob"), "rb") as f:
        quote = f.read()
    print(base64.b64encode(quote).decode())
finally:
    os.rmdir(tsm_report_dir)
"""

    def __init__(self, manifest_path: Optional[str] = None, logger=None):
        """Initialize the IMA verifier.

        Args:
            manifest_path: Path to reference_manifest.json.
                          If None, uses default location next to this file.
            logger: Logger instance.
        """
        self._logger = logger

        if manifest_path is None:
            manifest_path = os.path.join(
                os.path.dirname(__file__), "reference_manifest.json"
            )

        self._manifest_path = manifest_path
        self._manifest = {}

        if os.path.isfile(manifest_path):
            self._manifest = load_reference_manifest(manifest_path)
            self._log(f"Loaded reference manifest with {len(self._manifest)} entries")
        else:
            self._log(f"WARNING: No reference manifest at {manifest_path}")

    def _log(self, msg):
        if self._logger:
            self._logger.info(msg)

    def verify_cvm(self, cvm, skip_manifest: bool = False,
                   skip_tdx_quote: bool = False) -> dict:
        """Run the full IMA verification pipeline on a CVM.

        Args:
            cvm: ConfidentialVM instance (must have an active SSH connection
                 or be connectable).
            skip_manifest: If True, skip reference manifest verification
                          (useful when manifest hasn't been generated yet).
            skip_tdx_quote: If True, skip TDX quote generation
                           (for non-TDX environments or testing).

        Returns:
            Dict with:
                - "success": bool
                - "ima_log": raw IMA log text
                - "pcr10": actual PCR-10 value
                - "pcr10_replayed": replayed PCR-10 value
                - "pcr10_match": bool
                - "manifest_violations": list of violations (if checked)
                - "ima_log_hash": SHA-256 hash of the IMA log
                - "tdx_quote": base64 TDX quote (if requested)
                - "entry_count": number of IMA entries
                - "error": error message (if failed)
        """
        result = {"success": False}

        try:
            # Ensure SSH connection
            needs_disconnect = False
            if not cvm._ssh_client or not cvm._ssh_client.get_transport() or \
               not cvm._ssh_client.get_transport().is_active():
                cvm.connect()
                needs_disconnect = True

            # --- Step 1: Read IMA log ---
            self._log("Phase C': Reading IMA log from CVM...")
            ima_log_output = cvm.execute_command(
                f"sudo cat {self.IMA_LOG_PATH}"
            )
            raw_ima_log = "".join(ima_log_output).strip()

            if not raw_ima_log:
                result["error"] = "IMA log is empty — IMA may not be enabled on CVM"
                return result

            result["ima_log"] = raw_ima_log

            # --- Step 2: Read PCR-10 ---
            self._log("Phase C': Reading PCR-10 from CVM...")
            pcr10_output = cvm.execute_command(
                f"sudo cat {self.PCR10_SHA1_PATH}"
            )
            actual_pcr10 = "".join(pcr10_output).strip()
            result["pcr10"] = actual_pcr10

            # --- Step 3: Parse and replay ---
            self._log("Phase C': Parsing IMA log and replaying PCR-10...")
            entries = parse_ima_ascii_log(raw_ima_log)
            result["entry_count"] = len(entries)

            pcr10_match, replayed, actual = verify_log_integrity(
                entries, actual_pcr10, hash_algo="sha1"
            )
            result["pcr10_replayed"] = replayed
            result["pcr10_match"] = pcr10_match

            if not pcr10_match:
                self._log(
                    f"Phase C': PCR-10 MISMATCH! "
                    f"Replayed={replayed}, Actual={actual}"
                )
                result["error"] = (
                    f"PCR-10 replay mismatch: IMA log may be truncated or "
                    f"tampered. Replayed={replayed}, Actual={actual}"
                )
                return result

            self._log(
                f"Phase C': PCR-10 replay OK "
                f"({len(entries)} entries, PCR-10={replayed[:16]}...)"
            )

            # --- Step 4: Reference manifest verification ---
            if not skip_manifest and self._manifest:
                self._log("Phase C': Checking IMA entries against reference manifest...")
                manifest_ok, violations = verify_reference_manifest(
                    entries, self._manifest, strict=True
                )
                result["manifest_violations"] = violations

                if not manifest_ok:
                    self._log(
                        f"Phase C': MANIFEST VIOLATION! "
                        f"{len(violations)} unexpected file(s) detected"
                    )
                    for v in violations[:10]:  # Log first 10
                        self._log(
                            f"  - {v['file_path']}: {v['reason']} "
                            f"({v['file_hash']})"
                        )
                    result["error"] = (
                        f"Reference manifest check failed: "
                        f"{len(violations)} unexpected files detected "
                        f"during CVM boot"
                    )
                    return result

                self._log("Phase C': Reference manifest check passed")
            else:
                result["manifest_violations"] = []
                if skip_manifest:
                    self._log("Phase C': Skipping manifest check (skip_manifest=True)")
                else:
                    self._log("Phase C': Skipping manifest check (no manifest loaded)")

            # --- Step 5: Compute IMA log hash ---
            ima_log_hash = compute_ima_log_hash(raw_ima_log)
            result["ima_log_hash"] = ima_log_hash
            self._log(f"Phase C': IMA log hash: {ima_log_hash[:16]}...")

            # --- Step 6: Request TDX quote (optional) ---
            if not skip_tdx_quote:
                self._log("Phase C': Requesting TDX quote with IMA log hash binding...")
                try:
                    tdx_quote = self._request_tdx_quote(cvm, ima_log_hash)
                    result["tdx_quote"] = tdx_quote
                    self._log(f"Phase C': TDX quote obtained ({len(tdx_quote)} chars)")
                except Exception as exc:
                    self._log(f"Phase C': TDX quote failed: {exc}")
                    result["tdx_quote"] = None
                    result["tdx_quote_error"] = str(exc)
                    # Don't fail commissioning if TDX quote fails —
                    # the IMA verification itself passed
            else:
                result["tdx_quote"] = None
                self._log("Phase C': Skipping TDX quote (skip_tdx_quote=True)")

            # --- Success ---
            result["success"] = True
            self._log(
                f"Phase C': IMA verification PASSED "
                f"({len(entries)} entries, PCR-10 OK"
                + (", manifest OK" if self._manifest and not skip_manifest else "")
                + ")"
            )

            if needs_disconnect:
                cvm.disconnect()

        except Exception as exc:
            result["error"] = f"IMA verification failed: {exc}"
            self._log(f"Phase C': ERROR — {exc}")

        return result

    def _request_tdx_quote(self, cvm, ima_log_hash: str) -> str:
        """Request a TDX attestation quote from the CVM.

        Embeds report_data = SHA-256(ima_log) to bind the IMA state
        to the TDX hardware identity.

        Args:
            cvm: ConfidentialVM instance with active SSH.
            ima_log_hash: Hex string of SHA-256(ima_log).

        Returns:
            Base64-encoded TDX quote.
        """
        # Use configfs-tsm interface to generate TDX quote
        # report_data = ima_log_hash (32 bytes as hex)
        quote_cmd = (
            f"sudo python3 -c \""
            f"import hashlib, os, base64, sys; "
            f"rd = bytes.fromhex('{ima_log_hash}'); "
            f"rd = rd.ljust(64, b'\\\\x00'); "
            f"tsm = '/sys/kernel/config/tsm/report/ima_report'; "
            f"os.makedirs(tsm, exist_ok=True); "
            f"open(tsm+'/inblob','wb').write(rd); "
            f"q = open(tsm+'/outblob','rb').read(); "
            f"print(base64.b64encode(q).decode()); "
            f"os.rmdir(tsm)"
            f"\""
        )

        output = cvm.execute_command(quote_cmd)
        quote_b64 = "".join(output).strip()

        if not quote_b64 or "ERROR" in quote_b64:
            raise RuntimeError(f"TDX quote generation failed: {quote_b64}")

        return quote_b64
