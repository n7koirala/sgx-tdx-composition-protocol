"""
Merged IMA verification component used by the PCR10-replay variant of the
incremental-attestation benchmark.

One pass over the delta log does BOTH:
  (1) per-entry SHA-1 template-hash self-consistency (ima-ng TLV
      reconstruction, as in the original verify_ima_log), and
  (2) PCR 10 extend-chain replay against the SHA-1 PCR bank, carrying a
      20-byte rolling state across rounds so the optimized (delta-only)
      mode replays correctly.

The SHA-1 bank is used because the ASCII IMA log's template_hash column
is a SHA-1 digest.  The CVM exports PCR10 from
/sys/class/tpm/tpm0/pcr-sha1/10 to match.

Returns a richer result than the original verify_ima_log so the benchmark
harness can (a) persist the new PCR state for the next round and (b)
bucket integrity failures by cause (template tamper vs. PCR mismatch).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Optional, Tuple


# SHA-1 PCR banks are 20 bytes.  The "fresh" starting state is zero.
ZERO_PCR_SHA1 = b'\x00' * 20


@dataclass
class IMAVerifyResult:
    ok: bool
    entry_count: int          # lines that were treated as PCR-10 entries
    violations: int           # all-zero template-hash lines (expected)
    tampered: int             # ima-ng entries whose TLV hash didn't match
    tampered_files: list      # up to first 3 filenames
    pcr_match: bool           # did the replayed state match claimed_pcr10?
    new_pcr_state: bytes      # 20-byte post-replay SHA-1 PCR state
    message: str


def verify_ima_log_with_replay(
    ima_log_text: str,
    claimed_pcr10: str,
    prev_pcr_state: bytes = ZERO_PCR_SHA1,
    debug: bool = False,
) -> IMAVerifyResult:
    """
    Single-pass IMA integrity + PCR10 replay verifier.

    Args:
        ima_log_text:   Raw IMA ASCII log (one entry per line).  In the
                        optimized mode this is the Δn delta; in the
                        non-optimized mode it's the full N-entry log.
        claimed_pcr10:  Hex string of the CVM's live PCR-10 value
                        (SHA-1 bank, 40 hex chars).
        prev_pcr_state: 20-byte PCR state carried from the previous round.
                        For the first round (or whenever replaying from
                        scratch), pass ZERO_PCR_SHA1.
        debug:          Print per-entry diagnostic output.

    Returns:
        IMAVerifyResult with integrity flags, replay match flag, and
        the new 20-byte PCR state for the caller to stash.
    """
    if not ima_log_text or not ima_log_text.strip():
        return IMAVerifyResult(
            ok=False, entry_count=0, violations=0, tampered=0,
            tampered_files=[], pcr_match=False,
            new_pcr_state=prev_pcr_state,
            message="Empty IMA event log",
        )

    if not claimed_pcr10 or not claimed_pcr10.strip():
        return IMAVerifyResult(
            ok=False, entry_count=0, violations=0, tampered=0,
            tampered_files=[], pcr_match=False,
            new_pcr_state=prev_pcr_state,
            message="No PCR-10 value provided",
        )

    pcr_state = prev_pcr_state
    if len(pcr_state) != 20:
        # Guard against a caller passing in a SHA-256-shaped state by mistake.
        raise ValueError(
            f"prev_pcr_state must be 20 bytes (SHA-1 bank), got {len(pcr_state)}"
        )

    lines = ima_log_text.strip().split('\n')
    entry_count = 0
    violations = 0
    tampered = 0
    tampered_files: list = []

    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue

        # Format: PCR TEMPLATE_HASH TEMPLATE_NAME ALGO:DIGEST FILENAME
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue

        pcr_idx = parts[0]
        logged_sha1_hex = parts[1]
        template_name = parts[2]
        algo_digest = parts[3]
        filename = parts[4] if len(parts) > 4 else ""

        if pcr_idx != "10":
            continue

        entry_count += 1

        # (2) PCR-10 extend chain.  Every PCR-10 row — including violation
        # entries and non-ima-ng rows — contributes to the replay using the
        # SHA-1 hash the kernel logged.  We extend first so a per-entry
        # integrity failure below does not short-circuit the replay.
        try:
            template_hash_bytes = bytes.fromhex(logged_sha1_hex)
        except ValueError:
            # Malformed hex — treat as tamper, still consume the line so
            # entry_count stays aligned with the kernel's view.
            tampered += 1
            tampered_files.append(filename or f"<malformed line {i+1}>")
            continue

        if len(template_hash_bytes) != 20:
            tampered += 1
            tampered_files.append(filename or f"<bad-len line {i+1}>")
            continue

        pcr_state = hashlib.sha1(pcr_state + template_hash_bytes).digest()

        # (1) Per-entry SHA-1 template-hash self-consistency.
        if logged_sha1_hex == "0" * 40:
            violations += 1
            if debug and violations <= 3:
                print(f"[IMA] Violation entry {violations}: {filename[:60]}")
            continue  # violation rows are zero by design; skip TLV check

        if template_name == "ima-ng":
            try:
                if ':' not in algo_digest:
                    continue
                algo, hex_digest = algo_digest.split(':', 1)
                digest_bytes = bytes.fromhex(hex_digest)

                d_ng_data = (algo + ":").encode('utf-8') + b'\x00' + digest_bytes
                d_ng_len = struct.pack('<I', len(d_ng_data))
                n_ng_data = filename.encode('utf-8') + b'\x00'
                n_ng_len = struct.pack('<I', len(n_ng_data))
                template_data = d_ng_len + d_ng_data + n_ng_len + n_ng_data

                computed_sha1 = hashlib.sha1(template_data).hexdigest()
                if computed_sha1 != logged_sha1_hex:
                    tampered += 1
                    tampered_files.append(filename)
                    if debug:
                        print(f"[IMA] TAMPERED line {i+1}: {filename[:60]}")
                        print(f"[IMA]   Logged:   {logged_sha1_hex}")
                        print(f"[IMA]   Computed: {computed_sha1}")
            except (ValueError, Exception) as e:
                if debug:
                    print(f"[IMA] Error at line {i+1}: {e}")
                continue
        # Non-ima-ng rows (e.g. boot_aggregate, ima-sig) contribute to the
        # replay but cannot be self-consistency-checked from the ASCII log
        # without knowing the template binary format — trust the kernel.

    if entry_count == 0:
        return IMAVerifyResult(
            ok=False, entry_count=0, violations=0, tampered=0,
            tampered_files=[], pcr_match=False,
            new_pcr_state=prev_pcr_state,
            message="No valid IMA entries found",
        )

    claimed = claimed_pcr10.strip().lower()
    replayed = pcr_state.hex().lower()
    pcr_match = (claimed == replayed)

    ok = (tampered == 0) and pcr_match

    if tampered > 0:
        msg = (
            f"IMA log TAMPERED: {tampered}/{entry_count} entries failed "
            f"SHA-1 TLV integrity check (e.g., {', '.join(tampered_files[:3])})"
        )
    elif not pcr_match:
        msg = (
            f"PCR-10 replay MISMATCH after {entry_count} entries "
            f"(replayed={replayed[:16]}…, claimed={claimed[:16]}…)"
        )
    else:
        detail = f"{entry_count} entries verified"
        if violations > 0:
            detail += f", {violations} violation(s)"
        msg = f"IMA log integrity + PCR-10 replay OK ({detail})"

    if debug:
        print(f"[IMA] Verified {entry_count} entries: "
              f"{violations} violations, {tampered} tampered, "
              f"pcr_match={pcr_match}")

    return IMAVerifyResult(
        ok=ok, entry_count=entry_count, violations=violations,
        tampered=tampered, tampered_files=tampered_files,
        pcr_match=pcr_match, new_pcr_state=pcr_state,
        message=msg,
    )
