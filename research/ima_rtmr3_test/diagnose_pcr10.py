#!/usr/bin/env python3
"""
Diagnose why IMA log replay does not match vTPM PCR-10.

Run on the CVM:
    sudo python3 diagnose_pcr10.py
"""

from __future__ import annotations

import hashlib
import time

from ima_rtmr3_common import (
    ascii_ima_entries,
    binary_ascii_template_hash_match,
    count_ascii_ima_entries,
    read_ima_ascii_log,
    read_ima_binary_log,
    read_ima_count,
    read_pcr10_sha1,
    read_pcr10_sha256,
    replay_pcr10_sha1,
    replay_pcr10_sha1_ascii,
    replay_pcr10_sha256_binary,
)


def replay_sha256_ascii_sha1_hashes(log_text: str) -> str:
    state = b"\x00" * 32
    for pcr, template_hash_hex in ascii_ima_entries(log_text):
        if pcr != 10:
            continue
        try:
            digest = bytes.fromhex(template_hash_hex)
        except ValueError:
            continue
        state = hashlib.sha256(state + digest).digest()
    return state.hex()


def stable_snapshot(max_attempts: int = 10):
    last = None
    for attempt in range(1, max_attempts + 1):
        blob, entries = read_ima_binary_log()
        ascii_log = read_ima_ascii_log()
        ascii_count = count_ascii_ima_entries(ascii_log)
        kernel_count_before = read_ima_count()
        pcr_sha1 = read_pcr10_sha1()
        pcr_sha256 = read_pcr10_sha256()
        kernel_count_after = read_ima_count()

        last = (
            attempt,
            blob,
            entries,
            ascii_log,
            ascii_count,
            kernel_count_before,
            kernel_count_after,
            pcr_sha1,
            pcr_sha256,
        )

        if len(entries) == ascii_count == kernel_count_before == kernel_count_after:
            return last

        time.sleep(0.2)

    return last


def main() -> int:
    snap = stable_snapshot()
    if snap is None:
        print("failed to collect snapshot")
        return 2

    (
        attempt,
        blob,
        entries,
        ascii_log,
        ascii_count,
        kernel_count_before,
        kernel_count_after,
        pcr_sha1,
        pcr_sha256,
    ) = snap

    print("=" * 72)
    print("PCR-10 / IMA Diagnostic")
    print("=" * 72)
    print(f"snapshot_attempt      = {attempt}")
    print(f"binary_entries        = {len(entries)}")
    print(f"ascii_entries         = {ascii_count}")
    print(f"kernel_count_before   = {kernel_count_before}")
    print(f"kernel_count_after    = {kernel_count_after}")
    print(f"binary_size_bytes     = {len(blob)}")
    print(f"pcr10_sha1_claimed    = {pcr_sha1 or '<missing>'}")
    print(f"pcr10_sha256_claimed  = {pcr_sha256 or '<missing>'}")

    hash_match = binary_ascii_template_hash_match(entries, ascii_log)
    print(f"binary_ascii_hashes   = {'MATCH' if hash_match else 'MISMATCH'}")

    sha1_data_mismatch = 0
    first_mismatch = None
    for entry in entries:
        computed = hashlib.sha1(entry.template_data).digest()
        if computed != entry.template_hash:
            sha1_data_mismatch += 1
            if first_mismatch is None:
                first_mismatch = (
                    entry.index,
                    entry.template_name_text,
                    entry.template_hash.hex(),
                    computed.hex(),
                    len(entry.template_data),
                )

    print(f"sha1(template_data)   = {len(entries) - sha1_data_mismatch}/{len(entries)} entries match")
    if first_mismatch:
        idx, name, logged, computed, data_len = first_mismatch
        print("first_data_mismatch:")
        print(f"  index              = {idx}")
        print(f"  template           = {name}")
        print(f"  logged_sha1        = {logged}")
        print(f"  computed_sha1      = {computed}")
        print(f"  template_data_len  = {data_len}")

    sha1_ascii = replay_pcr10_sha1_ascii(ascii_log)
    sha1_binary = replay_pcr10_sha1(entries)
    sha256_binary = replay_pcr10_sha256_binary(entries)
    sha256_ascii_sha1 = replay_sha256_ascii_sha1_hashes(ascii_log)

    print()
    print("Replay candidates:")
    print(f"sha1_ascii_expected          = {sha1_ascii.pcr_hex}")
    print(f"sha1_ascii_match             = {sha1_ascii.pcr_hex == pcr_sha1}")
    print(f"sha1_binary_expected         = {sha1_binary.pcr_hex}")
    print(f"sha1_binary_match            = {sha1_binary.pcr_hex == pcr_sha1}")
    print(f"sha256_binary_expected       = {sha256_binary.pcr_hex}")
    print(f"sha256_binary_match          = {sha256_binary.pcr_hex == pcr_sha256}")
    print(f"sha256_ascii_sha1_expected   = {sha256_ascii_sha1}")
    print(f"sha256_ascii_sha1_match      = {sha256_ascii_sha1 == pcr_sha256}")

    print()
    if sha1_ascii.pcr_hex == pcr_sha1 or sha256_binary.pcr_hex == pcr_sha256:
        print("diagnosis = PCR replay formula works for at least one bank")
        return 0

    if hash_match and sha1_data_mismatch == 0:
        print("diagnosis = IMA log is internally consistent, but neither PCR bank matches")
        print("           This suggests PCR-10 has extra/non-IMA extends, a non-zero base,")
        print("           or this VM's vTPM PCR-10 is not the kernel IMA chain.")
    else:
        print("diagnosis = binary/ascii/template-data disagreement; inspect parser/template format")

    print("=" * 72)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
