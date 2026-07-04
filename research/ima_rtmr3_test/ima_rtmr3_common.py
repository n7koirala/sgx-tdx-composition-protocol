#!/usr/bin/env python3
"""
Common helpers for the isolated IMA -> RTMR[3] anchoring experiment.

Canonical RTMR extend mapping
=============================

Each IMA binary measurement-list event is parsed as:

    LE32(pcr_index)
    template_hash[20]
    LE32(template_name_len)
    template_name[template_name_len]
    LE32(template_data_len)
    template_data[template_data_len]

For RTMR[3], the 48-byte extend input for one IMA event is:

    SHA384(
        "IMA-RTMR3-CANON-v1\\0"
        || LE32(pcr_index)
        || LE32(len(template_hash)) || template_hash
        || LE32(len(template_name)) || template_name
        || LE32(len(template_data)) || template_data
    )

The RTMR chain itself follows the TDX SHA-384 extend rule:

    new_rtmr = SHA384(old_rtmr || extend_input)

This deliberately does not pad or reuse the IMA template hash.  The full
binary template data is included in the canonical serialization so the WEN can
recompute the exact same 48-byte RTMR extend input from the presented binary
IMA log.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple


CANON_MAGIC = b"IMA-RTMR3-CANON-v1\x00"
ZERO_RTMR_SHA384 = b"\x00" * 48
ZERO_PCR_SHA1 = b"\x00" * 20
ZERO_PCR_SHA256 = b"\x00" * 32

IMA_BINARY_PATHS = (
    "/sys/kernel/security/integrity/ima/binary_runtime_measurements",
    "/sys/kernel/security/ima/binary_runtime_measurements",
)

IMA_ASCII_PATHS = (
    "/sys/kernel/security/integrity/ima/ascii_runtime_measurements",
    "/sys/kernel/security/ima/ascii_runtime_measurements",
)

IMA_COUNT_PATHS = (
    "/sys/kernel/security/integrity/ima/runtime_measurements_count",
    "/sys/kernel/security/ima/runtime_measurements_count",
)

PCR10_SHA1_PATHS = (
    "/sys/class/tpm/tpm0/pcr-sha1/10",
    "/sys/class/tpm/tpm0/pcrs",  # fallback parser, if needed
)

PCR10_SHA256_PATHS = (
    "/sys/class/tpm/tpm0/pcr-sha256/10",
)

RTMR_MEASUREMENTS_DIRS = (
    "/sys/devices/virtual/misc/tdx_guest/measurements",
    "/sys/class/misc/tdx_guest/measurements",
    "/sys/devices/virtual/misc/tdx_guest/mr",
    "/sys/class/misc/tdx_guest/mr",
)


class IMABinaryParseError(ValueError):
    """Raised when binary_runtime_measurements cannot be parsed exactly."""


@dataclass(frozen=True)
class IMABinaryEntry:
    index: int
    pcr_index: int
    template_hash: bytes
    template_name: bytes
    template_data: bytes
    raw_event: bytes

    @property
    def template_hash_hex(self) -> str:
        return self.template_hash.hex()

    @property
    def template_name_text(self) -> str:
        return self.template_name.rstrip(b"\x00").decode("utf-8", errors="replace")

    def canonical_bytes(self) -> bytes:
        return canonical_entry_bytes(self)

    def rtmr_extend_digest(self) -> bytes:
        return hashlib.sha384(self.canonical_bytes()).digest()


@dataclass(frozen=True)
class PCRReplayResult:
    pcr_hex: str
    entry_count: int
    skipped_count: int


def _le32(value: int) -> bytes:
    if value < 0 or value > 0xFFFFFFFF:
        raise ValueError(f"value does not fit in LE32: {value}")
    return struct.pack("<I", value)


def canonical_entry_bytes(entry: IMABinaryEntry) -> bytes:
    return b"".join(
        (
            CANON_MAGIC,
            _le32(entry.pcr_index),
            _le32(len(entry.template_hash)),
            entry.template_hash,
            _le32(len(entry.template_name)),
            entry.template_name,
            _le32(len(entry.template_data)),
            entry.template_data,
        )
    )


def parse_ima_binary_log(blob: bytes) -> List[IMABinaryEntry]:
    entries: List[IMABinaryEntry] = []
    off = 0
    index = 0
    size = len(blob)

    while off < size:
        start = off
        if size - off < 4 + 20 + 4:
            raise IMABinaryParseError(
                f"truncated IMA event header at byte {off} of {size}"
            )

        pcr_index = struct.unpack_from("<I", blob, off)[0]
        off += 4

        template_hash = blob[off:off + 20]
        off += 20

        template_name_len = struct.unpack_from("<I", blob, off)[0]
        off += 4
        if template_name_len > size - off:
            raise IMABinaryParseError(
                f"bad template_name_len={template_name_len} at event {index}"
            )
        template_name = blob[off:off + template_name_len]
        off += template_name_len

        if size - off < 4:
            raise IMABinaryParseError(
                f"missing template_data_len at event {index}"
            )
        template_data_len = struct.unpack_from("<I", blob, off)[0]
        off += 4
        if template_data_len > size - off:
            raise IMABinaryParseError(
                f"bad template_data_len={template_data_len} at event {index}"
            )
        template_data = blob[off:off + template_data_len]
        off += template_data_len

        entries.append(
            IMABinaryEntry(
                index=index,
                pcr_index=pcr_index,
                template_hash=template_hash,
                template_name=template_name,
                template_data=template_data,
                raw_event=blob[start:off],
            )
        )
        index += 1

    return entries


def extend_sha384(current: bytes, extend_input: bytes) -> bytes:
    if len(current) != 48:
        raise ValueError(f"RTMR state must be 48 bytes, got {len(current)}")
    if len(extend_input) != 48:
        raise ValueError(f"RTMR extend input must be 48 bytes, got {len(extend_input)}")
    return hashlib.sha384(current + extend_input).digest()


def replay_rtmr3(entries: Iterable[IMABinaryEntry],
                 base: bytes = ZERO_RTMR_SHA384) -> bytes:
    state = base
    for entry in entries:
        state = extend_sha384(state, entry.rtmr_extend_digest())
    return state


def replay_pcr10_sha1(entries: Iterable[IMABinaryEntry],
                      base: bytes = ZERO_PCR_SHA1) -> PCRReplayResult:
    if len(base) != 20:
        raise ValueError(f"PCR SHA-1 base must be 20 bytes, got {len(base)}")

    state = base
    used = 0
    skipped = 0
    for entry in entries:
        if entry.pcr_index != 10:
            continue
        if len(entry.template_hash) != 20:
            skipped += 1
            continue
        state = hashlib.sha1(state + entry.template_hash).digest()
        used += 1

    return PCRReplayResult(
        pcr_hex=state.hex(),
        entry_count=used,
        skipped_count=skipped,
    )


def ascii_ima_entries(log_text: str) -> List[Tuple[int, str]]:
    """Return (PCR index, template_hash_hex) pairs from the ASCII IMA log."""
    entries: List[Tuple[int, str]] = []
    for line in log_text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 4)
        if len(parts) < 2:
            continue
        try:
            pcr_index = int(parts[0])
        except ValueError:
            continue
        entries.append((pcr_index, parts[1].strip().lower()))
    return entries


def replay_pcr10_sha1_ascii(log_text: str,
                            base: bytes = ZERO_PCR_SHA1) -> PCRReplayResult:
    """Replay PCR-10 from the ASCII log's SHA-1 template-hash column."""
    if len(base) != 20:
        raise ValueError(f"PCR SHA-1 base must be 20 bytes, got {len(base)}")

    state = base
    used = 0
    skipped = 0
    for pcr_index, template_hash_hex in ascii_ima_entries(log_text):
        if pcr_index != 10:
            continue
        try:
            template_hash = bytes.fromhex(template_hash_hex)
        except ValueError:
            skipped += 1
            continue
        if len(template_hash) != 20:
            skipped += 1
            continue
        state = hashlib.sha1(state + template_hash).digest()
        used += 1

    return PCRReplayResult(
        pcr_hex=state.hex(),
        entry_count=used,
        skipped_count=skipped,
    )


def replay_pcr10_sha256_binary(entries: Iterable[IMABinaryEntry],
                               base: bytes = ZERO_PCR_SHA256) -> PCRReplayResult:
    """Replay PCR-10 SHA-256 bank from binary template_data."""
    if len(base) != 32:
        raise ValueError(f"PCR SHA-256 base must be 32 bytes, got {len(base)}")

    state = base
    used = 0
    skipped = 0
    for entry in entries:
        if entry.pcr_index != 10:
            continue
        template_hash = hashlib.sha256(entry.template_data).digest()
        state = hashlib.sha256(state + template_hash).digest()
        used += 1

    return PCRReplayResult(
        pcr_hex=state.hex(),
        entry_count=used,
        skipped_count=skipped,
    )


def count_ascii_ima_entries(log_text: str) -> int:
    return len([line for line in log_text.splitlines() if line.strip()])


def binary_ascii_template_hash_match(entries: Iterable[IMABinaryEntry],
                                     log_text: str) -> bool:
    binary_hashes = [entry.template_hash.hex() for entry in entries if entry.pcr_index == 10]
    ascii_hashes = [h for pcr, h in ascii_ima_entries(log_text) if pcr == 10]
    return binary_hashes == ascii_hashes


def find_first_existing(paths: Iterable[str]) -> Optional[str]:
    for path in paths:
        if os.path.exists(path):
            return path
    return None


def locate_ima_binary_log() -> str:
    path = find_first_existing(IMA_BINARY_PATHS)
    if not path:
        raise FileNotFoundError(
            "IMA binary log not found. Tried: " + ", ".join(IMA_BINARY_PATHS)
        )
    return path


def locate_ima_ascii_log() -> str:
    path = find_first_existing(IMA_ASCII_PATHS)
    if not path:
        raise FileNotFoundError(
            "IMA ASCII log not found. Tried: " + ", ".join(IMA_ASCII_PATHS)
        )
    return path


def locate_ima_count_path() -> Optional[str]:
    return find_first_existing(IMA_COUNT_PATHS)


def read_ima_binary_log(path: Optional[str] = None) -> Tuple[bytes, List[IMABinaryEntry]]:
    path = path or locate_ima_binary_log()
    with open(path, "rb") as f:
        blob = f.read()
    return blob, parse_ima_binary_log(blob)


def read_ima_ascii_log(path: Optional[str] = None) -> str:
    path = path or locate_ima_ascii_log()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def read_ima_count() -> int:
    path = locate_ima_count_path()
    if not path:
        return -1
    try:
        with open(path, "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except Exception:
        return -1


def read_pcr10_sha1() -> str:
    direct = PCR10_SHA1_PATHS[0]
    if os.path.exists(direct):
        with open(direct, "r", encoding="utf-8") as f:
            return f.read().strip().lower()

    # Fallback for older /sys/class/tpm/tpm0/pcrs format.
    pcrs = PCR10_SHA1_PATHS[1]
    if os.path.exists(pcrs):
        with open(pcrs, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("PCR-10:"):
                    return line.split(":", 1)[1].strip().lower()

    return ""


def read_pcr10_sha256() -> str:
    direct = PCR10_SHA256_PATHS[0]
    if os.path.exists(direct):
        with open(direct, "r", encoding="utf-8") as f:
            return f.read().strip().lower()
    return ""


def locate_rtmr_measurements_dir() -> str:
    for directory in RTMR_MEASUREMENTS_DIRS:
        if os.path.isdir(directory):
            return directory

    # Last resort: search the known tdx_guest roots without invoking shell.
    roots = (
        "/sys/devices/virtual/misc/tdx_guest",
        "/sys/class/misc/tdx_guest",
    )
    for root in roots:
        if not os.path.isdir(root):
            continue
        for current, _, files in os.walk(root):
            if any(name.startswith("rtmr3") for name in files):
                return current

    raise FileNotFoundError("TDX RTMR measurements directory not found")


def rtmr_attr_path(index: int, measurements_dir: Optional[str] = None) -> str:
    measurements_dir = measurements_dir or locate_rtmr_measurements_dir()
    prefixes = (f"rtmr{index}:sha384", f"rtmr{index}")
    for name in prefixes:
        path = os.path.join(measurements_dir, name)
        if os.path.exists(path):
            return path
    for name in os.listdir(measurements_dir):
        if name.startswith(f"rtmr{index}:"):
            return os.path.join(measurements_dir, name)
    raise FileNotFoundError(f"RTMR[{index}] attribute not found in {measurements_dir}")


def mrtd_attr_path(measurements_dir: Optional[str] = None) -> Optional[str]:
    measurements_dir = measurements_dir or locate_rtmr_measurements_dir()
    for name in ("mrtd:sha384", "mrtd"):
        path = os.path.join(measurements_dir, name)
        if os.path.exists(path):
            return path
    for name in os.listdir(measurements_dir):
        if name.startswith("mrtd:"):
            return os.path.join(measurements_dir, name)
    return None


def decode_mr_attr(raw: bytes) -> bytes:
    stripped = raw.strip()
    if len(raw) == 48:
        return raw
    if len(stripped) in (96, 97, 98):
        text = bytes(ch for ch in stripped if chr(ch) in "0123456789abcdefABCDEF")
        if len(text) == 96:
            return bytes.fromhex(text.decode("ascii"))
    if len(stripped) == 96:
        return bytes.fromhex(stripped.decode("ascii"))
    raise ValueError(f"unexpected MR attribute size: raw={len(raw)} stripped={len(stripped)}")


def read_mr_hex(path: str) -> str:
    with open(path, "rb") as f:
        return decode_mr_attr(f.read()).hex()


def write_rtmr_digest(path: str, digest: bytes) -> None:
    if len(digest) != 48:
        raise ValueError(f"RTMR digest must be 48 bytes, got {len(digest)}")
    with open(path, "wb", buffering=0) as f:
        written = f.write(digest)
    if written != 48:
        raise OSError(f"short RTMR write: wrote {written} of 48 bytes")


def hex_to_48(value: str) -> bytes:
    value = value.strip().lower()
    if value == "zero":
        return ZERO_RTMR_SHA384
    raw = bytes.fromhex(value)
    if len(raw) != 48:
        raise ValueError(f"expected 48-byte SHA-384 hex value, got {len(raw)} bytes")
    return raw


def load_json_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json_file(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
