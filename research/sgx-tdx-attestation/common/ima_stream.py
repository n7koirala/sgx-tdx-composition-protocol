"""Persistent incremental readers for the Linux IMA seq_file interfaces."""

from __future__ import annotations

import os
import time
from dataclasses import asdict, dataclass
from typing import List, Optional

from .ima_rtmr3 import (
    IMABinaryEntry,
    ascii_ima_entries,
    locate_ima_count_path,
    parse_ima_binary_stream,
)


DEFAULT_READ_SIZE = 4 * 1024 * 1024


@dataclass
class IMAStreamSync:
    kernel_count_before: int
    kernel_count_after: int
    binary_entries_before: int
    binary_entries_after: int
    ascii_entries_before: int
    ascii_entries_after: int
    binary_bytes_read: int
    ascii_bytes_read: int
    binary_read_calls: int
    ascii_read_calls: int
    count_check_ms: float
    binary_read_ms: float
    ascii_read_ms: float
    parse_ms: float
    total_ms: float
    fast_path: bool
    fd_generation: int

    @property
    def delta_entries(self) -> int:
        return self.binary_entries_after - self.binary_entries_before

    def to_dict(self) -> dict:
        value = asdict(self)
        value["delta_entries"] = self.delta_entries
        value["reader_mode"] = "persistent-fd"
        return value


class PersistentIMAStream:
    """Keep binary and ASCII IMA pseudo-file descriptors open across rounds.

    The kernel measurement count is checked before touching either seq_file.
    If it has not changed, synchronization performs no pseudo-file read. When
    entries exist, only bytes available after the descriptors' current logical
    positions are read and parsed.
    """

    def __init__(
        self,
        binary_path: str,
        ascii_path: str,
        count_path: Optional[str] = None,
        *,
        read_size: int = DEFAULT_READ_SIZE,
    ):
        self.binary_path = binary_path
        self.ascii_path = ascii_path
        self.count_path = count_path or locate_ima_count_path()
        self.read_size = read_size
        self.binary_entries: List[IMABinaryEntry] = []
        self.ascii_lines: List[str] = []
        self._binary_pending = b""
        self._ascii_pending = b""
        self._binary_fd: Optional[int] = None
        self._ascii_fd: Optional[int] = None
        self.fd_generation = 0
        self.reset_count = 0
        self.total_binary_bytes_read = 0
        self.total_ascii_bytes_read = 0
        self.total_read_calls = 0
        self.fast_path_hits = 0
        self.last_sync: Optional[IMAStreamSync] = None
        self._validated_count = 0

    @property
    def entry_count(self) -> int:
        return len(self.binary_entries)

    @property
    def ascii_count(self) -> int:
        return len(self.ascii_lines)

    @property
    def descriptors_open(self) -> bool:
        return self._binary_fd is not None and self._ascii_fd is not None

    def open(self) -> None:
        if self.descriptors_open:
            return
        self.close()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        self._binary_fd = os.open(self.binary_path, flags)
        try:
            self._ascii_fd = os.open(self.ascii_path, flags)
        except Exception:
            os.close(self._binary_fd)
            self._binary_fd = None
            raise
        self.fd_generation += 1

    def close(self) -> None:
        for name in ("_binary_fd", "_ascii_fd"):
            fd = getattr(self, name)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, name, None)

    def _read_count(self) -> int:
        if not self.count_path:
            return -1
        try:
            with open(self.count_path, "r", encoding="utf-8") as handle:
                return int(handle.read().strip())
        except (OSError, ValueError):
            return -1

    def _drain(self, fd: int) -> tuple[bytes, int]:
        chunks = []
        calls = 0
        while True:
            chunk = os.read(fd, self.read_size)
            calls += 1
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), calls

    def sync(self) -> IMAStreamSync:
        self.open()
        started = time.perf_counter()
        count_started = time.perf_counter()
        kernel_before = self._read_count()
        count_ms = (time.perf_counter() - count_started) * 1000.0
        binary_before = self.entry_count
        ascii_before = self.ascii_count

        no_pending = not self._binary_pending and not self._ascii_pending
        if (
            kernel_before >= 0
            and kernel_before == binary_before
            and kernel_before == ascii_before
            and no_pending
        ):
            self.fast_path_hits += 1
            result = IMAStreamSync(
                kernel_before,
                kernel_before,
                binary_before,
                binary_before,
                ascii_before,
                ascii_before,
                0,
                0,
                0,
                0,
                count_ms,
                0.0,
                0.0,
                0.0,
                (time.perf_counter() - started) * 1000.0,
                True,
                self.fd_generation,
            )
            self.last_sync = result
            return result

        if kernel_before >= 0 and kernel_before < min(binary_before, ascii_before):
            raise RuntimeError(
                "IMA measurement count moved backwards: "
                f"kernel={kernel_before}, binary={binary_before}, ascii={ascii_before}"
            )

        binary_started = time.perf_counter()
        binary_raw, binary_calls = self._drain(self._binary_fd)
        binary_ms = (time.perf_counter() - binary_started) * 1000.0

        ascii_started = time.perf_counter()
        ascii_raw, ascii_calls = self._drain(self._ascii_fd)
        ascii_ms = (time.perf_counter() - ascii_started) * 1000.0

        parse_started = time.perf_counter()
        binary_input = self._binary_pending + binary_raw
        parsed, consumed = parse_ima_binary_stream(
            binary_input, start_index=binary_before
        )
        self._binary_pending = binary_input[consumed:]
        self.binary_entries.extend(parsed)

        ascii_input = self._ascii_pending + ascii_raw
        complete = ascii_input.rsplit(b"\n", 1)
        if len(complete) == 2:
            complete_bytes, self._ascii_pending = complete
            if complete_bytes:
                decoded = complete_bytes.decode("utf-8", errors="replace")
                self.ascii_lines.extend(
                    line + "\n" for line in decoded.splitlines() if line.strip()
                )
        else:
            self._ascii_pending = ascii_input
        parse_ms = (time.perf_counter() - parse_started) * 1000.0

        count_started = time.perf_counter()
        kernel_after = self._read_count()
        count_ms += (time.perf_counter() - count_started) * 1000.0

        self.total_binary_bytes_read += len(binary_raw)
        self.total_ascii_bytes_read += len(ascii_raw)
        self.total_read_calls += binary_calls + ascii_calls

        result = IMAStreamSync(
            kernel_before,
            kernel_after,
            binary_before,
            self.entry_count,
            ascii_before,
            self.ascii_count,
            len(binary_raw),
            len(ascii_raw),
            binary_calls,
            ascii_calls,
            count_ms,
            binary_ms,
            ascii_ms,
            parse_ms,
            (time.perf_counter() - started) * 1000.0,
            False,
            self.fd_generation,
        )
        self.last_sync = result
        return result

    def sync_aligned(self, max_attempts: int = 8) -> IMAStreamSync:
        last = None
        for _ in range(max_attempts):
            last = self.sync()
            kernel = last.kernel_count_after
            aligned = self.entry_count == self.ascii_count
            caught_up = kernel < 0 or self.entry_count == kernel
            if aligned and caught_up and not self._binary_pending and not self._ascii_pending:
                ascii_delta = ascii_ima_entries(
                    "".join(self.ascii_lines[self._validated_count:])
                )
                binary_delta = self.binary_entries[self._validated_count:]
                if len(ascii_delta) != len(binary_delta):
                    raise RuntimeError(
                        "new binary and ASCII IMA entry counts diverged"
                    )
                for entry, (pcr_index, template_hash) in zip(
                    binary_delta, ascii_delta
                ):
                    if (
                        entry.pcr_index != pcr_index
                        or entry.template_hash.hex() != template_hash
                    ):
                        raise RuntimeError(
                            "binary and ASCII IMA streams diverged at "
                            f"entry {entry.index}"
                        )
                self._validated_count = self.entry_count
                return last
            time.sleep(0.01)
        raise RuntimeError(
            "persistent IMA streams did not align: "
            f"kernel={last.kernel_count_after if last else -1}, "
            f"binary={self.entry_count}, ascii={self.ascii_count}, "
            f"binary_pending={len(self._binary_pending)}, "
            f"ascii_pending={len(self._ascii_pending)}"
        )

    def reset(self, *, validate_prefix: bool = True) -> IMAStreamSync:
        old_binary = self.binary_entries
        old_ascii = self.ascii_lines
        self.close()
        self.binary_entries = []
        self.ascii_lines = []
        self._binary_pending = b""
        self._ascii_pending = b""
        self._validated_count = 0
        self.reset_count += 1
        result = self.sync_aligned()
        if validate_prefix:
            prefix = min(len(old_binary), self.entry_count)
            for index in range(prefix):
                if old_binary[index].raw_event != self.binary_entries[index].raw_event:
                    raise RuntimeError(
                        f"IMA binary stream changed at retained entry {index}"
                    )
            ascii_prefix = min(len(old_ascii), self.ascii_count)
            if old_ascii[:ascii_prefix] != self.ascii_lines[:ascii_prefix]:
                raise RuntimeError("IMA ASCII stream changed before reset position")
        return result

    def binary_delta(self, start: int) -> bytes:
        return b"".join(entry.raw_event for entry in self.binary_entries[start:])

    def ascii_delta(self, start: int) -> str:
        return "".join(self.ascii_lines[start:])

    def metrics(self) -> dict:
        return {
            "reader_mode": "persistent-fd",
            "fd_generation": self.fd_generation,
            "descriptors_open": self.descriptors_open,
            "entry_count": self.entry_count,
            "ascii_count": self.ascii_count,
            "fast_path_hits": self.fast_path_hits,
            "reset_count": self.reset_count,
            "total_binary_bytes_read": self.total_binary_bytes_read,
            "total_ascii_bytes_read": self.total_ascii_bytes_read,
            "total_read_calls": self.total_read_calls,
            "last_sync": self.last_sync.to_dict() if self.last_sync else {},
        }
