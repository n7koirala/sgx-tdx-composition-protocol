"""CVM-side composed IMA, RTMR[3], and vTPM evidence collector."""

from __future__ import annotations

import base64
import hashlib
import threading
import time
from datetime import datetime, timezone
from typing import Callable, List, Tuple

from .ima_rtmr3 import (
    IMABinaryEntry,
    ZERO_PCR_SHA256,
    ZERO_TEMPLATE_SHA1,
    locate_ima_ascii_log,
    locate_ima_binary_log,
    locate_rtmr_measurements_dir,
    read_ima_count,
    read_mr_hex,
    read_pcr10_sha1,
    read_pcr10_sha256,
    rtmr_attr_path,
    write_rtmr_digest,
)
from .ima_stream import PersistentIMAStream
from .vtpm_quote import VtpmAk, rtmr_extend


RUNTIME_EVIDENCE_VERSION = "ima-rtmr3-vtpm-v2"
TDXQuoteCallback = Callable[[str], Tuple[bytes, str]]


class RuntimeEvidenceAgent:
    """Anchor IMA in RTMR[3] and collect nonce-bound incremental evidence."""

    def __init__(self, quote_tdx: TDXQuoteCallback, poll_interval: float = 1.0):
        self.quote_tdx = quote_tdx
        self.poll_interval = poll_interval
        self.ima_binary_path = locate_ima_binary_log()
        self.ima_ascii_path = locate_ima_ascii_log()
        measurements_dir = locate_rtmr_measurements_dir()
        self.rtmr3_path = rtmr_attr_path(3, measurements_dir)
        self.vtpm = VtpmAk()
        self.stream = PersistentIMAStream(
            self.ima_binary_path, self.ima_ascii_path
        )

        self._lock = threading.Lock()
        self._watcher = None
        self.running = False
        self.anchored_count = 0
        self.anchor_started_at = ""
        self.stream_epoch = ""
        self.rtmr3_base_before_start = ""
        self.rtmr3_after_ak_bind = ""
        self.rtmr3_after_startup_replay = ""
        self.extend_errors: List[str] = []
        self._rtmr_states: List[bytes] = []
        self._pcr10_sha256_state = ZERO_PCR_SHA256
        self._pcr10_states: List[bytes] = [ZERO_PCR_SHA256]
        self.stats = {
            "startup_extend_ms": 0.0,
            "incremental_extends": 0,
            "sync_requests": 0,
            "checkpoint_resyncs": 0,
        }

    @staticmethod
    def _pcr10_digest(entry: IMABinaryEntry) -> bytes:
        if entry.template_hash == ZERO_TEMPLATE_SHA1:
            return b"\xff" * 32
        return hashlib.sha256(entry.template_data).digest()

    def _extend_entries_locked(self, entries: List[IMABinaryEntry]) -> None:
        if not self._rtmr_states:
            raise RuntimeError("RTMR rolling state is not initialized")
        rtmr_state = self._rtmr_states[-1]
        for entry in entries:
            digest = entry.rtmr_extend_digest()
            write_rtmr_digest(self.rtmr3_path, digest)
            rtmr_state = rtmr_extend(rtmr_state, digest)
            self._rtmr_states.append(rtmr_state)

            if entry.pcr_index == 10:
                self._pcr10_sha256_state = hashlib.sha256(
                    self._pcr10_sha256_state + self._pcr10_digest(entry)
                ).digest()
            self._pcr10_states.append(self._pcr10_sha256_state)

            self.anchored_count += 1
            if self.anchored_count % 1000 == 0:
                print(f"    [RTMR3] anchored {self.anchored_count:,} IMA entries")

    def anchor_startup_log(self) -> None:
        """Bind the AK first, then perform the one required full IMA read."""
        with self._lock:
            self.anchor_started_at = datetime.now(timezone.utc).isoformat()
            self.rtmr3_base_before_start = read_mr_hex(self.rtmr3_path)

            ak_digest = self.vtpm.ak_pub_sha384
            write_rtmr_digest(self.rtmr3_path, ak_digest)
            self.rtmr3_after_ak_bind = read_mr_hex(self.rtmr3_path)
            expected_ak = rtmr_extend(
                bytes.fromhex(self.rtmr3_base_before_start), ak_digest
            ).hex()
            if expected_ak != self.rtmr3_after_ak_bind:
                raise RuntimeError(
                    "AK-bind RTMR3 mismatch: "
                    f"expected={expected_ak}, actual={self.rtmr3_after_ak_bind}"
                )
            print(f"[RTMR3] AK bound: SHA384(ak_pub)={ak_digest.hex()[:24]}...")

            self.stream_epoch = hashlib.sha256(
                (
                    RUNTIME_EVIDENCE_VERSION
                    + self.anchor_started_at
                    + self.rtmr3_base_before_start
                    + self.rtmr3_after_ak_bind
                ).encode("ascii")
            ).hexdigest()
            self._rtmr_states = [bytes.fromhex(self.rtmr3_after_ak_bind)]

            t0 = time.perf_counter()
            startup_sync = self.stream.sync_aligned()
            self._extend_entries_locked(self.stream.binary_entries)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            self.stats["startup_extend_ms"] = round(elapsed_ms, 3)
            self.rtmr3_after_startup_replay = read_mr_hex(self.rtmr3_path)

            expected = self._rtmr_states[-1].hex()
            if expected != self.rtmr3_after_startup_replay:
                raise RuntimeError(
                    "startup RTMR3 replay mismatch: "
                    f"expected={expected}, actual={self.rtmr3_after_startup_replay}"
                )

            print(
                f"[RTMR3] startup anchored {self.anchored_count:,} entries "
                f"in {elapsed_ms:.1f} ms"
            )
            print(
                "[IMA-FD] persistent descriptors positioned at "
                f"{self.stream.entry_count:,} entries "
                f"(read={startup_sync.binary_bytes_read + startup_sync.ascii_bytes_read:,} bytes)"
            )
            print(f"[RTMR3] base    : {self.rtmr3_base_before_start}")
            print(f"[RTMR3] after AK: {self.rtmr3_after_ak_bind}")
            print(f"[RTMR3] current : {self.rtmr3_after_startup_replay}")

    def _sync_new_entries_locked(self):
        before = self.anchored_count
        sync = self.stream.sync_aligned()
        if self.stream.entry_count < before:
            raise RuntimeError(
                "IMA log appears shorter than anchored count: "
                f"parsed={self.stream.entry_count}, anchored={before}"
            )

        new_entries = self.stream.binary_entries[before:]
        if new_entries:
            self._extend_entries_locked(new_entries)
            self.stats["incremental_extends"] += len(new_entries)
            actual = read_mr_hex(self.rtmr3_path)
            expected = self._rtmr_states[-1].hex()
            if actual != expected:
                raise RuntimeError(
                    f"incremental RTMR3 mismatch: expected={expected}, actual={actual}"
                )
            print(
                f"[RTMR3] extended {len(new_entries):,} new IMA "
                f"entr{'y' if len(new_entries) == 1 else 'ies'} "
                f"(total={self.anchored_count:,}, "
                f"fd-read={sync.binary_bytes_read + sync.ascii_bytes_read:,} bytes, "
                f"{sync.total_ms:.2f}ms)"
            )
        return sync, new_entries

    def _watch_loop(self) -> None:
        while self.running:
            try:
                with self._lock:
                    self._sync_new_entries_locked()
            except Exception as exc:
                msg = f"{datetime.now(timezone.utc).isoformat()} {exc}"
                self.extend_errors.append(msg)
                print(f"[RTMR3] watcher error: {exc}")
            time.sleep(self.poll_interval)

    def start(self, *, start_watcher: bool = True) -> None:
        if self.running:
            raise RuntimeError("runtime evidence agent is already running")
        self.anchor_startup_log()
        self.running = True
        if start_watcher:
            self._watcher = threading.Thread(target=self._watch_loop, daemon=True)
            self._watcher.start()

    def stop(self) -> None:
        self.running = False
        if self._watcher and self._watcher.is_alive():
            self._watcher.join(timeout=max(1.0, self.poll_interval * 2))
        self.stream.close()

    def reset_stream(self) -> dict:
        """Reopen both seq_file descriptors and validate the retained prefix."""
        with self._lock:
            old_count = self.stream.entry_count
            sync = self.stream.reset(validate_prefix=True)
            if self.stream.entry_count > self.anchored_count:
                self._extend_entries_locked(
                    self.stream.binary_entries[self.anchored_count:]
                )
            self.stats["checkpoint_resyncs"] += 1
            return {
                "status": "ok",
                "old_count": old_count,
                "new_count": self.stream.entry_count,
                "sync": sync.to_dict(),
            }

    @staticmethod
    def _vtpm_pcr10_hex(vtpm: dict) -> str:
        bank = vtpm.get("vtpm_quote_bank", "sha256")
        pcrs = vtpm.get("vtpm_pcrs", {})
        if isinstance(pcrs, dict):
            value = pcrs.get(bank, {}).get("10", "")
            if value:
                return str(value).lower()
        raw_b64 = vtpm.get("vtpm_pcr_bin_b64", "")
        if raw_b64:
            return base64.b64decode(raw_b64)[:32].hex()
        return ""

    def _find_signed_pcr_prefix(
        self, target_hex: str, start_index: int
    ) -> int | None:
        target = target_hex.lower()
        if not 0 <= start_index <= self.anchored_count:
            start_index = 0
        if self._pcr10_states[start_index].hex() == target:
            return start_index
        for index in range(start_index, self.anchored_count):
            entry = self.stream.binary_entries[index]
            if (
                entry.pcr_index == 10
                and self._pcr10_states[index + 1].hex() == target
            ):
                return index + 1
        return None

    def _select_wire_start(
        self, requested: int, checkpoint_rtmr3: str, checkpoint_epoch: str
    ) -> tuple[int, bool, str]:
        if requested == 0:
            return 0, True, "full-request"
        if requested < 0 or requested > self.anchored_count:
            return 0, False, "offset-out-of-range"
        if checkpoint_epoch != self.stream_epoch:
            return 0, False, "agent-epoch-mismatch"
        expected = self._rtmr_states[requested].hex()
        if not checkpoint_rtmr3 or checkpoint_rtmr3.lower() != expected:
            return 0, False, "rtmr3-checkpoint-mismatch"
        return requested, True, "checkpoint-continued"

    def collect(
        self,
        nonce: str,
        ima_offset: int = 0,
        checkpoint_rtmr3: str = "",
        checkpoint_epoch: str = "",
        stream_action: str = "continue",
    ) -> Tuple[bytes, str, dict]:
        """Collect one internally aligned composed-evidence response."""
        if not self.running:
            raise RuntimeError("runtime evidence agent has not been started")

        with self._lock:
            collection_started = time.perf_counter()
            timing = {
                "stream_reset_ms": 0.0,
                "stream_sync_ms": 0.0,
                "sync_and_extend_ms": 0.0,
                "rtmr_extend_ms": 0.0,
                "ima_extraction_ms": 0.0,
                "vtpm_quote_ms": 0.0,
                "tdx_quote_ms": 0.0,
            }
            if stream_action == "reset":
                reset_started = time.perf_counter()
                reset_sync = self.stream.reset(validate_prefix=True)
                timing["stream_reset_ms"] = (
                    time.perf_counter() - reset_started
                ) * 1000.0
                timing["ima_extraction_ms"] += reset_sync.total_ms
                self.stats["checkpoint_resyncs"] += 1

            self.stats["sync_requests"] += 1
            prefix_start, request_checkpoint_match, _ = self._select_wire_start(
                ima_offset if isinstance(ima_offset, int) else 0,
                checkpoint_rtmr3,
                checkpoint_epoch,
            )
            if not request_checkpoint_match:
                prefix_start = 0
            max_attempts = 8
            last = None
            nonce_bytes = base64.b64decode(nonce)

            for attempt in range(1, max_attempts + 1):
                phase_started = time.perf_counter()
                vtpm = self.vtpm.quote_pcr10(nonce_bytes, bank="sha256")
                timing["vtpm_quote_ms"] += (
                    time.perf_counter() - phase_started
                ) * 1000.0

                phase_started = time.perf_counter()
                sync, new_entries = self._sync_new_entries_locked()
                sync_and_extend_ms = (
                    time.perf_counter() - phase_started
                ) * 1000.0
                timing["stream_sync_ms"] += sync.total_ms
                timing["sync_and_extend_ms"] += sync_and_extend_ms
                timing["ima_extraction_ms"] += sync.total_ms
                timing["rtmr_extend_ms"] += max(
                    0.0, sync_and_extend_ms - sync.total_ms
                )
                entries = self.stream.binary_entries
                ascii_count = self.stream.ascii_count
                ima_count_before = read_ima_count()

                vtpm_pcr10 = self._vtpm_pcr10_hex(vtpm)
                prefix_count = self._find_signed_pcr_prefix(
                    vtpm_pcr10, prefix_start
                )
                pre_quote_consistent = (
                    ima_count_before == len(entries) and ascii_count == len(entries)
                )
                signed_prefix_match = bool(vtpm_pcr10) and prefix_count is not None
                evidence_consistent = pre_quote_consistent and signed_prefix_match

                quote_bytes = b""
                mrtd = ""
                if evidence_consistent:
                    phase_started = time.perf_counter()
                    quote_bytes, mrtd = self.quote_tdx(nonce)
                    timing["tdx_quote_ms"] += (
                        time.perf_counter() - phase_started
                    ) * 1000.0

                pcr10_sha1 = read_pcr10_sha1()
                pcr10_sha256 = read_pcr10_sha256()
                ima_count_after = read_ima_count()
                rtmr3_current = read_mr_hex(self.rtmr3_path)
                post_quote_drift = max(0, ima_count_after - len(entries))
                snapshot = {
                    "consistent": evidence_consistent,
                    "count_stable": evidence_consistent and post_quote_drift == 0,
                    "pre_quote_consistent": pre_quote_consistent,
                    "pcr_signed_snapshot_match": signed_prefix_match,
                    "vtpm_pcr10_at_quote": vtpm_pcr10,
                    "vtpm_ima_prefix_entries": prefix_count,
                    "replayed_pcr10_at_prefix": (
                        vtpm_pcr10 if prefix_count is not None else ""
                    ),
                    "replayed_pcr10_at_snapshot": self._pcr10_sha256_state.hex(),
                    "post_quote_drift": post_quote_drift,
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    "ima_entries": len(entries),
                    "ima_count_before": ima_count_before,
                    "ima_count_after": ima_count_after,
                    "ima_ascii_entries": ascii_count,
                    "new_entries_synced_for_request": len(new_entries),
                }
                last = (
                    quote_bytes,
                    mrtd,
                    vtpm,
                    pcr10_sha1,
                    pcr10_sha256,
                    rtmr3_current,
                    snapshot,
                    sync,
                )

                if evidence_consistent:
                    if post_quote_drift:
                        print(
                            "    [SNAPSHOT] post-TDX-quote IMA drift "
                            f"({post_quote_drift} new entries); sent evidence "
                            "remains bound by signed PCR and quoted RTMR"
                        )
                    break

                print(
                    "    [SNAPSHOT] PCR/log not aligned "
                    f"(attempt={attempt}, entries={len(entries)}, "
                    f"ascii={ascii_count}); retrying"
                )

            if last is None or not last[6].get("consistent", False):
                snapshot = last[6] if last else {}
                raise RuntimeError(
                    "failed to collect aligned vTPM PCR-10 / IMA / RTMR3 "
                    f"evidence after {max_attempts} attempts; last snapshot={snapshot}"
                )

            (
                quote_bytes,
                mrtd,
                vtpm,
                pcr10_sha1,
                pcr10_sha256,
                rtmr3_current,
                snapshot,
                sync,
            ) = last

            start_index, checkpoint_match, start_reason = self._select_wire_start(
                ima_offset if isinstance(ima_offset, int) else 0,
                checkpoint_rtmr3,
                checkpoint_epoch,
            )
            if ima_offset and not checkpoint_match:
                print(
                    "    [IMA-FD] verifier checkpoint cannot continue "
                    f"({start_reason}); sending full recovery snapshot"
                )

            timing["total_ms"] = (
                time.perf_counter() - collection_started
            ) * 1000.0
            timing = {name: round(value, 6) for name, value in timing.items()}

            binary_delta = self.stream.binary_delta(start_index)
            ascii_delta = self.stream.ascii_delta(start_index)
            evidence = {
                "version": RUNTIME_EVIDENCE_VERSION,
                **vtpm,
                "ima_binary_log_b64": base64.b64encode(binary_delta).decode("ascii"),
                "ima_ascii_log_b64": base64.b64encode(
                    ascii_delta.encode("utf-8")
                ).decode("ascii"),
                "ima_start_index": start_index,
                "ima_entry_count": self.stream.entry_count,
                "pcr10_sha1_debug": pcr10_sha1,
                "pcr10_sha256_debug": pcr10_sha256,
                "snapshot": snapshot,
                "timing": timing,
                "stream": {
                    "epoch": self.stream_epoch,
                    "requested_start_index": ima_offset,
                    "checkpoint_match": checkpoint_match,
                    "start_reason": start_reason,
                    "wire_delta_entries": self.stream.entry_count - start_index,
                    "wire_binary_bytes": len(binary_delta),
                    "wire_ascii_bytes": len(ascii_delta.encode("utf-8")),
                    "sync": sync.to_dict(),
                    "cumulative": self.stream.metrics(),
                },
                "anchor": {
                    "rtmr_index": 3,
                    "hash_alg": "sha384",
                    "canonical": (
                        "SHA384(CANON_MAGIC || LE32(pcr) || "
                        "LE32(len(template_hash)) || template_hash || "
                        "LE32(len(template_name)) || template_name || "
                        "LE32(len(template_data)) || template_data)"
                    ),
                    "rtmr3_base_before_start": self.rtmr3_base_before_start,
                    "rtmr3_after_ak_bind": self.rtmr3_after_ak_bind,
                    "ak_pub_sha384": self.vtpm.ak_pub_sha384.hex(),
                    "rtmr3_after_startup_replay": self.rtmr3_after_startup_replay,
                    "rtmr3_current": rtmr3_current,
                    "anchored_count": self.anchored_count,
                    "anchor_started_at": self.anchor_started_at,
                    "extend_errors": self.extend_errors[-5:],
                },
            }
            return quote_bytes, mrtd, evidence

    def banner_fields(self) -> dict:
        return {
            "evidence_version": RUNTIME_EVIDENCE_VERSION,
            "ima_binary_path": self.ima_binary_path,
            "ima_ascii_path": self.ima_ascii_path,
            "rtmr3_path": self.rtmr3_path,
            "ak_source": self.vtpm.source,
            "ak_sha384": self.vtpm.ak_pub_sha384.hex(),
            "ak_cert_present": self.vtpm.cert_der is not None,
            "anchored_count": self.anchored_count,
            "reader_mode": "persistent-fd",
        }
