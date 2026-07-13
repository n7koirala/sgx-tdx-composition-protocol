"""CVM-side composed IMA, RTMR[3], and vTPM evidence collector."""

from __future__ import annotations

import base64
import threading
import time
from datetime import datetime, timezone
from typing import Callable, List, Tuple

from .ima_rtmr3 import (
    IMABinaryEntry,
    count_ascii_ima_entries,
    find_pcr10_sha256_prefix,
    locate_ima_ascii_log,
    locate_ima_binary_log,
    locate_rtmr_measurements_dir,
    read_ima_ascii_log,
    read_ima_binary_log,
    read_ima_count,
    read_mr_hex,
    read_pcr10_sha1,
    read_pcr10_sha256,
    replay_pcr10_sha256_binary,
    replay_rtmr3,
    rtmr_attr_path,
    write_rtmr_digest,
)
from .vtpm_quote import VtpmAk, rtmr_extend


RUNTIME_EVIDENCE_VERSION = "ima-rtmr3-vtpm-v1"
TDXQuoteCallback = Callable[[str], Tuple[bytes, str]]


class RuntimeEvidenceAgent:
    """Anchor IMA in RTMR[3] and collect nonce-bound composed evidence."""

    def __init__(self, quote_tdx: TDXQuoteCallback, poll_interval: float = 1.0):
        self.quote_tdx = quote_tdx
        self.poll_interval = poll_interval
        self.ima_binary_path = locate_ima_binary_log()
        self.ima_ascii_path = locate_ima_ascii_log()
        measurements_dir = locate_rtmr_measurements_dir()
        self.rtmr3_path = rtmr_attr_path(3, measurements_dir)
        self.vtpm = VtpmAk()

        self._lock = threading.Lock()
        self._watcher = None
        self.running = False
        self.anchored_count = 0
        self.anchor_started_at = ""
        self.rtmr3_base_before_start = ""
        self.rtmr3_after_ak_bind = ""
        self.rtmr3_after_startup_replay = ""
        self.extend_errors: List[str] = []
        self.stats = {
            "startup_extend_ms": 0.0,
            "incremental_extends": 0,
        }

    def _extend_entries_locked(
        self, entries: List[IMABinaryEntry], start_index: int
    ) -> None:
        for entry in entries[start_index:]:
            write_rtmr_digest(self.rtmr3_path, entry.rtmr_extend_digest())
            self.anchored_count += 1
            if self.anchored_count % 1000 == 0:
                print(f"    [RTMR3] anchored {self.anchored_count:,} IMA entries")

    def anchor_startup_log(self) -> None:
        """Bind the AK first, then replay every existing IMA event."""
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

            t0 = time.perf_counter()
            _, entries = read_ima_binary_log(self.ima_binary_path)
            self._extend_entries_locked(entries, 0)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            self.stats["startup_extend_ms"] = round(elapsed_ms, 3)
            self.rtmr3_after_startup_replay = read_mr_hex(self.rtmr3_path)

            expected = replay_rtmr3(
                entries, base=bytes.fromhex(self.rtmr3_after_ak_bind)
            ).hex()
            if expected != self.rtmr3_after_startup_replay:
                raise RuntimeError(
                    "startup RTMR3 replay mismatch: "
                    f"expected={expected}, actual={self.rtmr3_after_startup_replay}"
                )

            print(
                f"[RTMR3] startup anchored {self.anchored_count:,} entries "
                f"in {elapsed_ms:.1f} ms"
            )
            print(f"[RTMR3] base    : {self.rtmr3_base_before_start}")
            print(f"[RTMR3] after AK: {self.rtmr3_after_ak_bind}")
            print(f"[RTMR3] current : {self.rtmr3_after_startup_replay}")

    def _sync_new_entries_locked(self):
        blob, entries = read_ima_binary_log(self.ima_binary_path)
        if len(entries) < self.anchored_count:
            raise RuntimeError(
                "IMA log appears shorter than anchored count: "
                f"parsed={len(entries)}, anchored={self.anchored_count}"
            )

        new_count = len(entries) - self.anchored_count
        if new_count:
            self._extend_entries_locked(entries, self.anchored_count)
            self.stats["incremental_extends"] += new_count
            print(
                f"[RTMR3] extended {new_count:,} new IMA "
                f"entr{'y' if new_count == 1 else 'ies'} "
                f"(total={self.anchored_count:,})"
            )
        return blob, entries, new_count

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

    def start(self) -> None:
        if self.running:
            raise RuntimeError("runtime evidence agent is already running")
        self.anchor_startup_log()
        self.running = True
        self._watcher = threading.Thread(target=self._watch_loop, daemon=True)
        self._watcher.start()

    def stop(self) -> None:
        self.running = False

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

    def collect(self, nonce: str, ima_offset: int = 0) -> Tuple[bytes, str, dict]:
        """Collect one internally aligned composed-evidence response."""
        if not self.running:
            raise RuntimeError("runtime evidence agent has not been started")

        with self._lock:
            max_attempts = 8
            last = None

            nonce_bytes = base64.b64decode(nonce)
            for attempt in range(1, max_attempts + 1):
                vtpm = self.vtpm.quote_pcr10(nonce_bytes, bank="sha256")
                ima_blob, entries, new_count = self._sync_new_entries_locked()
                ima_ascii_log = read_ima_ascii_log(self.ima_ascii_path)
                ascii_count = count_ascii_ima_entries(ima_ascii_log)
                ima_count_before = read_ima_count()

                full_replay = replay_pcr10_sha256_binary(entries).pcr_hex
                vtpm_pcr10 = self._vtpm_pcr10_hex(vtpm)
                prefix_count, prefix_replay = find_pcr10_sha256_prefix(
                    entries, vtpm_pcr10
                )
                pre_quote_consistent = (
                    ima_count_before == len(entries) and ascii_count == len(entries)
                )
                signed_prefix_match = bool(vtpm_pcr10) and prefix_count is not None
                evidence_consistent = pre_quote_consistent and signed_prefix_match

                quote_bytes = b""
                mrtd = ""
                if evidence_consistent:
                    quote_bytes, mrtd = self.quote_tdx(nonce)

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
                    "replayed_pcr10_at_prefix": prefix_replay.pcr_hex,
                    "replayed_pcr10_at_snapshot": full_replay,
                    "post_quote_drift": post_quote_drift,
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    "ima_entries": len(entries),
                    "ima_count_before": ima_count_before,
                    "ima_count_after": ima_count_after,
                    "ima_ascii_entries": ascii_count,
                    "new_entries_synced_for_request": new_count,
                }
                last = (
                    quote_bytes,
                    mrtd,
                    vtpm,
                    ima_blob,
                    ima_ascii_log,
                    entries,
                    pcr10_sha1,
                    pcr10_sha256,
                    rtmr3_current,
                    snapshot,
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

            if last is None or not last[-1].get("consistent", False):
                snapshot = last[-1] if last else {}
                raise RuntimeError(
                    "failed to collect aligned vTPM PCR-10 / IMA / RTMR3 "
                    f"evidence after {max_attempts} attempts; last snapshot={snapshot}"
                )

            (
                quote_bytes,
                mrtd,
                vtpm,
                ima_blob,
                ima_ascii_log,
                entries,
                pcr10_sha1,
                pcr10_sha256,
                rtmr3_current,
                snapshot,
            ) = last

            start_index = (
                ima_offset
                if isinstance(ima_offset, int) and 0 <= ima_offset <= len(entries)
                else 0
            )
            binary_delta = b"".join(
                entry.raw_event for entry in entries[start_index:]
            )
            ascii_lines = ima_ascii_log.splitlines(keepends=True)
            if len(ascii_lines) != len(entries):
                start_index = 0
                binary_delta = ima_blob
            ascii_delta = "".join(ascii_lines[start_index:])

            evidence = {
                "version": RUNTIME_EVIDENCE_VERSION,
                **vtpm,
                "ima_binary_log_b64": base64.b64encode(binary_delta).decode("ascii"),
                "ima_ascii_log_b64": base64.b64encode(
                    ascii_delta.encode("utf-8")
                ).decode("ascii"),
                "ima_start_index": start_index,
                "ima_entry_count": len(entries),
                "pcr10_sha1_debug": pcr10_sha1,
                "pcr10_sha256_debug": pcr10_sha256,
                "snapshot": snapshot,
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
        }
