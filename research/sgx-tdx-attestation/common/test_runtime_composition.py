#!/usr/bin/env python3
"""Focused tests for the production composed runtime evidence predicate."""

import base64
import hashlib
import os
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from common.ima_rtmr3 import (
    parse_ima_binary_log,
    replay_pcr10_sha1_ascii,
    replay_pcr10_sha256_binary,
    replay_rtmr3,
)
from common.ima_stream import PersistentIMAStream
from common.protocol import AttestationRequest, AttestationResponse, EndUserRequest
from common.runtime_agent import RUNTIME_EVIDENCE_VERSION
from common.runtime_verifier import (
    expand_runtime_evidence,
    verify_runtime_evidence,
    verify_runtime_incremental,
)
from common.sealed_checkpoint import CheckpointSealError, SealedCheckpointStore
from common.vtpm_quote import VtpmVerdict, rtmr_extend


def _event_blob(template_data: bytes) -> tuple[bytes, str]:
    template_hash = hashlib.sha1(template_data).digest()
    template_name = b"ima-ng\x00"
    event = b"".join(
        (
            struct.pack("<I", 10),
            template_hash,
            struct.pack("<I", len(template_name)),
            template_name,
            struct.pack("<I", len(template_data)),
            template_data,
        )
    )
    ascii_line = (
        f"10 {template_hash.hex()} ima-ng sha256:"
        f"{hashlib.sha256(b'file').hexdigest()} /test/file\n"
    )
    return event, ascii_line


class RuntimeCompositionTests(unittest.TestCase):
    def _evidence(self):
        blob, ascii_log = _event_blob(b"canonical-template-data")
        entries = parse_ima_binary_log(blob)
        base = b"\x00" * 48
        ak_digest = hashlib.sha384(b"ak-public-area").digest()
        after_ak = rtmr_extend(base, ak_digest)
        quoted_rtmr3 = replay_rtmr3(entries, base=after_ak).hex()
        pcr_sha256 = replay_pcr10_sha256_binary(entries).pcr_hex
        pcr_sha1 = replay_pcr10_sha1_ascii(ascii_log).pcr_hex
        evidence = {
            "version": RUNTIME_EVIDENCE_VERSION,
            "ima_binary_log_b64": base64.b64encode(blob).decode(),
            "ima_ascii_log_b64": base64.b64encode(ascii_log.encode()).decode(),
            "ima_entry_count": 1,
            "ak_pub_sha384": ak_digest.hex(),
            "pcr10_sha1_debug": pcr_sha1,
            "pcr10_sha256_debug": pcr_sha256,
            "snapshot": {
                "consistent": True,
                "vtpm_ima_prefix_entries": 1,
                "post_quote_drift": 0,
            },
            "anchor": {
                "rtmr3_base_before_start": base.hex(),
                "rtmr3_after_ak_bind": after_ak.hex(),
                "ak_pub_sha384": ak_digest.hex(),
                "rtmr3_current": quoted_rtmr3,
                "anchored_count": 1,
            },
        }
        quote_info = SimpleNamespace(
            mrtd="11" * 48,
            rtmr0="22" * 48,
            rtmr1="33" * 48,
            rtmr2="44" * 48,
            rtmr3=quoted_rtmr3,
        )
        vtpm = VtpmVerdict(
            ok=True,
            signature_ok=True,
            nonce_ok=True,
            quoted_pcr10=pcr_sha256,
            ak_sha384=ak_digest.hex(),
            cert_binds_ak=False,
        )
        return evidence, quote_info, vtpm

    def test_composed_predicate_accepts_valid_chain(self):
        evidence, quote_info, vtpm = self._evidence()
        with patch(
            "common.runtime_verifier.parse_dcap_quote", return_value=quote_info
        ), patch(
            "common.runtime_verifier.verify_pcr10_quote", return_value=vtpm
        ):
            verdict = verify_runtime_evidence(
                evidence, b"quote", base64.b64encode(b"n" * 32).decode()
            )
        self.assertTrue(verdict.ok, verdict.error)
        self.assertTrue(verdict.checks["rtmr3_replay"])
        self.assertTrue(verdict.checks["pcr10_signed_prefix"])
        self.assertTrue(verdict.checks["ak_bind_consistent"])

    def test_ascii_tamper_is_rejected(self):
        evidence, quote_info, vtpm = self._evidence()
        ascii_log = base64.b64decode(evidence["ima_ascii_log_b64"]).decode()
        evidence["ima_ascii_log_b64"] = base64.b64encode(
            ascii_log.replace("10 ", "10 f").encode()
        ).decode()
        with patch(
            "common.runtime_verifier.parse_dcap_quote", return_value=quote_info
        ), patch(
            "common.runtime_verifier.verify_pcr10_quote", return_value=vtpm
        ):
            verdict = verify_runtime_evidence(
                evidence, b"quote", base64.b64encode(b"n" * 32).decode()
            )
        self.assertFalse(verdict.ok)
        self.assertFalse(verdict.checks["binary_ascii_hashes"])

    def test_runtime_evidence_round_trip(self):
        evidence, _, _ = self._evidence()
        encoded = AttestationResponse(runtime_evidence=evidence).to_json()
        decoded = AttestationResponse.from_json(encoded)
        self.assertEqual(decoded.runtime_evidence["version"], RUNTIME_EVIDENCE_VERSION)
        self.assertEqual(decoded.runtime_evidence["ima_entry_count"], 1)

    def test_incremental_evidence_expands_verified_history(self):
        first_blob, first_ascii = _event_blob(b"first-template-data")
        second_blob, second_ascii = _event_blob(b"second-template-data")
        first = {
            "ima_start_index": 0,
            "ima_entry_count": 1,
            "ima_binary_log_b64": base64.b64encode(first_blob).decode(),
            "ima_ascii_log_b64": base64.b64encode(first_ascii.encode()).decode(),
        }
        _, prior_binary, prior_ascii = expand_runtime_evidence(first)

        second = {
            "ima_start_index": 1,
            "ima_entry_count": 2,
            "ima_binary_log_b64": base64.b64encode(second_blob).decode(),
            "ima_ascii_log_b64": base64.b64encode(second_ascii.encode()).decode(),
        }
        expanded, full_binary, full_ascii = expand_runtime_evidence(
            second, prior_binary, prior_ascii
        )

        self.assertEqual(len(parse_ima_binary_log(full_binary)), 2)
        self.assertEqual(len(full_ascii.splitlines()), 2)
        self.assertEqual(expanded["wire_ima_start_index"], 1)
        self.assertEqual(expanded["wire_ima_entry_count"], 1)

    def test_incremental_evidence_rejects_gap(self):
        blob, ascii_log = _event_blob(b"delta-template-data")
        evidence = {
            "ima_start_index": 2,
            "ima_entry_count": 3,
            "ima_binary_log_b64": base64.b64encode(blob).decode(),
            "ima_ascii_log_b64": base64.b64encode(ascii_log.encode()).decode(),
        }
        with self.assertRaisesRegex(ValueError, "does not continue verifier state"):
            expand_runtime_evidence(evidence)

    def test_request_checkpoint_fields_round_trip_without_affecting_end_user(self):
        request = AttestationRequest(
            nonce=base64.b64encode(b"n" * 32).decode(),
            ima_offset=42,
            ima_checkpoint_rtmr3="ab" * 48,
            runtime_epoch="epoch",
            stream_action="reset",
        )
        decoded = AttestationRequest.from_json(request.to_json())
        self.assertEqual(decoded.ima_offset, 42)
        self.assertEqual(decoded.ima_checkpoint_rtmr3, "ab" * 48)
        self.assertEqual(decoded.runtime_epoch, "epoch")
        self.assertEqual(decoded.stream_action, "reset")
        self.assertTrue(decoded.validate()[0])

        end_user = EndUserRequest(nonce="nonce")
        self.assertTrue(end_user.validate()[0])

    def test_persistent_stream_uses_count_only_fast_path_and_reads_delta(self):
        first_blob, first_ascii = _event_blob(b"stream-first")
        second_blob, second_ascii = _event_blob(b"stream-second")
        with tempfile.TemporaryDirectory() as directory:
            binary_path = os.path.join(directory, "binary")
            ascii_path = os.path.join(directory, "ascii")
            count_path = os.path.join(directory, "count")
            with open(binary_path, "wb") as handle:
                handle.write(first_blob)
            with open(ascii_path, "w", encoding="utf-8") as handle:
                handle.write(first_ascii)
            with open(count_path, "w", encoding="utf-8") as handle:
                handle.write("1")

            stream = PersistentIMAStream(
                binary_path, ascii_path, count_path, read_size=31
            )
            initial = stream.sync_aligned()
            self.assertFalse(initial.fast_path)
            self.assertEqual(stream.entry_count, 1)

            unchanged = stream.sync_aligned()
            self.assertTrue(unchanged.fast_path)
            self.assertEqual(unchanged.binary_bytes_read, 0)
            self.assertEqual(unchanged.ascii_bytes_read, 0)

            with open(binary_path, "ab") as handle:
                handle.write(second_blob)
            with open(ascii_path, "a", encoding="utf-8") as handle:
                handle.write(second_ascii)
            with open(count_path, "w", encoding="utf-8") as handle:
                handle.write("2")

            delta = stream.sync_aligned()
            self.assertFalse(delta.fast_path)
            self.assertEqual(delta.delta_entries, 1)
            self.assertEqual(stream.entry_count, 2)
            self.assertEqual(stream.binary_delta(1), second_blob)
            self.assertEqual(stream.ascii_delta(1), second_ascii)
            stream.close()

    def test_incremental_verifier_replays_only_wire_delta(self):
        first, quote1, vtpm1 = self._evidence()
        first["stream"] = {
            "epoch": "epoch-1",
            "checkpoint_match": True,
            "sync": {"reader_mode": "persistent-fd"},
        }
        with patch(
            "common.runtime_verifier.parse_dcap_quote", return_value=quote1
        ), patch(
            "common.runtime_verifier.verify_pcr10_quote", return_value=vtpm1
        ):
            verdict1, checkpoint1 = verify_runtime_incremental(
                first, b"quote-1", base64.b64encode(b"n" * 32).decode()
            )
        self.assertTrue(verdict1.ok, verdict1.error)
        self.assertIsNotNone(checkpoint1)

        blob2, ascii2 = _event_blob(b"second-incremental-event")
        entries2 = parse_ima_binary_log(blob2)
        rtmr3_2 = replay_rtmr3(
            entries2, base=bytes.fromhex(checkpoint1.rtmr3)
        ).hex()
        pcr256_2 = replay_pcr10_sha256_binary(
            entries2, base=bytes.fromhex(checkpoint1.pcr10_sha256)
        ).pcr_hex
        pcr_sha1_2 = replay_pcr10_sha1_ascii(
            ascii2, base=bytes.fromhex(checkpoint1.pcr10_sha1)
        ).pcr_hex
        quote2 = SimpleNamespace(
            mrtd=checkpoint1.mrtd,
            rtmr0=checkpoint1.rtmr0,
            rtmr1=checkpoint1.rtmr1,
            rtmr2=checkpoint1.rtmr2,
            rtmr3=rtmr3_2,
        )
        vtpm2 = VtpmVerdict(
            ok=True,
            signature_ok=True,
            nonce_ok=True,
            quoted_pcr10=pcr256_2,
            ak_sha384=checkpoint1.ak_pub_sha384,
            cert_binds_ak=False,
        )
        second = {
            "version": RUNTIME_EVIDENCE_VERSION,
            "ima_binary_log_b64": base64.b64encode(blob2).decode(),
            "ima_ascii_log_b64": base64.b64encode(ascii2.encode()).decode(),
            "ima_start_index": 1,
            "ima_entry_count": 2,
            "ak_pub_sha384": checkpoint1.ak_pub_sha384,
            "pcr10_sha1_debug": pcr_sha1_2,
            "pcr10_sha256_debug": pcr256_2,
            "snapshot": {
                "consistent": True,
                "vtpm_ima_prefix_entries": 2,
                "post_quote_drift": 0,
            },
            "stream": {
                "epoch": checkpoint1.stream_epoch,
                "checkpoint_match": True,
                "sync": {
                    "reader_mode": "persistent-fd",
                    "delta_entries": 1,
                },
            },
            "anchor": {
                "rtmr3_base_before_start": checkpoint1.rtmr3_base,
                "rtmr3_after_ak_bind": checkpoint1.rtmr3_after_ak,
                "ak_pub_sha384": checkpoint1.ak_pub_sha384,
                "rtmr3_current": rtmr3_2,
                "anchored_count": 2,
            },
        }
        with patch(
            "common.runtime_verifier.parse_dcap_quote", return_value=quote2
        ), patch(
            "common.runtime_verifier.verify_pcr10_quote", return_value=vtpm2
        ):
            verdict2, checkpoint2 = verify_runtime_incremental(
                second,
                b"quote-2",
                base64.b64encode(b"n" * 32).decode(),
                checkpoint1,
            )
        self.assertTrue(verdict2.ok, verdict2.error)
        self.assertEqual(verdict2.details["verification_mode"], "incremental-delta")
        self.assertEqual(verdict2.details["wire_ima_entries"], 1)
        self.assertEqual(checkpoint2.entry_count, 2)
        self.assertEqual(checkpoint2.generation, 2)

    def test_sealed_checkpoint_round_trip_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "checkpoint.bin")
            store = SealedCheckpointStore(
                path,
                "controller|tdx:8443",
                key_material=b"k" * 32,
            )
            value = {"entry_count": 140000, "rtmr3": "ab" * 48}
            store.save(value)
            self.assertEqual(store.load(), value)

            payload = bytearray(Path(path).read_bytes())
            payload[-1] ^= 1
            Path(path).write_bytes(payload)
            with self.assertRaises(CheckpointSealError):
                store.load()



if __name__ == "__main__":
    unittest.main()
