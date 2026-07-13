#!/usr/bin/env python3
"""Focused tests for the production composed runtime evidence predicate."""

import base64
import hashlib
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from common.ima_rtmr3 import (
    parse_ima_binary_log,
    replay_pcr10_sha1_ascii,
    replay_pcr10_sha256_binary,
    replay_rtmr3,
)
from common.protocol import AttestationResponse
from common.runtime_agent import RUNTIME_EVIDENCE_VERSION
from common.runtime_verifier import expand_runtime_evidence, verify_runtime_evidence
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


if __name__ == "__main__":
    unittest.main()
