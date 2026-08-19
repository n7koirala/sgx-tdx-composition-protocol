#!/usr/bin/env python3
"""Focused tests for protocol-1.2 audit evidence serving."""

from __future__ import annotations

import asyncio
import base64
import tempfile
import unittest
from pathlib import Path

from run_vordr_sweep import verify_audit_evidence_response
from vordr_server import (
    FileCommandLogProvider,
    SGXVerifierRefreshBackend,
    SyntheticRefreshBackend,
    VordrServer,
)


class AuditArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = SGXVerifierRefreshBackend.__new__(SGXVerifierRefreshBackend)
        self.backend._audit_binary = b""
        self.backend._audit_ascii = b""
        self.backend._audit_entry_count = 0

    @staticmethod
    def evidence(start: int, total: int, binary: bytes, ascii_log: bytes) -> dict:
        return {
            "version": "ima-rtmr3-vtpm-v2",
            "ima_start_index": start,
            "ima_entry_count": total,
            "ima_binary_log_b64": base64.b64encode(binary).decode("ascii"),
            "ima_ascii_log_b64": base64.b64encode(ascii_log).decode("ascii"),
            "stream": {"epoch": "stream-1"},
        }

    def test_verified_deltas_form_start_zero_snapshot(self) -> None:
        first = self.backend._accumulate_audit_evidence(
            self.evidence(0, 2, b"binary-0-2", b"ascii-0-2")
        )
        second = self.backend._accumulate_audit_evidence(
            self.evidence(2, 3, b"binary-2-3", b"ascii-2-3")
        )

        self.assertEqual(first["ima_start_index"], 0)
        self.assertEqual(second["ima_start_index"], 0)
        self.assertEqual(second["ima_entry_count"], 3)
        self.assertEqual(
            base64.b64decode(second["ima_binary_log_b64"]),
            b"binary-0-2binary-2-3",
        )
        self.assertEqual(
            base64.b64decode(second["ima_ascii_log_b64"]),
            b"ascii-0-2ascii-2-3",
        )

    def test_non_contiguous_delta_is_rejected(self) -> None:
        self.backend._accumulate_audit_evidence(
            self.evidence(0, 2, b"binary", b"ascii")
        )
        with self.assertRaisesRegex(RuntimeError, "does not continue"):
            self.backend._accumulate_audit_evidence(
                self.evidence(1, 3, b"bad", b"bad")
            )


class AuditResponseTests(unittest.TestCase):
    def make_response(self, mode: str) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            command_log = Path(directory) / "commands.jsonl"
            command_log.write_text('{"command":"apt install curl"}\n', encoding="utf-8")
            backend = SyntheticRefreshBackend(
                latency_ms=0,
                evidence_mode=mode,
                synthetic_ima_entries=4,
                command_log_provider=FileCommandLogProvider(command_log),
            )
            state = backend.refresh(1)
            server = VordrServer(
                listen_host="127.0.0.1",
                port=0,
                listen_backlog=128,
                nofile_soft_limit=1024,
                nofile_hard_limit=1024,
                controller_id="wen-test",
                evidence_mode=mode,
                refresh_interval_s=30,
                backend=backend,
                proof_secret="test-secret",
                response_auth="hmac-sha256",
                require_sgx_signing_key=False,
                ssl_context=None,
            )
            server.state = state
            return asyncio.run(server._handle_verify({"nonce": "test-nonce"}))

    def test_mode2_omits_raw_tdx_quote(self) -> None:
        response = self.make_response("ima-audit")
        self.assertNotIn("raw_quote", response)
        sizes = verify_audit_evidence_response(response, "ima-audit")
        self.assertEqual(sizes["raw_quote_bytes"], 0)
        self.assertGreater(sizes["ima_log_bytes"], 0)

    def test_mode3_includes_raw_tdx_quote(self) -> None:
        response = self.make_response("full-audit")
        self.assertIn("raw_quote", response)
        sizes = verify_audit_evidence_response(response, "full-audit")
        self.assertGreater(sizes["raw_quote_bytes"], 0)

    def test_mode2_rejects_quote_leak(self) -> None:
        response = self.make_response("ima-audit")
        response["raw_quote"] = base64.b64encode(b"leak").decode("ascii")
        with self.assertRaisesRegex(ValueError, "leaked"):
            verify_audit_evidence_response(response, "ima-audit")


if __name__ == "__main__":
    unittest.main()
