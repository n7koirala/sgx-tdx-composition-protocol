#!/usr/bin/env python3
"""Focused tests for delegated-response authentication helpers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from scale_common import ResponseProofSigner, verify_ed25519_proof


class ResponseProofSignerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fields = {
            "controller_id": "wen-1",
            "nonce_echo": "nonce",
            "runtime_verdict": "CLEAN",
            "refresh_count": 7,
        }

    def test_sgx_derived_key_is_stable_for_same_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "mrsigner"
            key_path.write_bytes(bytes(range(32)))
            first = ResponseProofSigner(
                "ed25519",
                controller_id="wen-1",
                proof_secret="unused",
                require_sgx_key=True,
                sgx_key_path=str(key_path),
            )
            second = ResponseProofSigner(
                "ed25519",
                controller_id="wen-1",
                proof_secret="unused",
                require_sgx_key=True,
                sgx_key_path=str(key_path),
            )

            self.assertEqual(first.public_key_bytes, second.public_key_bytes)
            self.assertEqual(first.key_id, second.key_id)
            self.assertEqual(first.key_origin, "sgx-mrsigner-derived")

            proof = first.authenticate(self.fields)
            verify_ed25519_proof(
                first.public_key_bytes,
                proof["proof_signature_b64"],
                self.fields,
            )

    def test_signature_rejects_tampered_result(self) -> None:
        signer = ResponseProofSigner(
            "ed25519",
            controller_id="wen-1",
            proof_secret="unused",
        )
        proof = signer.authenticate(self.fields)
        tampered = dict(self.fields, runtime_verdict="RUNTIME_VIOLATION")
        with self.assertRaises(InvalidSignature):
            verify_ed25519_proof(
                signer.public_key_bytes,
                proof["proof_signature_b64"],
                tampered,
            )

    def test_required_sgx_key_fails_closed(self) -> None:
        with self.assertRaises(RuntimeError):
            ResponseProofSigner(
                "ed25519",
                controller_id="wen-1",
                proof_secret="unused",
                require_sgx_key=True,
                sgx_key_path="/definitely/missing/sgx-key",
            )


if __name__ == "__main__":
    unittest.main()

