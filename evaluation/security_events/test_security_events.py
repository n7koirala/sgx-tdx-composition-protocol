#!/usr/bin/env python3
"""Unit tests for the security-event policy and authorization helpers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from audit_security_events import (
    append_authorization,
    initialize_authorization_keys,
    read_authorizations,
    semantic_verdict,
    validate_authorizations,
)


class AuthorizationTests(unittest.TestCase):
    def test_signed_hash_chain_round_trip_and_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_key = root / "authorization-private.pem"
            public_key = root / "authorization-public.pem"
            log = root / "authorization.jsonl"
            initialize_authorization_keys(private_key, public_key)
            artifact = {
                "target_path": "/usr/local/bin/vordr-authorized-1",
                "candidate_sha256": "a" * 64,
                "package_name": "vordr-authorized-1",
            }
            for trial in (1, 2):
                append_authorization(
                    log,
                    private_key,
                    campaign_id="test-campaign",
                    scenario="authorized-package",
                    trial=trial,
                    artifact={**artifact, "target_path": f"{artifact['target_path']}-{trial}"},
                )
            public = load_pem_public_key(public_key.read_bytes())
            records = read_authorizations(log)
            self.assertEqual(len(validate_authorizations(records, public)), 2)

            records[0]["target_path"] = "/tmp/tampered"
            with self.assertRaises(Exception):
                validate_authorizations(records, public)


class PolicyTests(unittest.TestCase):
    def test_library_replacement_is_policy_violation(self) -> None:
        trigger = {
            "campaign_id": "campaign",
            "scenario": "shared-library-replacement",
            "trial": 1,
            "ima_count_before": 10,
            "target_path": "/opt/test/lib.so",
            "event_aliases": ["/opt/test/lib.so"],
            "candidate_sha256": "b" * 64,
        }
        entries = [
            {
                "index": 12,
                "path": "/opt/test/lib.so",
                "digest_algorithm": "sha256",
                "digest": "b" * 64,
            }
        ]
        verdict = semantic_verdict(
            "shared-library-replacement", {}, trigger, entries, []
        )
        self.assertEqual(verdict["verdict"], "VIOLATION")
        self.assertTrue(verdict["event_observed"])

    def test_authorized_package_requires_matching_record(self) -> None:
        trigger = {
            "campaign_id": "campaign",
            "scenario": "authorized-package",
            "trial": 1,
            "ima_count_before": 20,
            "target_path": "/usr/local/bin/authorized",
            "event_aliases": ["/usr/local/bin/authorized"],
            "candidate_sha256": "c" * 64,
        }
        entries = [
            {
                "index": 21,
                "path": trigger["target_path"],
                "digest_algorithm": "sha256",
                "digest": trigger["candidate_sha256"],
            }
        ]
        without_record = semantic_verdict(
            "authorized-package", {}, trigger, entries, []
        )
        self.assertEqual(without_record["verdict"], "VIOLATION")

        record = {
            "campaign_id": trigger["campaign_id"],
            "scenario": trigger["scenario"],
            "trial": trigger["trial"],
            "target_path": trigger["target_path"],
            "artifact_sha256": trigger["candidate_sha256"],
        }
        with_record = semantic_verdict(
            "authorized-package", {}, trigger, entries, [record]
        )
        self.assertEqual(with_record["verdict"], "COMPLIANT")

    def test_no_update_control_ignores_unrelated_activity(self) -> None:
        state = {
            "artifacts": {
                "shared-library-replacement": [
                    {
                        "target_path": "/opt/test/lib.so",
                        "baseline_sha256": "d" * 64,
                    }
                ],
                "binary-replacement": [],
            }
        }
        trigger = {"ima_count_before": 30}
        entries = [
            {
                "index": 31,
                "path": "/usr/bin/unrelated",
                "digest_algorithm": "sha256",
                "digest": "e" * 64,
            }
        ]
        verdict = semantic_verdict(
            "no-update", state, trigger, entries, []
        )
        self.assertEqual(verdict["verdict"], "COMPLIANT")


if __name__ == "__main__":
    unittest.main()
