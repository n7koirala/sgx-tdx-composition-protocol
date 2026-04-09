"""
Unit tests for the IMA verifier module.

Tests IMA log parsing, PCR-10 replay, reference manifest checking,
and IMA log hash computation using synthetic test data.

Usage:
    python3 -m commissioning_phase.test_ima_verifier
    # or:
    python3 -m pytest commissioning_phase/test_ima_verifier.py -v
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest

# Add parent directory to path for direct execution
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from commissioning_phase.ima_verifier import (
    IMAEntry,
    parse_ima_ascii_log,
    replay_pcr10,
    replay_pcr10_sha1,
    verify_log_integrity,
    load_reference_manifest,
    verify_reference_manifest,
    compute_ima_log_hash,
)


# ---------------------------------------------------------------------------
# Sample IMA log data (synthetic)
# ---------------------------------------------------------------------------

# Generate deterministic SHA-1 template hashes for test entries
def _sha1_hex(data: str) -> str:
    return hashlib.sha1(data.encode()).hexdigest()


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


SAMPLE_IMA_LOG = f"""10 {_sha1_hex("boot_aggregate")} ima-ng sha256:{_sha256_hex("boot_aggregate_content")} boot_aggregate
10 {_sha1_hex("entry1")} ima-ng sha256:{_sha256_hex("/usr/bin/bash")} /usr/bin/bash
10 {_sha1_hex("entry2")} ima-ng sha256:{_sha256_hex("/usr/lib/x86_64-linux-gnu/libssl.so.3")} /usr/lib/x86_64-linux-gnu/libssl.so.3
10 {_sha1_hex("entry3")} ima-ng sha256:{_sha256_hex("/usr/bin/python3")} /usr/bin/python3
10 {_sha1_hex("entry4")} ima-ng sha256:{_sha256_hex("/usr/sbin/sshd")} /usr/sbin/sshd
"""


class TestIMAParser(unittest.TestCase):
    """Tests for IMA ASCII log parsing."""

    def test_parse_basic_log(self):
        entries = parse_ima_ascii_log(SAMPLE_IMA_LOG)
        self.assertEqual(len(entries), 5)

    def test_parse_entry_fields(self):
        entries = parse_ima_ascii_log(SAMPLE_IMA_LOG)
        entry = entries[1]  # /usr/bin/bash
        self.assertEqual(entry.pcr, 10)
        self.assertEqual(entry.template_hash, _sha1_hex("entry1"))
        self.assertEqual(entry.template_name, "ima-ng")
        self.assertEqual(entry.file_hash_algo, "sha256")
        self.assertEqual(entry.file_hash, _sha256_hex("/usr/bin/bash"))
        self.assertEqual(entry.file_path, "/usr/bin/bash")

    def test_parse_boot_aggregate(self):
        entries = parse_ima_ascii_log(SAMPLE_IMA_LOG)
        boot = entries[0]
        self.assertEqual(boot.file_path, "boot_aggregate")
        self.assertEqual(boot.pcr, 10)

    def test_parse_empty_log(self):
        entries = parse_ima_ascii_log("")
        self.assertEqual(len(entries), 0)

    def test_parse_whitespace_only(self):
        entries = parse_ima_ascii_log("   \n\n   \n")
        self.assertEqual(len(entries), 0)

    def test_parse_single_entry(self):
        log = f"10 {_sha1_hex('test')} ima-ng sha256:{_sha256_hex('test_file')} /test/file"
        entries = parse_ima_ascii_log(log)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].file_path, "/test/file")


class TestPCR10Replay(unittest.TestCase):
    """Tests for PCR-10 replay computation."""

    def test_replay_deterministic(self):
        """Same log should produce same PCR-10."""
        entries = parse_ima_ascii_log(SAMPLE_IMA_LOG)
        pcr1 = replay_pcr10_sha1(entries)
        pcr2 = replay_pcr10_sha1(entries)
        self.assertEqual(pcr1, pcr2)

    def test_replay_non_zero(self):
        """Replayed PCR-10 should not be all zeros (log has entries)."""
        entries = parse_ima_ascii_log(SAMPLE_IMA_LOG)
        pcr = replay_pcr10_sha1(entries)
        self.assertNotEqual(pcr, "0" * 40)

    def test_replay_sha1_length(self):
        """SHA-1 PCR should be 40 hex chars (20 bytes)."""
        entries = parse_ima_ascii_log(SAMPLE_IMA_LOG)
        pcr = replay_pcr10_sha1(entries)
        self.assertEqual(len(pcr), 40)

    def test_replay_sha256_length(self):
        """SHA-256 PCR should be 64 hex chars (32 bytes)."""
        entries = parse_ima_ascii_log(SAMPLE_IMA_LOG)
        pcr = replay_pcr10(entries, hash_algo="sha256")
        self.assertEqual(len(pcr), 64)

    def test_replay_empty_log(self):
        """Empty log should produce zero PCR."""
        pcr = replay_pcr10_sha1([])
        self.assertEqual(pcr, "0" * 40)

    def test_replay_manual_computation(self):
        """Manually verify the extend chain for a single entry."""
        log = f"10 {_sha1_hex('singleentry')} ima-ng sha256:{_sha256_hex('file')} /file"
        entries = parse_ima_ascii_log(log)

        # Manual computation: PCR = SHA1(zeros || template_hash)
        template_hash_bytes = bytes.fromhex(_sha1_hex("singleentry"))
        expected = hashlib.sha1(b'\x00' * 20 + template_hash_bytes).hexdigest()

        pcr = replay_pcr10_sha1(entries)
        self.assertEqual(pcr, expected)


class TestLogIntegrity(unittest.TestCase):
    """Tests for log integrity verification."""

    def test_integrity_match(self):
        """Replayed PCR-10 should match itself."""
        entries = parse_ima_ascii_log(SAMPLE_IMA_LOG)
        replayed = replay_pcr10_sha1(entries)

        match, r, a = verify_log_integrity(entries, replayed, hash_algo="sha1")
        self.assertTrue(match)
        self.assertEqual(r, a)

    def test_integrity_mismatch(self):
        """Wrong PCR-10 should not match."""
        entries = parse_ima_ascii_log(SAMPLE_IMA_LOG)

        match, r, a = verify_log_integrity(
            entries, "a" * 40, hash_algo="sha1"
        )
        self.assertFalse(match)

    def test_integrity_case_insensitive(self):
        """PCR-10 comparison should be case-insensitive."""
        entries = parse_ima_ascii_log(SAMPLE_IMA_LOG)
        replayed = replay_pcr10_sha1(entries)

        match, _, _ = verify_log_integrity(
            entries, replayed.upper(), hash_algo="sha1"
        )
        self.assertTrue(match)


class TestReferenceManifest(unittest.TestCase):
    """Tests for reference manifest loading and verification."""

    def setUp(self):
        """Create a temp manifest file for testing."""
        self._entries = parse_ima_ascii_log(SAMPLE_IMA_LOG)

        # Build a manifest that includes all entries except the last one
        self._manifest = {}
        for entry in self._entries[:-1]:  # Exclude /usr/sbin/sshd
            if entry.file_path and entry.file_path != "boot_aggregate":
                key = f"{entry.file_hash_algo}:{entry.file_hash}"
                self._manifest[key] = [entry.file_path]

    def test_all_entries_in_manifest(self):
        """No violations when all entries are in manifest."""
        # Add the missing entry
        last = self._entries[-1]
        key = f"{last.file_hash_algo}:{last.file_hash}"
        self._manifest[key] = [last.file_path]

        ok, violations = verify_reference_manifest(self._entries, self._manifest)
        self.assertTrue(ok)
        self.assertEqual(len(violations), 0)

    def test_unknown_entry_detected(self):
        """Missing entry should be flagged as violation."""
        ok, violations = verify_reference_manifest(
            self._entries, self._manifest, strict=True
        )
        self.assertFalse(ok)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["file_path"], "/usr/sbin/sshd")

    def test_empty_manifest(self):
        """Empty manifest should flag all non-boot entries."""
        ok, violations = verify_reference_manifest(
            self._entries, {}, strict=True
        )
        self.assertFalse(ok)
        # All entries except boot_aggregate should be violations
        non_boot = [e for e in self._entries
                     if e.pcr == 10 and e.file_path and e.file_path != "boot_aggregate"]
        self.assertEqual(len(violations), len(non_boot))

    def test_load_manifest_file(self):
        """Test loading a manifest from a JSON file."""
        manifest_data = {
            "version": "1.0",
            "image": "test",
            "entries": self._manifest,
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(manifest_data, f)
            tmppath = f.name

        try:
            loaded = load_reference_manifest(tmppath)
            self.assertEqual(len(loaded), len(self._manifest))
        finally:
            os.unlink(tmppath)


class TestIMALogHash(unittest.TestCase):
    """Tests for IMA log hashing."""

    def test_hash_deterministic(self):
        h1 = compute_ima_log_hash(SAMPLE_IMA_LOG)
        h2 = compute_ima_log_hash(SAMPLE_IMA_LOG)
        self.assertEqual(h1, h2)

    def test_hash_length(self):
        h = compute_ima_log_hash(SAMPLE_IMA_LOG)
        self.assertEqual(len(h), 64)  # SHA-256 hex

    def test_hash_changes_with_content(self):
        h1 = compute_ima_log_hash(SAMPLE_IMA_LOG)
        h2 = compute_ima_log_hash(SAMPLE_IMA_LOG + "\n10 extra extra extra extra extra")
        self.assertNotEqual(h1, h2)

    def test_hash_matches_stdlib(self):
        h = compute_ima_log_hash(SAMPLE_IMA_LOG)
        expected = hashlib.sha256(SAMPLE_IMA_LOG.encode("utf-8")).hexdigest()
        self.assertEqual(h, expected)


# ---------------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  IMA Verifier Unit Tests")
    print("=" * 60)
    unittest.main(verbosity=2)
