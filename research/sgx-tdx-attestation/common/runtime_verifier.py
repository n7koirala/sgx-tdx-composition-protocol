"""WEN-side verification for composed IMA, RTMR[3], and vTPM evidence."""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional

from .ima_rtmr3 import (
    ZERO_TEMPLATE_SHA1,
    binary_ascii_template_hash_match,
    count_ascii_ima_entries,
    find_pcr10_sha256_prefix,
    parse_ima_binary_log,
    replay_pcr10_sha1_ascii,
    replay_pcr10_sha256_binary,
    replay_rtmr3,
)
from .protocol import parse_dcap_quote
from .runtime_agent import RUNTIME_EVIDENCE_VERSION
from .vtpm_quote import rtmr_extend, verify_pcr10_quote


CHECKPOINT_VERSION = 1


@dataclass
class RuntimeEvidenceVerdict:
    ok: bool
    checks: Dict[str, bool] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class RuntimeCheckpoint:
    """Compact verified state needed to validate the next IMA delta."""

    checkpoint_version: int
    evidence_version: str
    entry_count: int
    stream_epoch: str
    rtmr3: str
    pcr10_sha256: str
    pcr10_sha1: str
    continuity_sha256: str
    ak_pub_sha384: str
    rtmr3_base: str
    rtmr3_after_ak: str
    mrtd: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    generation: int = 1

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict) -> "RuntimeCheckpoint":
        checkpoint = cls(**value)
        if checkpoint.checkpoint_version != CHECKPOINT_VERSION:
            raise ValueError(
                f"unsupported runtime checkpoint version "
                f"{checkpoint.checkpoint_version}"
            )
        if checkpoint.evidence_version != RUNTIME_EVIDENCE_VERSION:
            raise ValueError(
                f"checkpoint evidence version {checkpoint.evidence_version!r} "
                f"does not match {RUNTIME_EVIDENCE_VERSION!r}"
            )
        return checkpoint


def _resolve_rtmr3_base(
    requested: str, anchor: dict, golden: Optional[dict]
) -> tuple[bytes, str]:
    value = (requested or "auto").strip().lower()
    if value == "zero":
        return b"\x00" * 48, "explicit zero"
    if value != "auto":
        raw = bytes.fromhex(value)
        if len(raw) != 48:
            raise ValueError("expected RTMR3 base must be 48 bytes")
        return raw, "explicit command-line value"

    if golden and golden.get("rtmr3_base"):
        raw = bytes.fromhex(golden["rtmr3_base"])
        if len(raw) != 48:
            raise ValueError("golden RTMR3 base must be 48 bytes")
        return raw, "golden file"

    raw = bytes.fromhex(anchor.get("rtmr3_base_before_start", ""))
    if len(raw) != 48:
        raise ValueError("agent-reported RTMR3 base is missing or malformed")
    return raw, "agent-reported startup base"


def _golden_checks(quote_info, golden: Optional[dict]) -> tuple[bool, dict]:
    if not golden:
        return True, {}
    actual = {
        "mrtd": quote_info.mrtd.lower(),
        "rtmr0": quote_info.rtmr0.lower(),
        "rtmr1": quote_info.rtmr1.lower(),
        "rtmr2": quote_info.rtmr2.lower(),
    }
    checks = {}
    for name, value in actual.items():
        expected = str(golden.get(name, "")).strip().lower()
        checks[name] = bool(expected) and value == expected
    return all(checks.values()), checks


def _continuity_digest(
    prior_hex: str, start: int, total: int, binary_delta: bytes, ascii_delta: str
) -> str:
    prior = bytes.fromhex(prior_hex) if prior_hex else b"\x00" * 32
    return hashlib.sha256(
        b"VORDR-RUNTIME-CHECKPOINT-v1\x00"
        + prior
        + struct.pack("<QQ", start, total)
        + hashlib.sha256(binary_delta).digest()
        + hashlib.sha256(ascii_delta.encode("utf-8")).digest()
    ).hexdigest()


def expand_runtime_evidence(
    evidence: dict, prior_binary: bytes = b"", prior_ascii: str = ""
) -> tuple[dict, bytes, str]:
    """Legacy helper that expands a delta into full history for compatibility."""
    start = int(evidence.get("ima_start_index", 0))
    total = int(evidence.get("ima_entry_count", 0))
    wire_binary = base64.b64decode(evidence["ima_binary_log_b64"])
    wire_ascii = base64.b64decode(evidence["ima_ascii_log_b64"]).decode(
        "utf-8", errors="replace"
    )

    if start == 0:
        full_binary = wire_binary
        full_ascii = wire_ascii
    else:
        prior_entries = parse_ima_binary_log(prior_binary)
        prior_ascii_count = count_ascii_ima_entries(prior_ascii)
        if len(prior_entries) != start or prior_ascii_count != start:
            raise ValueError(
                "runtime delta does not continue verifier state: "
                f"start={start}, binary_prior={len(prior_entries)}, "
                f"ascii_prior={prior_ascii_count}"
            )
        full_binary = prior_binary + wire_binary
        full_ascii = prior_ascii + wire_ascii

    full_entries = parse_ima_binary_log(full_binary)
    full_ascii_count = count_ascii_ima_entries(full_ascii)
    if len(full_entries) != total or full_ascii_count != total:
        raise ValueError(
            "expanded runtime evidence count mismatch: "
            f"declared={total}, binary={len(full_entries)}, ascii={full_ascii_count}"
        )

    expanded = dict(evidence)
    expanded["wire_ima_start_index"] = start
    expanded["wire_ima_entry_count"] = total - start
    expanded["ima_binary_log_b64"] = base64.b64encode(full_binary).decode("ascii")
    expanded["ima_ascii_log_b64"] = base64.b64encode(
        full_ascii.encode("utf-8")
    ).decode("ascii")
    return expanded, full_binary, full_ascii


def verify_runtime_evidence(
    evidence: dict,
    quote_bytes: bytes,
    nonce_b64: str,
    *,
    expected_rtmr3_base: str = "auto",
    golden: Optional[dict] = None,
    require_golden: bool = False,
    require_ak_cert: bool = False,
) -> RuntimeEvidenceVerdict:
    """Verify a complete start-index-zero composed runtime snapshot."""
    try:
        quote_info = parse_dcap_quote(quote_bytes)
        ima_blob = base64.b64decode(evidence["ima_binary_log_b64"])
        entries = parse_ima_binary_log(ima_blob)
        ima_ascii = base64.b64decode(evidence["ima_ascii_log_b64"]).decode(
            "utf-8", errors="replace"
        )
        anchor = evidence.get("anchor", {})
        snapshot = evidence.get("snapshot", {})
        stream = evidence.get("stream", {})
        nonce_bytes = base64.b64decode(nonce_b64)

        vtpm = verify_pcr10_quote(evidence, nonce_bytes)
        ascii_count = count_ascii_ima_entries(ima_ascii)
        binary_ascii_count = ascii_count == len(entries)
        binary_ascii_hashes = binary_ascii_template_hash_match(entries, ima_ascii)

        rtmr3_base, base_source = _resolve_rtmr3_base(
            expected_rtmr3_base, anchor, golden
        )
        ak_field = str(evidence.get("ak_pub_sha384", "")).lower()
        anchor_ak = str(anchor.get("ak_pub_sha384", "")).lower()
        ak_bind_consistent = (
            bool(vtpm.ak_sha384)
            and vtpm.ak_sha384 == ak_field
            and vtpm.ak_sha384 == anchor_ak
        )

        base_after_ak = rtmr_extend(
            rtmr3_base, bytes.fromhex(vtpm.ak_sha384)
        )
        reported_after_ak = str(anchor.get("rtmr3_after_ak_bind", "")).lower()
        ak_rtmr_step = reported_after_ak == base_after_ak.hex()
        expected_rtmr3 = replay_rtmr3(entries, base=base_after_ak).hex()
        quoted_rtmr3 = quote_info.rtmr3.lower()
        rtmr3_replay = expected_rtmr3 == quoted_rtmr3
        rtmr3_metadata = str(anchor.get("rtmr3_current", "")).lower() == quoted_rtmr3

        full_sha256 = replay_pcr10_sha256_binary(entries)
        full_sha1 = replay_pcr10_sha1_ascii(ima_ascii)
        prefix_count, prefix_replay = find_pcr10_sha256_prefix(
            entries, vtpm.quoted_pcr10
        )
        reported_prefix = snapshot.get("vtpm_ima_prefix_entries")
        prefix_count_match = (
            reported_prefix is not None and reported_prefix == prefix_count
        )
        pcr10_signed = vtpm.ok and prefix_count is not None

        anchored_count = anchor.get("anchored_count")
        anchor_count_match = anchored_count == len(entries)
        snapshot_consistent = bool(snapshot.get("consistent", False))
        version_ok = evidence.get("version") == RUNTIME_EVIDENCE_VERSION
        start_zero = int(evidence.get("ima_start_index", 0)) == 0
        ak_cert_policy = vtpm.cert_binds_ak or not require_ak_cert
        golden_present = golden is not None
        golden_match, per_register_golden = _golden_checks(quote_info, golden)
        golden_policy = golden_match and (golden_present or not require_golden)

        claimed_sha1 = str(evidence.get("pcr10_sha1_debug", "")).lower()
        claimed_sha256 = str(evidence.get("pcr10_sha256_debug", "")).lower()
        debug_sha1_match = bool(claimed_sha1) and full_sha1.pcr_hex == claimed_sha1
        debug_sha256_match = (
            bool(claimed_sha256) and full_sha256.pcr_hex == claimed_sha256
        )

        checks = {
            "evidence_version": version_ok,
            "checkpoint_continuity": start_zero,
            "binary_ascii_count": binary_ascii_count,
            "binary_ascii_hashes": binary_ascii_hashes,
            "snapshot_consistent": snapshot_consistent,
            "anchor_count": anchor_count_match,
            "vtpm_signature": vtpm.signature_ok,
            "vtpm_nonce": vtpm.nonce_ok,
            "vtpm_quote": vtpm.ok,
            "ak_bind_consistent": ak_bind_consistent,
            "ak_rtmr_step": ak_rtmr_step,
            "rtmr3_replay": rtmr3_replay,
            "rtmr3_metadata": rtmr3_metadata,
            "pcr10_signed_prefix": pcr10_signed,
            "pcr10_prefix_count": prefix_count_match,
            "ak_cert_policy": ak_cert_policy,
            "golden_boot_policy": golden_policy,
        }
        ok = all(checks.values())

        warnings = []
        if not vtpm.cert_binds_ak and not require_ak_cert:
            warnings.append("Google AK certificate binding was not required")
        if not golden_present and not require_golden:
            warnings.append("MRTD/RTMR0-2 golden boot policy was not required")
        if base_source == "agent-reported startup base":
            warnings.append("RTMR3 startup base was accepted from agent metadata")
        if snapshot.get("post_quote_drift", 0):
            warnings.append(
                f"{snapshot['post_quote_drift']} IMA entries arrived after evidence capture"
            )

        details = {
            "verification_mode": "full",
            "ima_entries": len(entries),
            "wire_ima_entries": len(entries),
            "ima_ascii_entries": ascii_count,
            "anchored_count": anchored_count,
            "pcr10_prefix_entries": prefix_count,
            "agent_pcr10_prefix_entries": reported_prefix,
            "vtpm_quoted_pcr10_sha256": vtpm.quoted_pcr10,
            "replayed_pcr10_sha256": (
                prefix_replay.pcr_hex if prefix_count is not None else ""
            ),
            "full_replayed_pcr10_sha256": full_sha256.pcr_hex,
            "full_replayed_pcr10_sha1": full_sha1.pcr_hex,
            "debug_pcr10_sha1_match": debug_sha1_match,
            "debug_pcr10_sha256_match": debug_sha256_match,
            "ak_pub_sha384": vtpm.ak_sha384,
            "ak_cert_binds_ak": vtpm.cert_binds_ak,
            "vtpm_detail": vtpm.detail,
            "rtmr3_base": rtmr3_base.hex(),
            "rtmr3_base_source": base_source,
            "rtmr3_after_ak": base_after_ak.hex(),
            "expected_rtmr3": expected_rtmr3,
            "quoted_rtmr3": quoted_rtmr3,
            "snapshot": snapshot,
            "stream": stream,
            "agent_stream": stream.get("sync", {}),
            "agent_timing": evidence.get("timing", {}),
            "golden_checks": per_register_golden,
            "boot_measurements": {
                "mrtd": quote_info.mrtd.lower(),
                "rtmr0": quote_info.rtmr0.lower(),
                "rtmr1": quote_info.rtmr1.lower(),
                "rtmr2": quote_info.rtmr2.lower(),
            },
        }
        failed = [name for name, passed in checks.items() if not passed]
        return RuntimeEvidenceVerdict(
            ok=ok,
            checks=checks,
            details=details,
            warnings=warnings,
            error=("failed runtime checks: " + ", ".join(failed)) if failed else "",
        )
    except Exception as exc:
        return RuntimeEvidenceVerdict(
            ok=False,
            checks={"runtime_evidence_parse": False},
            error=f"runtime evidence verification error: {exc}",
        )


def _pcr256_digest(entry) -> bytes:
    if entry.template_hash == ZERO_TEMPLATE_SHA1:
        return b"\xff" * 32
    return hashlib.sha256(entry.template_data).digest()


def _find_delta_pcr_prefix(
    entries, target_hex: str, base: bytes, absolute_start: int
) -> tuple[Optional[int], str]:
    state = base
    target = target_hex.lower()
    if state.hex() == target:
        return absolute_start, state.hex()
    for relative, entry in enumerate(entries):
        if entry.pcr_index == 10:
            state = hashlib.sha256(state + _pcr256_digest(entry)).digest()
            if state.hex() == target:
                return absolute_start + relative + 1, state.hex()
    return None, state.hex()


def _checkpoint_from_full(
    evidence: dict, verdict: RuntimeEvidenceVerdict
) -> RuntimeCheckpoint:
    details = verdict.details
    boot = details["boot_measurements"]
    stream = evidence.get("stream", {})
    binary_log = base64.b64decode(evidence["ima_binary_log_b64"])
    ascii_log = base64.b64decode(evidence["ima_ascii_log_b64"]).decode(
        "utf-8", errors="replace"
    )
    total = details["ima_entries"]
    return RuntimeCheckpoint(
        checkpoint_version=CHECKPOINT_VERSION,
        evidence_version=RUNTIME_EVIDENCE_VERSION,
        entry_count=total,
        stream_epoch=str(stream.get("epoch", "")),
        rtmr3=details["quoted_rtmr3"],
        pcr10_sha256=details["full_replayed_pcr10_sha256"],
        pcr10_sha1=details["full_replayed_pcr10_sha1"],
        continuity_sha256=_continuity_digest(
            "", 0, total, binary_log, ascii_log
        ),
        ak_pub_sha384=details["ak_pub_sha384"],
        rtmr3_base=details["rtmr3_base"],
        rtmr3_after_ak=details["rtmr3_after_ak"],
        mrtd=boot["mrtd"],
        rtmr0=boot["rtmr0"],
        rtmr1=boot["rtmr1"],
        rtmr2=boot["rtmr2"],
    )


def _verify_runtime_delta(
    evidence: dict,
    quote_bytes: bytes,
    nonce_b64: str,
    prior: RuntimeCheckpoint,
    *,
    expected_rtmr3_base: str,
    golden: Optional[dict],
    require_golden: bool,
    require_ak_cert: bool,
) -> tuple[RuntimeEvidenceVerdict, Optional[RuntimeCheckpoint]]:
    try:
        quote_info = parse_dcap_quote(quote_bytes)
        binary_delta = base64.b64decode(evidence["ima_binary_log_b64"])
        ascii_delta = base64.b64decode(evidence["ima_ascii_log_b64"]).decode(
            "utf-8", errors="replace"
        )
        entries = parse_ima_binary_log(binary_delta)
        start = int(evidence.get("ima_start_index", -1))
        total = int(evidence.get("ima_entry_count", -1))
        anchor = evidence.get("anchor", {})
        snapshot = evidence.get("snapshot", {})
        stream = evidence.get("stream", {})
        vtpm = verify_pcr10_quote(evidence, base64.b64decode(nonce_b64))

        continuation = start == prior.entry_count and total == start + len(entries)
        binary_ascii_count = count_ascii_ima_entries(ascii_delta) == len(entries)
        binary_ascii_hashes = binary_ascii_template_hash_match(entries, ascii_delta)
        version_ok = evidence.get("version") == RUNTIME_EVIDENCE_VERSION
        stream_match = (
            bool(prior.stream_epoch)
            and stream.get("epoch") == prior.stream_epoch
            and bool(stream.get("checkpoint_match", False))
        )

        boot = {
            "mrtd": quote_info.mrtd.lower(),
            "rtmr0": quote_info.rtmr0.lower(),
            "rtmr1": quote_info.rtmr1.lower(),
            "rtmr2": quote_info.rtmr2.lower(),
        }
        checkpoint_identity = boot == {
            "mrtd": prior.mrtd,
            "rtmr0": prior.rtmr0,
            "rtmr1": prior.rtmr1,
            "rtmr2": prior.rtmr2,
        }
        policy_base, base_source = _resolve_rtmr3_base(
            expected_rtmr3_base, anchor, golden
        )
        checkpoint_base_policy = policy_base.hex() == prior.rtmr3_base

        ak_field = str(evidence.get("ak_pub_sha384", "")).lower()
        anchor_ak = str(anchor.get("ak_pub_sha384", "")).lower()
        ak_bind_consistent = (
            vtpm.ak_sha384 == prior.ak_pub_sha384 == ak_field == anchor_ak
        )
        ak_rtmr_step = (
            str(anchor.get("rtmr3_base_before_start", "")).lower()
            == prior.rtmr3_base
            and str(anchor.get("rtmr3_after_ak_bind", "")).lower()
            == prior.rtmr3_after_ak
        )

        expected_rtmr3 = replay_rtmr3(
            entries, base=bytes.fromhex(prior.rtmr3)
        ).hex()
        quoted_rtmr3 = quote_info.rtmr3.lower()
        rtmr3_replay = continuation and expected_rtmr3 == quoted_rtmr3
        rtmr3_metadata = str(anchor.get("rtmr3_current", "")).lower() == quoted_rtmr3
        anchor_count_match = anchor.get("anchored_count") == total

        full_sha256 = replay_pcr10_sha256_binary(
            entries, base=bytes.fromhex(prior.pcr10_sha256)
        )
        full_sha1 = replay_pcr10_sha1_ascii(
            ascii_delta, base=bytes.fromhex(prior.pcr10_sha1)
        )
        prefix_count, prefix_value = _find_delta_pcr_prefix(
            entries,
            vtpm.quoted_pcr10,
            bytes.fromhex(prior.pcr10_sha256),
            start,
        )
        reported_prefix = snapshot.get("vtpm_ima_prefix_entries")
        prefix_count_match = (
            reported_prefix is not None and reported_prefix == prefix_count
        )
        pcr10_signed = vtpm.ok and prefix_count is not None
        snapshot_consistent = bool(snapshot.get("consistent", False))

        ak_cert_policy = vtpm.cert_binds_ak or not require_ak_cert
        golden_present = golden is not None
        golden_match, per_register_golden = _golden_checks(quote_info, golden)
        golden_policy = golden_match and (golden_present or not require_golden)

        checks = {
            "evidence_version": version_ok,
            "checkpoint_continuity": continuation and stream_match,
            "checkpoint_identity": checkpoint_identity,
            "checkpoint_base_policy": checkpoint_base_policy,
            "binary_ascii_count": binary_ascii_count,
            "binary_ascii_hashes": binary_ascii_hashes,
            "snapshot_consistent": snapshot_consistent,
            "anchor_count": anchor_count_match,
            "vtpm_signature": vtpm.signature_ok,
            "vtpm_nonce": vtpm.nonce_ok,
            "vtpm_quote": vtpm.ok,
            "ak_bind_consistent": ak_bind_consistent,
            "ak_rtmr_step": ak_rtmr_step,
            "rtmr3_replay": rtmr3_replay,
            "rtmr3_metadata": rtmr3_metadata,
            "pcr10_signed_prefix": pcr10_signed,
            "pcr10_prefix_count": prefix_count_match,
            "ak_cert_policy": ak_cert_policy,
            "golden_boot_policy": golden_policy,
        }
        ok = all(checks.values())
        warnings = []
        if not vtpm.cert_binds_ak and not require_ak_cert:
            warnings.append("Google AK certificate binding was not required")
        if not golden_present and not require_golden:
            warnings.append("MRTD/RTMR0-2 golden boot policy was not required")
        if snapshot.get("post_quote_drift", 0):
            warnings.append(
                f"{snapshot['post_quote_drift']} IMA entries arrived after evidence capture"
            )

        continuity = _continuity_digest(
            prior.continuity_sha256,
            start,
            total,
            binary_delta,
            ascii_delta,
        )
        details = {
            "verification_mode": "incremental-delta",
            "ima_entries": total,
            "wire_ima_entries": len(entries),
            "ima_ascii_entries": total,
            "anchored_count": anchor.get("anchored_count"),
            "pcr10_prefix_entries": prefix_count,
            "agent_pcr10_prefix_entries": reported_prefix,
            "vtpm_quoted_pcr10_sha256": vtpm.quoted_pcr10,
            "replayed_pcr10_sha256": prefix_value,
            "full_replayed_pcr10_sha256": full_sha256.pcr_hex,
            "full_replayed_pcr10_sha1": full_sha1.pcr_hex,
            "ak_pub_sha384": vtpm.ak_sha384,
            "ak_cert_binds_ak": vtpm.cert_binds_ak,
            "vtpm_detail": vtpm.detail,
            "rtmr3_base": prior.rtmr3_base,
            "rtmr3_base_source": (
                f"sealed WEN checkpoint; current policy: {base_source}"
            ),
            "rtmr3_after_ak": prior.rtmr3_after_ak,
            "expected_rtmr3": expected_rtmr3,
            "quoted_rtmr3": quoted_rtmr3,
            "snapshot": snapshot,
            "stream": stream,
            "agent_stream": stream.get("sync", {}),
            "agent_timing": evidence.get("timing", {}),
            "golden_checks": per_register_golden,
            "boot_measurements": boot,
            "checkpoint_generation": prior.generation,
            "continuity_sha256": continuity,
        }
        failed = [name for name, passed in checks.items() if not passed]
        verdict = RuntimeEvidenceVerdict(
            ok=ok,
            checks=checks,
            details=details,
            warnings=warnings,
            error=("failed runtime checks: " + ", ".join(failed)) if failed else "",
        )
        if not ok:
            return verdict, None

        checkpoint = RuntimeCheckpoint(
            checkpoint_version=CHECKPOINT_VERSION,
            evidence_version=RUNTIME_EVIDENCE_VERSION,
            entry_count=total,
            stream_epoch=prior.stream_epoch,
            rtmr3=quoted_rtmr3,
            pcr10_sha256=full_sha256.pcr_hex,
            pcr10_sha1=full_sha1.pcr_hex,
            continuity_sha256=continuity,
            ak_pub_sha384=prior.ak_pub_sha384,
            rtmr3_base=prior.rtmr3_base,
            rtmr3_after_ak=prior.rtmr3_after_ak,
            mrtd=prior.mrtd,
            rtmr0=prior.rtmr0,
            rtmr1=prior.rtmr1,
            rtmr2=prior.rtmr2,
            generation=prior.generation + 1,
        )
        return verdict, checkpoint
    except Exception as exc:
        return (
            RuntimeEvidenceVerdict(
                ok=False,
                checks={"runtime_delta_parse": False},
                error=f"runtime delta verification error: {exc}",
            ),
            None,
        )


def verify_runtime_incremental(
    evidence: dict,
    quote_bytes: bytes,
    nonce_b64: str,
    prior: Optional[RuntimeCheckpoint] = None,
    *,
    expected_rtmr3_base: str = "auto",
    golden: Optional[dict] = None,
    require_golden: bool = False,
    require_ak_cert: bool = False,
) -> tuple[RuntimeEvidenceVerdict, Optional[RuntimeCheckpoint]]:
    """Verify full evidence once, then verify only deltas from a checkpoint."""
    start = int(evidence.get("ima_start_index", 0))
    if prior is not None and start > 0:
        return _verify_runtime_delta(
            evidence,
            quote_bytes,
            nonce_b64,
            prior,
            expected_rtmr3_base=expected_rtmr3_base,
            golden=golden,
            require_golden=require_golden,
            require_ak_cert=require_ak_cert,
        )
    if start != 0:
        return (
            RuntimeEvidenceVerdict(
                ok=False,
                checks={"checkpoint_continuity": False},
                error="received a runtime delta without a WEN checkpoint",
            ),
            None,
        )

    verdict = verify_runtime_evidence(
        evidence,
        quote_bytes,
        nonce_b64,
        expected_rtmr3_base=expected_rtmr3_base,
        golden=golden,
        require_golden=require_golden,
        require_ak_cert=require_ak_cert,
    )
    return verdict, _checkpoint_from_full(evidence, verdict) if verdict.ok else None
