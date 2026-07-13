"""WEN-side verification for composed IMA, RTMR[3], and vTPM evidence."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .ima_rtmr3 import (
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


@dataclass
class RuntimeEvidenceVerdict:
    ok: bool
    checks: Dict[str, bool] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    error: str = ""


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


def expand_runtime_evidence(
    evidence: dict, prior_binary: bytes = b"", prior_ascii: str = ""
) -> tuple[dict, bytes, str]:
    """Expand a wire delta into the complete history held by the WEN."""
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
    """Verify the complete composed runtime predicate for one round."""
    try:
        quote_info = parse_dcap_quote(quote_bytes)
        ima_blob = base64.b64decode(evidence["ima_binary_log_b64"])
        entries = parse_ima_binary_log(ima_blob)
        ima_ascii = base64.b64decode(evidence["ima_ascii_log_b64"]).decode(
            "utf-8", errors="replace"
        )
        anchor = evidence.get("anchor", {})
        snapshot = evidence.get("snapshot", {})
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
            "ima_entries": len(entries),
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
            "golden_checks": per_register_golden,
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
