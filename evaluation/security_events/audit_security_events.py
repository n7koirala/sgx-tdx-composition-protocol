#!/usr/bin/env python3
"""Orchestrate and audit protocol-1.2 IMA security-event experiments."""

from __future__ import annotations

import argparse
import asyncio
import base64
import copy
import csv
import gzip
import hashlib
import json
import os
import shlex
import ssl
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)


THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parents[1]
SCALABILITY_DIR = REPO_ROOT / "evaluation" / "scalability"
SGX_TDX_ROOT = REPO_ROOT / "research" / "sgx-tdx-attestation"
for path in (SCALABILITY_DIR, SGX_TDX_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from scale_common import generate_nonce, recv_json, send_json, stable_json_bytes, write_csv
from run_vordr_sweep import (
    response_proof_fields,
    validate_server_proof_identity,
    verify_audit_evidence_response,
    verify_response_proof,
)
from common.ima_rtmr3 import (
    binary_ascii_template_hash_match,
    count_ascii_ima_entries,
    find_pcr10_sha256_prefix,
    parse_ima_binary_log,
)
from common.vtpm_quote import verify_pcr10_quote


STREAM_LIMIT_BYTES = 256 * 1024 * 1024
AUTH_SCHEMA = "vordr-authorization-v1"
RESULT_SCHEMA = "vordr-security-event-result-v1"
DEFAULT_SCENARIOS = (
    "no-update",
    "authorized-package",
    "shared-library-replacement",
    "kernel-module-insertion",
    "unauthorized-package",
    "binary-replacement",
)
EXPECTED_POLICY = {
    "no-update": "COMPLIANT",
    "authorized-package": "COMPLIANT",
    "shared-library-replacement": "VIOLATION",
    "kernel-module-insertion": "VIOLATION",
    "unauthorized-package": "VIOLATION",
    "binary-replacement": "VIOLATION",
}


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, capture_output=True)


def remote_command(args: argparse.Namespace, command: list[str]) -> str:
    invocation = [
        "gcloud",
        "compute",
        "ssh",
        args.instance,
        "--zone",
        args.zone,
        "--quiet",
        "--command",
        shlex.join(command),
    ]
    if args.project:
        invocation.extend(["--project", args.project])
    return run_command(invocation).stdout


def parse_last_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped:
        try:
            value = json.loads(stripped)
            if isinstance(value, dict):
                if value.get("status") == "error":
                    raise RuntimeError(value.get("error", "remote command failed"))
                return value
        except json.JSONDecodeError:
            pass
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            if value.get("status") == "error":
                raise RuntimeError(value.get("error", "remote command failed"))
            return value
    raise ValueError(f"remote command did not return JSON: {text[-1000:]}")


def load_remote_state(args: argparse.Namespace) -> dict[str, Any]:
    output = remote_command(args, ["sudo", "-n", "cat", args.remote_state])
    state = parse_last_json(output)
    if state.get("schema") != "vordr-security-events-cvm-v1":
        raise ValueError("remote CVM state has an unsupported schema")
    return state


def trigger_remote(
    args: argparse.Namespace,
    scenario: str,
    trial: int,
) -> dict[str, Any]:
    script = (
        Path(args.remote_repo)
        / "evaluation"
        / "security_events"
        / "cvm_security_events.py"
    )
    output = remote_command(
        args,
        [
            "sudo",
            "-n",
            "python3",
            str(script),
            "run",
            "--state",
            args.remote_state,
            "--scenario",
            scenario,
            "--trial",
            str(trial),
        ],
    )
    record = parse_last_json(output)
    if record.get("schema") != "vordr-security-event-trigger-v1":
        raise ValueError("remote trigger returned an unsupported record")
    return record


def client_ssl_context(ca_cert: Path) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(str(ca_cert))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


async def query_server_async(
    host: str,
    port: int,
    context: ssl.SSLContext,
    action: str,
    nonce: str = "",
) -> dict[str, Any]:
    reader, writer = await asyncio.open_connection(
        host,
        port,
        ssl=context,
        server_hostname=host,
        limit=STREAM_LIMIT_BYTES,
    )
    try:
        request: dict[str, Any] = {"action": action}
        if nonce:
            request["nonce"] = nonce
        await send_json(writer, request)
        return await recv_json(reader)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError, OSError):
            pass


def query_server(
    host: str,
    port: int,
    context: ssl.SSLContext,
    action: str,
    nonce: str = "",
) -> dict[str, Any]:
    return asyncio.run(query_server_async(host, port, context, action, nonce))


def initialize_authorization_keys(private_path: Path, public_path: Path) -> dict[str, str]:
    if private_path.exists() or public_path.exists():
        raise FileExistsError("authorization key path already exists")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption(),
        )
    )
    os.chmod(private_path, 0o600)
    public_bytes = private_key.public_key().public_bytes(
        Encoding.PEM,
        PublicFormat.SubjectPublicKeyInfo,
    )
    public_path.write_bytes(public_bytes)
    return {
        "private_key": str(private_path),
        "public_key": str(public_path),
        "public_key_sha256": sha256_hex(public_bytes),
    }


def auth_record_hash(record: dict[str, Any]) -> str:
    return sha256_hex(stable_json_bytes(record))


def read_authorizations(log_path: Path) -> list[dict[str, Any]]:
    if not log_path.exists():
        return []
    records = []
    for line_number, line in enumerate(log_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"authorization record {line_number} is not an object")
        records.append(value)
    return records


def validate_authorizations(
    records: list[dict[str, Any]],
    public_key: Ed25519PublicKey,
) -> list[dict[str, Any]]:
    previous_hash = "0" * 64
    validated = []
    for expected_sequence, record in enumerate(records, 1):
        if record.get("schema") != AUTH_SCHEMA:
            raise ValueError(f"authorization record {expected_sequence} has wrong schema")
        if int(record.get("sequence", 0)) != expected_sequence:
            raise ValueError(f"authorization sequence gap at {expected_sequence}")
        if record.get("previous_record_sha256") != previous_hash:
            raise ValueError(f"authorization chain mismatch at {expected_sequence}")
        unsigned = dict(record)
        signature = base64.b64decode(unsigned.pop("signature_b64"), validate=True)
        public_key.verify(signature, stable_json_bytes(unsigned))
        previous_hash = auth_record_hash(record)
        validated.append(record)
    return validated


def append_authorization(
    log_path: Path,
    private_key_path: Path,
    *,
    campaign_id: str,
    scenario: str,
    trial: int,
    artifact: dict[str, Any],
) -> dict[str, Any]:
    private_key = load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("authorization private key is not Ed25519")
    records = read_authorizations(log_path)
    previous_hash = auth_record_hash(records[-1]) if records else "0" * 64
    unsigned = {
        "schema": AUTH_SCHEMA,
        "sequence": len(records) + 1,
        "previous_record_sha256": previous_hash,
        "transaction_id": f"{campaign_id}:{scenario}:{trial}",
        "campaign_id": campaign_id,
        "scenario": scenario,
        "trial": trial,
        "action": "install-package",
        "target_path": artifact["target_path"],
        "artifact_sha256": artifact["candidate_sha256"],
        "package_name": artifact.get("package_name", ""),
        "issued_at": time.time(),
    }
    signature = private_key.sign(stable_json_bytes(unsigned))
    record = {
        **unsigned,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(compact_json(record) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return record


def artifact_for(
    state: dict[str, Any],
    scenario: str,
    trial: int,
) -> dict[str, Any]:
    for artifact in state.get("artifacts", {}).get(scenario, []):
        if int(artifact.get("trial", 0)) == trial:
            return artifact
    raise ValueError(f"missing state artifact for {scenario} trial {trial}")


def parse_ascii_entries(ascii_text: str) -> list[dict[str, Any]]:
    entries = []
    for index, line in enumerate(ascii_text.splitlines()):
        fields = line.split(" ", 4)
        if len(fields) < 5:
            continue
        file_digest = fields[3]
        algorithm, separator, digest = file_digest.partition(":")
        entries.append(
            {
                "index": index,
                "pcr": fields[0],
                "template_hash": fields[1],
                "template": fields[2],
                "digest_algorithm": algorithm if separator else "",
                "digest": digest if separator else file_digest,
                "path": fields[4],
                "line": line,
            }
        )
    return entries


def independent_mode2_checks(evidence: dict[str, Any]) -> dict[str, Any]:
    binary_blob = base64.b64decode(evidence["ima_binary_log_b64"], validate=True)
    ascii_text = base64.b64decode(
        evidence["ima_ascii_log_b64"], validate=True
    ).decode("utf-8", errors="replace")
    binary_entries = parse_ima_binary_log(binary_blob)
    nonce_b64 = evidence.get("wen_cvm_nonce_b64", "")
    if not nonce_b64:
        raise ValueError("audit evidence is missing wen_cvm_nonce_b64")
    vtpm = verify_pcr10_quote(evidence, base64.b64decode(nonce_b64, validate=True))
    prefix_count, prefix_replay = find_pcr10_sha256_prefix(
        binary_entries, vtpm.quoted_pcr10
    )
    reported_prefix = evidence.get("snapshot", {}).get("vtpm_ima_prefix_entries")
    checks = {
        "binary_ascii_count": (
            len(binary_entries) == count_ascii_ima_entries(ascii_text)
        ),
        "binary_ascii_hashes": binary_ascii_template_hash_match(
            binary_entries, ascii_text
        ),
        "vtpm_signature": vtpm.signature_ok,
        "vtpm_nonce": vtpm.nonce_ok,
        "vtpm_quote": vtpm.ok,
        "pcr10_signed_prefix": prefix_count is not None,
        "pcr10_prefix_count": (
            prefix_count is not None and int(reported_prefix) == prefix_count
        ),
    }
    return {
        "checks": checks,
        "ok": all(checks.values()),
        "binary_entries": len(binary_entries),
        "ascii_entries": count_ascii_ima_entries(ascii_text),
        "pcr10_prefix_entries": prefix_count,
        "quoted_pcr10": vtpm.quoted_pcr10,
        "replayed_pcr10": prefix_replay.pcr_hex if prefix_replay else "",
        "ascii_text": ascii_text,
    }


def find_current_events(
    ascii_entries: list[dict[str, Any]],
    trigger: dict[str, Any],
) -> list[dict[str, Any]]:
    start = int(trigger.get("ima_count_before", 0))
    target = trigger.get("target_path", "")
    exact = [
        entry
        for entry in ascii_entries
        if entry["index"] >= start and target and entry["path"] == target
    ]
    if exact:
        return exact
    aliases = set(trigger.get("event_aliases", []))
    return [
        entry
        for entry in ascii_entries
        if entry["index"] >= start
        and any(
            entry["path"] == alias
            or entry["path"].endswith("/" + alias)
            for alias in aliases
            if alias
        )
    ]


def authorization_matches(
    records: list[dict[str, Any]],
    trigger: dict[str, Any],
) -> bool:
    for record in records:
        if (
            record.get("campaign_id") == trigger.get("campaign_id")
            and record.get("scenario") == trigger.get("scenario")
            and int(record.get("trial", 0)) == int(trigger.get("trial", -1))
            and record.get("target_path") == trigger.get("target_path")
            and record.get("artifact_sha256") == trigger.get("candidate_sha256")
        ):
            return True
    return False


def semantic_verdict(
    scenario: str,
    state: dict[str, Any],
    trigger: dict[str, Any],
    ascii_entries: list[dict[str, Any]],
    authorizations: list[dict[str, Any]],
) -> dict[str, Any]:
    if scenario == "no-update":
        violations = []
        protected = []
        for protected_scenario in (
            "shared-library-replacement",
            "binary-replacement",
        ):
            for artifact in state.get("artifacts", {}).get(protected_scenario, []):
                protected.append(artifact)
        suffix = [
            entry
            for entry in ascii_entries
            if entry["index"] >= int(trigger.get("ima_count_before", 0))
        ]
        for artifact in protected:
            for entry in suffix:
                if (
                    entry["path"] == artifact["target_path"]
                    and entry["digest_algorithm"] == "sha256"
                    and entry["digest"] != artifact["baseline_sha256"]
                ):
                    violations.append(entry)
        return {
            "verdict": "VIOLATION" if violations else "COMPLIANT",
            "reason": (
                "protected canary changed during no-update control"
                if violations
                else "no unauthorized protected-path transition"
            ),
            "event_observed": False,
            "matching_events": violations,
            "authorization_match": False,
        }

    matches = find_current_events(ascii_entries, trigger)
    candidate = trigger.get("candidate_sha256", "")
    digest_match = any(
        event["digest_algorithm"] == "sha256" and event["digest"] == candidate
        for event in matches
    )
    auth_match = authorization_matches(authorizations, trigger)
    if not matches:
        return {
            "verdict": "INDETERMINATE",
            "reason": "target event not yet present in the exported IMA snapshot",
            "event_observed": False,
            "matching_events": [],
            "authorization_match": auth_match,
        }
    if not digest_match:
        return {
            "verdict": "INDETERMINATE",
            "reason": "target path appeared with an unexpected measured digest",
            "event_observed": True,
            "matching_events": matches,
            "authorization_match": auth_match,
        }
    if scenario == "authorized-package":
        verdict = "COMPLIANT" if auth_match else "VIOLATION"
        reason = (
            "measured package digest matches a signed authorization"
            if auth_match
            else "measured package has no matching signed authorization"
        )
    elif scenario in (
        "shared-library-replacement",
        "binary-replacement",
    ):
        verdict = "VIOLATION"
        reason = "protected path changed from its reference-manifest digest"
    elif scenario == "kernel-module-insertion":
        verdict = "VIOLATION"
        reason = "unapproved kernel module was measured without authorization"
    else:
        verdict = "VIOLATION"
        reason = "package executable was measured without authorization"
    return {
        "verdict": verdict,
        "reason": reason,
        "event_observed": True,
        "matching_events": matches,
        "authorization_match": auth_match,
    }


def decode_and_validate_authorizations(
    response: dict[str, Any],
    public_key_path: Path,
) -> list[dict[str, Any]]:
    public_key = load_pem_public_key(public_key_path.read_bytes())
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("authorization public key is not Ed25519")
    command_log = base64.b64decode(response.get("command_log", ""), validate=True)
    text = command_log.decode("utf-8")
    records = [
        json.loads(line)
        for line in text.splitlines()
        if line.strip()
    ]
    return validate_authorizations(records, public_key)


def verify_response(
    response: dict[str, Any],
    nonce: str,
    public_key: bytes,
    auth_public_key_path: Path,
) -> dict[str, Any]:
    if response.get("status") != "success":
        raise ValueError(f"WEN returned an error: {response.get('error')}")
    if response.get("evidence_mode") != "ima-audit":
        raise ValueError("WEN is not serving Mode 2 ima-audit evidence")
    if response.get("nonce_echo") != nonce:
        raise ValueError("end-user nonce echo mismatch")
    if response.get("nonce_hash") != sha256_hex(nonce.encode("utf-8")):
        raise ValueError("end-user nonce hash mismatch")
    verify_response_proof(
        response,
        proof_secret="",
        public_key=public_key,
    )
    sizes = verify_audit_evidence_response(response, "ima-audit")
    independent = independent_mode2_checks(response["runtime_evidence"])
    authorizations = decode_and_validate_authorizations(
        response, auth_public_key_path
    )
    wen_checks = {
        "tdx_verified": bool(response.get("tdx_verified")),
        "tdx_verdict": response.get("tdx_verdict") == "TRUSTED",
        "runtime_verdict": response.get("tdx_runtime_verdict") == "CLEAN",
        "ima_verified": bool(response.get("tdx_ima_verified")),
    }
    return {
        "ok": all(wen_checks.values()) and independent["ok"],
        "wen_checks": wen_checks,
        "independent_checks": independent["checks"],
        "independent": independent,
        "authorizations": authorizations,
        "sizes": sizes,
    }


def save_response(path: Path, response: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8", compresslevel=6) as handle:
        json.dump(response, handle, separators=(",", ":"))


def wait_for_evidence(
    args: argparse.Namespace,
    ssl_context: ssl.SSLContext,
    starting_refresh: int,
    trigger: dict[str, Any],
    state: dict[str, Any],
    wen_public_key: bytes,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    deadline = time.monotonic() + args.refresh_timeout_s
    seen_refresh = starting_refresh
    last_detail = "no new refresh"
    while time.monotonic() < deadline:
        stats = query_server(args.wen_host, args.wen_port, ssl_context, "stats")
        refresh_count = int(stats.get("refresh_count", 0))
        if (
            refresh_count > seen_refresh
            and not stats.get("refresh_in_progress", False)
            and stats.get("tdx_verdict") == "TRUSTED"
        ):
            seen_refresh = refresh_count
            nonce = generate_nonce()
            response = query_server(
                args.wen_host,
                args.wen_port,
                ssl_context,
                "verify",
                nonce,
            )
            verified = verify_response(
                response,
                nonce,
                wen_public_key,
                Path(args.auth_public_key),
            )
            ascii_entries = parse_ascii_entries(
                verified["independent"]["ascii_text"]
            )
            semantic = semantic_verdict(
                trigger["scenario"],
                state,
                trigger,
                ascii_entries,
                verified["authorizations"],
            )
            if trigger["scenario"] == "no-update" or semantic["event_observed"]:
                return response, verified, semantic
            last_detail = semantic["reason"]
        elif refresh_count > seen_refresh:
            last_detail = compact_json(stats)
            seen_refresh = refresh_count
        time.sleep(args.poll_interval_s)
    raise TimeoutError(
        f"target evidence did not appear within {args.refresh_timeout_s}s: {last_detail}"
    )


def run_campaign(args: argparse.Namespace) -> int:
    state = load_remote_state(args)
    if int(state.get("trials", 0)) < args.trials:
        raise ValueError("remote state contains fewer trials than requested")
    auth_private = Path(args.auth_private_key)
    auth_public = Path(args.auth_public_key)
    auth_log = Path(args.command_log)
    for path in (auth_private, auth_public, auth_log):
        if not path.exists():
            raise FileNotFoundError(f"required campaign input is missing: {path}")

    ssl_context = client_ssl_context(Path(args.ca_cert))
    stats = query_server(args.wen_host, args.wen_port, ssl_context, "stats")
    if stats.get("evidence_mode") != "ima-audit":
        raise RuntimeError("restart the WEN with --evidence-mode ima-audit")
    wen_public_key, key_id = validate_server_proof_identity(
        stats,
        expected_auth="ed25519",
        expected_key_sha256=args.expected_wen_key_sha256,
    )
    if wen_public_key is None:
        raise RuntimeError("WEN did not publish an Ed25519 verification key")

    scenarios = tuple(
        item.strip() for item in args.scenarios.split(",") if item.strip()
    )
    unknown = sorted(set(scenarios) - set(DEFAULT_SCENARIOS))
    if unknown:
        raise ValueError(f"unsupported scenarios: {', '.join(unknown)}")

    output = Path(args.out_dir)
    output.mkdir(parents=True, exist_ok=True)
    (output / "cvm_state.json").write_text(
        json.dumps(state, indent=2) + "\n", encoding="utf-8"
    )
    metadata = {
        "schema": "vordr-security-events-campaign-v1",
        "campaign_id": state["campaign_id"],
        "created_at": time.time(),
        "trials": args.trials,
        "scenarios": scenarios,
        "attestation_period_s": args.attestation_period_s,
        "wen_host": args.wen_host,
        "wen_port": args.wen_port,
        "wen_key_id": key_id,
        "cvm_instance": args.instance,
        "cvm_zone": args.zone,
        "cvm_project": args.project,
        "remote_state": args.remote_state,
    }
    (output / "campaign_metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )

    rows: list[dict[str, Any]] = []
    for scenario in scenarios:
        for trial in range(1, args.trials + 1):
            print(f"[security-event] scenario={scenario} trial={trial}/{args.trials}")
            before = query_server(
                args.wen_host, args.wen_port, ssl_context, "stats"
            )
            if scenario == "authorized-package":
                artifact = artifact_for(state, scenario, trial)
                append_authorization(
                    auth_log,
                    auth_private,
                    campaign_id=state["campaign_id"],
                    scenario=scenario,
                    trial=trial,
                    artifact=artifact,
                )

            trigger = trigger_remote(args, scenario, trial)
            try:
                response, verified, semantic = wait_for_evidence(
                    args,
                    ssl_context,
                    int(before.get("refresh_count", 0)),
                    trigger,
                    state,
                    wen_public_key,
                )
                response_path = (
                    output
                    / "responses"
                    / f"{scenario}-trial-{trial}.json.gz"
                )
                save_response(response_path, response)
                expected_policy = EXPECTED_POLICY[scenario]
                trial_pass = (
                    verified["ok"]
                    and semantic["verdict"] == expected_policy
                )
                matching = semantic.get("matching_events", [])
                first_event = matching[0] if matching else {}
                row = {
                    "scenario": scenario,
                    "trial": trial,
                    "expected_policy_verdict": expected_policy,
                    "evidence_integrity": (
                        "VALID" if verified["ok"] else "INVALID"
                    ),
                    "workload_policy": semantic["verdict"],
                    "trial_pass": trial_pass,
                    "reason": semantic["reason"],
                    "event_observed": semantic["event_observed"],
                    "event_index": first_event.get("index", ""),
                    "event_path": first_event.get("path", ""),
                    "observed_sha256": first_event.get("digest", ""),
                    "expected_baseline_sha256": trigger.get(
                        "baseline_sha256", ""
                    ),
                    "candidate_sha256": trigger.get("candidate_sha256", ""),
                    "authorization_match": semantic["authorization_match"],
                    "ima_count_before": trigger["ima_count_before"],
                    "ima_count_after_trigger": trigger["ima_count_after"],
                    "ima_count_evidence": int(
                        response.get("ima_entry_count", 0)
                    ),
                    "wen_refresh_count": int(response.get("refresh_count", 0)),
                    "attack_started_at": trigger["attack_started_at"],
                    "trigger_completed_at": trigger["trigger_completed_at"],
                    "wen_verified_at": response.get(
                        "tdx_verification_time", 0.0
                    ),
                    "detected_at": time.time(),
                    "wen_detection_latency_ms": max(
                        0.0,
                        (
                            float(response.get("tdx_verification_time", 0.0))
                            - float(trigger["trigger_completed_at"])
                        )
                        * 1000.0,
                    ),
                    "end_user_observation_latency_ms": max(
                        0.0,
                        (time.time() - float(trigger["trigger_completed_at"]))
                        * 1000.0,
                    ),
                    "response_payload_bytes": int(
                        verified["sizes"]["response_payload_bytes"]
                    ),
                    "pcr10_prefix_entries": verified["independent"][
                        "pcr10_prefix_entries"
                    ],
                    "response_file": str(response_path.relative_to(output)),
                    "error": "",
                }
            except Exception as exc:
                row = {
                    "scenario": scenario,
                    "trial": trial,
                    "expected_policy_verdict": EXPECTED_POLICY[scenario],
                    "evidence_integrity": "ERROR",
                    "workload_policy": "INDETERMINATE",
                    "trial_pass": False,
                    "reason": "",
                    "event_observed": False,
                    "attack_started_at": trigger["attack_started_at"],
                    "trigger_completed_at": trigger["trigger_completed_at"],
                    "error": str(exc),
                }
                print(f"  FAIL: {exc}", file=sys.stderr)
            rows.append(row)
            write_csv(output / "security_event_results.csv", rows)
            (output / "security_event_results.json").write_text(
                json.dumps(rows, indent=2) + "\n", encoding="utf-8"
            )
            print(
                f"  evidence={row['evidence_integrity']} "
                f"policy={row['workload_policy']} pass={row['trial_pass']}"
            )

    passed = sum(bool(row.get("trial_pass")) for row in rows)
    print(f"Completed {len(rows)} trials: passed={passed}, failed={len(rows) - passed}")
    return 0 if passed == len(rows) else 1


def fault_test(args: argparse.Namespace) -> int:
    with gzip.open(args.response, "rt", encoding="utf-8") as handle:
        response = json.load(handle)
    public_key = base64.b64decode(
        response.get("proof_public_key_b64", ""), validate=True
    )
    original_nonce = response.get("nonce_echo", "")
    results = []

    fresh_nonce = generate_nonce()
    results.append(
        {
            "test": "replay-old-response-under-fresh-nonce",
            "rejected": original_nonce != fresh_nonce,
            "reason": "nonce echo does not match the fresh challenge",
        }
    )

    modified_nonce = copy.deepcopy(response)
    modified_nonce["nonce_echo"] = fresh_nonce
    try:
        verify_response_proof(
            modified_nonce, proof_secret="", public_key=public_key
        )
        nonce_signature_rejected = False
    except Exception:
        nonce_signature_rejected = True
    results.append(
        {
            "test": "rewrite-replayed-response-nonce",
            "rejected": nonce_signature_rejected,
            "reason": "WEN Ed25519 proof covers the end-user nonce",
        }
    )

    malformed = copy.deepcopy(response)
    evidence = malformed["runtime_evidence"]
    ascii_lines = base64.b64decode(
        evidence["ima_ascii_log_b64"], validate=True
    ).splitlines(keepends=True)
    binary_entries = parse_ima_binary_log(
        base64.b64decode(evidence["ima_binary_log_b64"], validate=True)
    )
    reported_prefix = int(
        evidence.get("snapshot", {}).get("vtpm_ima_prefix_entries", 0)
    )
    remove_index = max(1, min(reported_prefix // 2, len(binary_entries) - 2))
    evidence["ima_binary_log_b64"] = base64.b64encode(
        b"".join(
            entry.raw_event
            for index, entry in enumerate(binary_entries)
            if index != remove_index
        )
    ).decode("ascii")
    evidence["ima_ascii_log_b64"] = base64.b64encode(
        b"".join(
            line for index, line in enumerate(ascii_lines) if index != remove_index
        )
    ).decode("ascii")
    try:
        verify_audit_evidence_response(malformed, "ima-audit")
        bundle_rejected = False
    except Exception:
        bundle_rejected = True
    independent = independent_mode2_checks(evidence)
    results.append(
        {
            "test": "delete-ima-entry",
            "rejected": bundle_rejected and not independent["ok"],
            "reason": (
                "authenticated bundle hash and independent PCR/IMA checks reject "
                "the omitted event"
            ),
            "independent_checks": independent["checks"],
            "removed_index": remove_index,
        }
    )

    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    passed = all(result["rejected"] for result in results)
    print(json.dumps({"passed": passed, "results": results}, indent=2))
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    key_parser = subparsers.add_parser("init-auth")
    key_parser.add_argument("--private-key", required=True)
    key_parser.add_argument("--public-key", required=True)
    key_parser.add_argument("--command-log", required=True)

    campaign = subparsers.add_parser("run-campaign")
    campaign.add_argument("--project", default="")
    campaign.add_argument("--zone", required=True)
    campaign.add_argument("--instance", required=True)
    campaign.add_argument("--remote-repo", required=True)
    campaign.add_argument("--remote-state", required=True)
    campaign.add_argument("--wen-host", required=True)
    campaign.add_argument("--wen-port", type=int, default=10443)
    campaign.add_argument("--ca-cert", required=True)
    campaign.add_argument("--expected-wen-key-sha256", required=True)
    campaign.add_argument("--auth-private-key", required=True)
    campaign.add_argument("--auth-public-key", required=True)
    campaign.add_argument("--command-log", required=True)
    campaign.add_argument("--trials", type=int, default=3)
    campaign.add_argument(
        "--scenarios", default=",".join(DEFAULT_SCENARIOS)
    )
    campaign.add_argument("--attestation-period-s", type=float, default=30.0)
    campaign.add_argument("--refresh-timeout-s", type=float, default=75.0)
    campaign.add_argument("--poll-interval-s", type=float, default=0.5)
    campaign.add_argument("--out-dir", required=True)

    fault = subparsers.add_parser("fault-test")
    fault.add_argument("--response", required=True)
    fault.add_argument("--out", required=True)

    args = parser.parse_args()
    try:
        if args.command == "init-auth":
            result = initialize_authorization_keys(
                Path(args.private_key), Path(args.public_key)
            )
            command_log = Path(args.command_log)
            command_log.parent.mkdir(parents=True, exist_ok=True)
            command_log.write_text("", encoding="utf-8")
            print(json.dumps({**result, "command_log": str(command_log)}, indent=2))
            return 0
        if args.command == "fault-test":
            return fault_test(args)
        if args.trials <= 0:
            parser.error("--trials must be positive")
        if args.refresh_timeout_s <= args.attestation_period_s:
            parser.error("--refresh-timeout-s must exceed --attestation-period-s")
        return run_campaign(args)
    except (
        OSError,
        ValueError,
        RuntimeError,
        subprocess.CalledProcessError,
    ) as exc:
        detail = str(exc)
        if isinstance(exc, subprocess.CalledProcessError):
            detail = (
                f"{exc}; stdout={exc.stdout[-2000:]}; stderr={exc.stderr[-2000:]}"
            )
        print(f"error: {detail}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
