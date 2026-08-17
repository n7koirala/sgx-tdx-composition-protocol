#!/usr/bin/env python3
"""Benchmark a single WEN serving many end-user attestation requests."""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import gzip
import hashlib
import json
import os
import platform
import random
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from scale_common import (
    compute_proof_mac,
    ensure_dir,
    generate_nonce,
    recv_json,
    send_json,
    summarize_samples,
    verify_ed25519_proof,
    write_csv,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SCALABILITY_DIR = REPO_ROOT / "evaluation" / "scalability"
SERVER_SCRIPT = REPO_ROOT / "evaluation" / "scalability" / "vordr_server.py"
GRAMINE_APP = "./vordr_wen"
GRAMINE_ENTRYPOINT = "/app/evaluation/scalability/vordr_server.py"
STREAM_LIMIT_BYTES = 16 * 1024 * 1024
GRAMINE_RUNTIMES = {"gramine-direct", "gramine-sgx"}


def raw_point_filename(
    *,
    workload_model: str,
    connection_model: str,
    users: int,
    offered_rate: float,
    repeat: int,
) -> str:
    if workload_model == "open-loop":
        point = f"rate-{offered_rate:g}".replace(".", "p")
    else:
        point = f"users-{users}"
    connection = f"-{connection_model}" if workload_model == "one-shot" else ""
    return f"{workload_model}{connection}-{point}-repeat-{repeat}.json.gz"


def write_gzip_json(path: Path, payload: dict[str, Any]) -> None:
    """Write one result point atomically without retaining the full matrix."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    with gzip.open(temporary, "wt", encoding="utf-8", compresslevel=6) as handle:
        json.dump(payload, handle, separators=(",", ":"))
    temporary.replace(path)


def command_output(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return (result.stdout or result.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unavailable: {exc}"


def file_sha256(path: Path) -> str:
    try:
        return sha256_hex(path.read_bytes())
    except OSError:
        return ""


def parse_colon_metadata(raw: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized = key.strip().lower().replace(" ", "_")
        if normalized:
            parsed[normalized] = value.strip()
    return parsed


def collect_reproducibility_metadata(args: argparse.Namespace) -> dict[str, Any]:
    sigstruct_raw = ""
    if args.server_runtime == "gramine-sgx":
        sigstruct_raw = command_output(
            ["gramine-sgx-sigstruct-view", str(SCALABILITY_DIR / "vordr_wen.sig")]
        )
    safe_args = {
        key: value
        for key, value in vars(args).items()
        if key not in {"proof_secret"}
    }
    return {
        "schema": "vordr-scalability-metadata-v1",
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git": {
            "commit": command_output(["git", "rev-parse", "HEAD"]),
            "branch": command_output(["git", "branch", "--show-current"]),
            "status_porcelain": command_output(["git", "status", "--short"]),
        },
        "protocol": {
            "version": "1.2",
            "runtime_evidence": "ima-rtmr3-vtpm-v2",
        },
        "load_generator": {
            "hostname": socket.gethostname(),
            "location": args.load_generator_location,
            "platform": platform.platform(),
            "python": sys.version,
            "cpu_count": os.cpu_count(),
            "kernel": platform.release(),
            "hardware_description": args.load_generator_hardware,
            "lscpu": command_output(["lscpu"]),
        },
        "wen": {
            "location": args.wen_location,
            "host": args.host,
            "port": args.port,
            "runtime": args.server_runtime,
            "gramine_version": command_output(["gramine-sgx", "--version"]),
            "sigstruct_sha256": file_sha256(SCALABILITY_DIR / "vordr_wen.sig"),
            "sgx_identity": parse_colon_metadata(sigstruct_raw),
            "hardware_description": args.wen_hardware,
            "python_version": platform.python_version(),
            "cryptography_version": command_output([sys.executable, "-c", "import cryptography; print(cryptography.__version__)"]),
            "sgx_debug_manifest": (
                args.server_runtime == "gramine-sgx"
                and "sgx.debug = true" in (SCALABILITY_DIR / "vordr_wen.manifest.template").read_text(
                    encoding="utf-8"
                )
            ),
        },
        "cvm": {
            "location": args.cvm_location,
            "host": args.tdx_host,
            "image": args.cvm_image,
            "kernel": args.cvm_kernel,
            "ima_policy": args.ima_policy,
            "baseline_ima_count": args.baseline_ima_count,
            "hardware_description": args.cvm_hardware,
            "tpm2_tools_version": args.tpm2_tools_version,
            "gotpm_version": args.gotpm_version,
            "dcap_version": args.dcap_version,
        },
        "transport": {
            "mode": args.transport,
            "certificate_verification": (
                args.transport == "tls" and not args.no_verify_server_cert
            ),
            "load_generator_to_wen_rtt_ms": args.loadgen_wen_rtt_ms,
            "load_generator_to_wen_rtt_method": args.loadgen_wen_rtt_method,
            "wen_to_cvm_rtt_ms": args.wen_cvm_rtt_ms,
            "wen_to_cvm_rtt_method": args.wen_cvm_rtt_method,
            "client_ca_cert_sha256": (
                file_sha256(Path(args.client_ca_cert).expanduser())
                if args.client_ca_cert
                else ""
            ),
        },
        "arguments": safe_args,
        "completed_points": [],
    }


def response_proof_fields(response: dict[str, Any]) -> dict[str, Any]:
    return {
        "controller_id": response.get("controller_id", ""),
        "evidence_mode": response.get("evidence_mode", "light"),
        "nonce_echo": response.get("nonce_echo", ""),
        "nonce_hash": response.get("nonce_hash", ""),
        "wen_refresh_in_progress": response.get("wen_refresh_in_progress", False),
        "cvm_update_in_progress": response.get("cvm_update_in_progress", False),
        "tdx_verdict": response.get("tdx_verdict", ""),
        "tdx_mrtd": response.get("tdx_mrtd", ""),
        "tdx_quote_hash": response.get("tdx_quote_hash", ""),
        "runtime_verdict": response.get("tdx_runtime_verdict", ""),
        "tdx_verification_time": response.get("tdx_verification_time", 0.0),
        "refresh_count": response.get("refresh_count", 0),
        "raw_quote_sha256": response.get("raw_quote_sha256", ""),
        "runtime_evidence_sha256": response.get("runtime_evidence_sha256", ""),
        "ima_log_sha256": response.get("ima_log_sha256", ""),
        "pcr10_sha256": response.get("pcr10_sha256", ""),
        "command_log_sha256": response.get("command_log_sha256", ""),
        "ima_entry_count": response.get("ima_entry_count", 0),
        "command_log_entries": response.get("command_log_entries", 0),
        "issued_at": response.get("issued_at", 0.0),
    }


def parse_float_list(raw: str) -> list[float]:
    values = [float(item.strip()) for item in raw.split(",") if item.strip()]
    if not values:
        raise ValueError("expected at least one numeric value")
    return values


def validate_server_proof_identity(
    metadata: dict[str, Any],
    *,
    expected_auth: str,
    expected_key_sha256: str,
) -> tuple[bytes | None, str]:
    proof_alg = metadata.get("proof_alg", "")
    if proof_alg != expected_auth:
        raise ValueError(
            f"WEN proof algorithm mismatch: expected={expected_auth}, actual={proof_alg}"
        )
    if proof_alg == "hmac-sha256":
        return None, ""

    public_key = base64.b64decode(
        metadata.get("proof_public_key_b64", ""),
        validate=True,
    )
    if len(public_key) != 32:
        raise ValueError("WEN Ed25519 public key is missing or malformed")
    key_id = sha256_hex(public_key)
    if metadata.get("proof_key_id", "") != key_id:
        raise ValueError("WEN Ed25519 key identifier does not match its public key")
    if expected_key_sha256 and key_id != expected_key_sha256.lower():
        raise ValueError(
            f"WEN signing-key pin mismatch: expected={expected_key_sha256.lower()}, "
            f"actual={key_id}"
        )
    return public_key, key_id


def verify_response_proof(
    response: dict[str, Any],
    *,
    proof_secret: str,
    public_key: bytes | None,
) -> None:
    proof_alg = response.get("proof_alg", "")
    if proof_alg == "hmac-sha256":
        expected_mac = compute_proof_mac(proof_secret, response_proof_fields(response))
        if response.get("proof_mac") != expected_mac:
            raise ValueError("proof MAC mismatch")
        return
    if proof_alg != "ed25519" or public_key is None:
        raise ValueError(f"unsupported or unpinned proof algorithm: {proof_alg}")
    if response.get("proof_key_id") != sha256_hex(public_key):
        raise ValueError("response signing key changed during the benchmark")
    verify_ed25519_proof(
        public_key,
        response.get("proof_signature_b64", ""),
        response_proof_fields(response),
    )

def response_wire_bytes(response: dict[str, Any]) -> float:
    """Return the compact JSON payload size used by the framed protocol."""
    return float(
        len(json.dumps(response, separators=(",", ":")).encode("utf-8"))
    )



def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_full_evidence_response(response: dict[str, Any]) -> dict[str, float]:
    """Validate the exact protocol-1.2 evidence bundle signed by the WEN."""
    raw_quote_b64 = response.get("raw_quote", "")
    runtime_evidence = response.get("runtime_evidence")
    command_log_b64 = response.get("command_log", "")

    if not raw_quote_b64:
        raise ValueError("missing raw_quote")
    if not isinstance(runtime_evidence, dict) or not runtime_evidence:
        raise ValueError("missing runtime_evidence")
    if runtime_evidence.get("version") != "ima-rtmr3-vtpm-v2":
        raise ValueError("runtime_evidence is not protocol 1.2")
    if not command_log_b64:
        raise ValueError("missing command_log")

    try:
        raw_quote = base64.b64decode(raw_quote_b64, validate=True)
        runtime_evidence_bytes = json.dumps(
            runtime_evidence,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        ima_binary = base64.b64decode(
            runtime_evidence.get("ima_binary_log_b64", ""),
            validate=True,
        )
        ima_ascii = base64.b64decode(
            runtime_evidence.get("ima_ascii_log_b64", ""),
            validate=True,
        )
        command_log = base64.b64decode(command_log_b64, validate=True)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise ValueError(f"malformed full-evidence encoding: {exc}") from exc

    if not ima_binary or not ima_ascii:
        raise ValueError("runtime_evidence is missing its binary or ASCII IMA delta")

    raw_quote_sha256 = sha256_hex(raw_quote)
    runtime_evidence_sha256 = sha256_hex(runtime_evidence_bytes)
    ima_log_sha256 = sha256_hex(ima_binary + ima_ascii)
    command_log_sha256 = sha256_hex(command_log)

    if response.get("raw_quote_sha256") != raw_quote_sha256:
        raise ValueError("raw_quote_sha256 mismatch")
    if response.get("runtime_evidence_sha256") != runtime_evidence_sha256:
        raise ValueError("runtime_evidence_sha256 mismatch")
    if response.get("ima_log_sha256") != ima_log_sha256:
        raise ValueError("ima_log_sha256 mismatch")
    if response.get("command_log_sha256") != command_log_sha256:
        raise ValueError("command_log_sha256 mismatch")

    return {
        "response_payload_bytes": response_wire_bytes(response),
        "raw_quote_bytes": float(len(raw_quote)),
        "runtime_evidence_bytes": float(len(runtime_evidence_bytes)),
        "ima_log_bytes": float(len(ima_binary) + len(ima_ascii)),
        "command_log_bytes": float(len(command_log)),
        "ima_entry_count": float(response.get("ima_entry_count", 0)),
        "command_log_entries": float(response.get("command_log_entries", 0)),
    }


def build_client_ssl_context(ca_cert: str | None, verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if verify and ca_cert:
        ctx.load_verify_locations(ca_cert)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


async def query_server(host: str, port: int, ssl_ctx: ssl.SSLContext | None, action: str) -> dict[str, Any]:
    reader, writer = await asyncio.open_connection(host, port, ssl=ssl_ctx, limit=STREAM_LIMIT_BYTES)
    try:
        await send_json(writer, {"action": action})
        return await recv_json(reader)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError, OSError):
            # The server may close the connection first during shutdown; that
            # should not invalidate an otherwise successful benchmark point.
            pass


async def wait_for_server(host: str, port: int, ssl_ctx: ssl.SSLContext | None, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_error = "timeout"
    while time.monotonic() < deadline:
        try:
            response = await query_server(host, port, ssl_ctx, "health")
            if response.get("status") == "success" and response.get("ready"):
                return
            if (
                response.get("status") == "success"
                and int(response.get("refresh_count", 0)) > 0
                and not response.get("verified")
            ):
                detail = response.get("error") or response.get("verdict") or "unknown error"
                raise RuntimeError(f"initial WEN refresh failed: {detail}")
            last_error = json.dumps(response)
        except Exception as exc:  # pragma: no cover - best effort
            last_error = str(exc)
        await asyncio.sleep(0.2)
    raise TimeoutError(f"server did not become ready within {timeout_s}s: {last_error}")


async def measure_control_rtt(
    host: str,
    port: int,
    ssl_ctx: ssl.SSLContext | None,
    samples: int = 5,
) -> list[float]:
    values: list[float] = []
    for _ in range(samples):
        started = time.perf_counter()
        response = await query_server(host, port, ssl_ctx, "health")
        if response.get("status") != "success" or not response.get("ready"):
            raise RuntimeError(f"WEN preflight health check failed: {response}")
        values.append((time.perf_counter() - started) * 1000.0)
    return values


async def warmup_delegated_requests(
    host: str,
    port: int,
    ssl_ctx: ssl.SSLContext | None,
    *,
    count: int,
    proof_secret: str,
    proof_public_key: bytes | None,
    verify_proof: bool,
    evidence_mode: str,
) -> None:
    if count <= 0:
        return
    reader, writer = await asyncio.open_connection(
        host, port, ssl=ssl_ctx, limit=STREAM_LIMIT_BYTES
    )
    try:
        for _ in range(count):
            nonce = generate_nonce()
            await send_json(writer, {"action": "verify", "nonce": nonce})
            response = await recv_json(reader)
            if response.get("status") != "success" or response.get("nonce_echo") != nonce:
                raise RuntimeError(f"delegated-response warm-up failed: {response}")
            if response.get("evidence_mode", "light") != evidence_mode:
                raise RuntimeError("delegated-response warm-up evidence mode mismatch")
            if verify_proof:
                verify_response_proof(
                    response,
                    proof_secret=proof_secret,
                    public_key=proof_public_key,
                )
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError, OSError):
            pass


async def one_user(
    user_id: int,
    host: str,
    port: int,
    ssl_ctx: ssl.SSLContext | None,
    deadline: float,
    proof_secret: str,
    proof_public_key: bytes | None,
    verify_proof: bool,
    requests_per_user: int,
    evidence_mode: str,
) -> dict[str, Any]:
    latencies: list[float] = []
    connection_times: list[float] = []
    proof_verify_times: list[float] = []
    proof_signing_times: list[float] = []
    server_processing_times: list[float] = []
    refresh_overlap: list[bool] = []
    staleness: list[float] = []
    response_payload_bytes: list[float] = []
    raw_quote_bytes: list[float] = []
    runtime_evidence_bytes: list[float] = []
    ima_log_bytes: list[float] = []
    command_log_bytes: list[float] = []
    ima_entry_counts: list[float] = []
    command_log_entries: list[float] = []
    successful = 0
    failed = 0
    error_samples: list[str] = []
    sent = 0
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None

    try:
        connect_started = time.perf_counter()
        reader, writer = await asyncio.open_connection(host, port, ssl=ssl_ctx, limit=STREAM_LIMIT_BYTES)
        connection_times.append((time.perf_counter() - connect_started) * 1000.0)
        while time.monotonic() < deadline:
            if requests_per_user and sent >= requests_per_user:
                break
            nonce = generate_nonce()
            t0 = time.perf_counter()
            await send_json(writer, {"action": "verify", "nonce": nonce})
            response = await recv_json(reader)
            latency_ms = (time.perf_counter() - t0) * 1000.0
            sent += 1

            try:
                if response.get("status") != "success":
                    raise ValueError(response.get("error", "server returned error"))
                if response.get("nonce_echo") != nonce:
                    raise ValueError("nonce mismatch")
                if response.get("evidence_mode", "light") != evidence_mode:
                    raise ValueError("evidence mode mismatch")
                if verify_proof:
                    proof_started = time.perf_counter()
                    verify_response_proof(
                        response, proof_secret=proof_secret, public_key=proof_public_key
                    )
                    proof_verify_times.append((time.perf_counter() - proof_started) * 1000.0)
                response_payload_bytes.append(response_wire_bytes(response))
                if evidence_mode == "full":
                    evidence_sizes = verify_full_evidence_response(response)
                    raw_quote_bytes.append(evidence_sizes["raw_quote_bytes"])
                    runtime_evidence_bytes.append(
                        evidence_sizes["runtime_evidence_bytes"]
                    )
                    ima_log_bytes.append(evidence_sizes["ima_log_bytes"])
                    command_log_bytes.append(evidence_sizes["command_log_bytes"])
                    ima_entry_counts.append(evidence_sizes["ima_entry_count"])
                    command_log_entries.append(evidence_sizes["command_log_entries"])
                successful += 1
                latencies.append(latency_ms)
                proof_signing_times.append(float(response.get("proof_signing_ms", 0.0)))
                server_processing_times.append(float(response.get("server_processing_ms", 0.0)))
                refresh_overlap.append(bool(response.get("wen_refresh_in_progress", False)))
                staleness.append(float(response.get("staleness_ms", 0.0)))
            except Exception as exc:
                failed += 1
                error_samples.append(str(exc))
    except Exception as exc:
        failed += 1
        error_samples.append(str(exc))
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError, ssl.SSLError, OSError):
                # Teardown races are expected when the server or peer closes
                # the socket before asyncio finishes draining the writer.
                pass

    return {
        "user_id": user_id,
        "sent": sent,
        "attempted": sent,
        "successful": successful,
        "failed": failed,
        "latencies_ms": latencies,
        "service_latencies_ms": latencies,
        "connection_ms": connection_times,
        "generator_queue_delay_ms": [],
        "proof_verify_ms": proof_verify_times,
        "proof_signing_ms": proof_signing_times,
        "server_processing_ms": server_processing_times,
        "refresh_overlap": refresh_overlap,
        "staleness_ms": staleness,
        "response_payload_bytes": response_payload_bytes,
        "raw_quote_bytes": raw_quote_bytes,
        "runtime_evidence_bytes": runtime_evidence_bytes,
        "ima_log_bytes": ima_log_bytes,
        "command_log_bytes": command_log_bytes,
        "ima_entry_counts": ima_entry_counts,
        "command_log_entries": command_log_entries,
        "errors": error_samples[:5],
    }


async def one_shot_user(
    user_id: int,
    host: str,
    port: int,
    ssl_ctx: ssl.SSLContext | None,
    proof_secret: str,
    proof_public_key: bytes | None,
    verify_proof: bool,
    evidence_mode: str,
    connection_model: str,
    ready_queue: asyncio.Queue[int],
    start_event: asyncio.Event,
    timing: dict[str, float],
) -> dict[str, Any]:
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    connect_ms = 0.0
    connect_error = ""

    async def connect() -> tuple[asyncio.StreamReader, asyncio.StreamWriter, float]:
        started = time.perf_counter()
        connected_reader, connected_writer = await asyncio.open_connection(
            host,
            port,
            ssl=ssl_ctx,
            limit=STREAM_LIMIT_BYTES,
        )
        return connected_reader, connected_writer, (time.perf_counter() - started) * 1000.0

    if connection_model == "pre-established":
        try:
            reader, writer, connect_ms = await connect()
        except Exception as exc:
            connect_error = str(exc)

    await ready_queue.put(user_id)
    await start_event.wait()
    barrier_started = timing["started_perf"]

    if connection_model == "new" and not connect_error:
        try:
            reader, writer, connect_ms = await connect()
        except Exception as exc:
            connect_error = str(exc)

    result: dict[str, Any] = {
        "user_id": user_id,
        "sent": 0,
        "attempted": 1,
        "successful": 0,
        "failed": 0,
        "completion_perf": 0.0,
        "latencies_ms": [],
        "service_latencies_ms": [],
        "connection_ms": [connect_ms] if connect_ms else [],
        "generator_queue_delay_ms": [],
        "staleness_ms": [],
        "proof_verify_ms": [],
        "proof_signing_ms": [],
        "server_processing_ms": [],
        "refresh_overlap": [],
        "response_payload_bytes": [],
        "raw_quote_bytes": [],
        "runtime_evidence_bytes": [],
        "ima_log_bytes": [],
        "command_log_bytes": [],
        "ima_entry_counts": [],
        "command_log_entries": [],
        "errors": [],
    }

    try:
        if connect_error or reader is None or writer is None:
            raise ConnectionError(connect_error or "connection was not established")

        nonce = generate_nonce()
        request_started = time.perf_counter()
        await send_json(writer, {"action": "verify", "nonce": nonce})
        result["sent"] = 1
        response = await recv_json(reader)
        completed = time.perf_counter()
        result["completion_perf"] = completed
        service_ms = (completed - request_started) * 1000.0
        completion_ms = (completed - barrier_started) * 1000.0

        if response.get("status") != "success":
            raise ValueError(response.get("error", "server returned error"))
        if response.get("nonce_echo") != nonce:
            raise ValueError("nonce mismatch")
        if response.get("evidence_mode", "light") != evidence_mode:
            raise ValueError("evidence mode mismatch")

        proof_started = time.perf_counter()
        if verify_proof:
            verify_response_proof(
                response,
                proof_secret=proof_secret,
                public_key=proof_public_key,
            )
        result["proof_verify_ms"].append(
            (time.perf_counter() - proof_started) * 1000.0
        )
        result["response_payload_bytes"].append(response_wire_bytes(response))

        if evidence_mode == "full":
            evidence_sizes = verify_full_evidence_response(response)
            for result_key, size_key in (
                ("raw_quote_bytes", "raw_quote_bytes"),
                ("runtime_evidence_bytes", "runtime_evidence_bytes"),
                ("ima_log_bytes", "ima_log_bytes"),
                ("command_log_bytes", "command_log_bytes"),
                ("ima_entry_counts", "ima_entry_count"),
                ("command_log_entries", "command_log_entries"),
            ):
                result[result_key].append(evidence_sizes[size_key])

        completed = time.perf_counter()
        result["completion_perf"] = completed
        service_ms = (completed - request_started) * 1000.0
        completion_ms = (completed - barrier_started) * 1000.0

        result["successful"] = 1
        result["latencies_ms"].append(completion_ms)
        result["service_latencies_ms"].append(service_ms)
        result["staleness_ms"].append(float(response.get("staleness_ms", 0.0)))
        result["proof_signing_ms"].append(float(response.get("proof_signing_ms", 0.0)))
        result["server_processing_ms"].append(float(response.get("server_processing_ms", 0.0)))
        result["refresh_overlap"].append(bool(response.get("wen_refresh_in_progress", False)))
    except Exception as exc:
        if not result["completion_perf"]:
            result["completion_perf"] = time.perf_counter()
        result["failed"] = 1
        result["errors"] = [str(exc)]
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError, ssl.SSLError, OSError):
                pass
    return result


async def open_loop_worker(
    worker_id: int,
    host: str,
    port: int,
    ssl_ctx: ssl.SSLContext | None,
    proof_secret: str,
    proof_public_key: bytes | None,
    verify_proof: bool,
    evidence_mode: str,
    request_queue: asyncio.Queue[dict[str, float] | None],
    ready_queue: asyncio.Queue[int],
    start_event: asyncio.Event,
    result: dict[str, Any],
) -> None:
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    connect_error = ""
    connect_started = time.perf_counter()
    try:
        reader, writer = await asyncio.open_connection(
            host,
            port,
            ssl=ssl_ctx,
            limit=STREAM_LIMIT_BYTES,
        )
        result["connection_ms"].append(
            (time.perf_counter() - connect_started) * 1000.0
        )
    except Exception as exc:
        connect_error = str(exc)
        result["errors"].append(f"worker {worker_id}: {exc}")

    await ready_queue.put(worker_id)
    await start_event.wait()
    if connect_error or reader is None or writer is None:
        return

    try:
        while True:
            job = await request_queue.get()
            if job is None:
                request_queue.task_done()
                return

            intended_at = job["intended_at"]
            actual_send = time.perf_counter()
            result["generator_queue_delay_ms"].append(
                max(0.0, (actual_send - intended_at) * 1000.0)
            )
            nonce = generate_nonce()
            try:
                await send_json(writer, {"action": "verify", "nonce": nonce})
                result["sent"] += 1
                response = await recv_json(reader)
                if response.get("status") != "success":
                    raise ValueError(response.get("error", "server returned error"))
                if response.get("nonce_echo") != nonce:
                    raise ValueError("nonce mismatch")
                if response.get("evidence_mode", "light") != evidence_mode:
                    raise ValueError("evidence mode mismatch")

                proof_started = time.perf_counter()
                if verify_proof:
                    verify_response_proof(
                        response,
                        proof_secret=proof_secret,
                        public_key=proof_public_key,
                    )
                result["proof_verify_ms"].append(
                    (time.perf_counter() - proof_started) * 1000.0
                )
                result["response_payload_bytes"].append(
                    response_wire_bytes(response)
                )

                if evidence_mode == "full":
                    evidence_sizes = verify_full_evidence_response(response)
                    for result_key, size_key in (
                        ("raw_quote_bytes", "raw_quote_bytes"),
                        ("runtime_evidence_bytes", "runtime_evidence_bytes"),
                        ("ima_log_bytes", "ima_log_bytes"),
                        ("command_log_bytes", "command_log_bytes"),
                        ("ima_entry_counts", "ima_entry_count"),
                        ("command_log_entries", "command_log_entries"),
                    ):
                        result[result_key].append(evidence_sizes[size_key])

                completed = time.perf_counter()
                service_ms = (completed - actual_send) * 1000.0
                latency_ms = (completed - intended_at) * 1000.0

                result["successful"] += 1
                result["latencies_ms"].append(latency_ms)
                result["service_latencies_ms"].append(service_ms)
                result["staleness_ms"].append(float(response.get("staleness_ms", 0.0)))
                result["proof_signing_ms"].append(float(response.get("proof_signing_ms", 0.0)))
                result["server_processing_ms"].append(float(response.get("server_processing_ms", 0.0)))
                result["refresh_overlap"].append(bool(response.get("wen_refresh_in_progress", False)))
            except Exception as exc:
                result["failed"] += 1
                if len(result["errors"]) < 20:
                    result["errors"].append(f"request {int(job['request_id'])}: {exc}")
            finally:
                request_queue.task_done()
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError, ssl.SSLError, OSError):
                pass


async def run_open_loop(
    *,
    args: argparse.Namespace,
    host: str,
    port: int,
    ssl_ctx: ssl.SSLContext | None,
    proof_public_key: bytes | None,
    offered_rate: float,
) -> tuple[list[dict[str, Any]], float, dict[str, Any]]:
    request_queue: asyncio.Queue[dict[str, float] | None] = asyncio.Queue()
    ready_queue: asyncio.Queue[int] = asyncio.Queue()
    start_event = asyncio.Event()
    result: dict[str, Any] = {
        "user_id": -1,
        "sent": 0,
        "attempted": 0,
        "successful": 0,
        "failed": 0,
        "latencies_ms": [],
        "service_latencies_ms": [],
        "connection_ms": [],
        "generator_queue_delay_ms": [],
        "staleness_ms": [],
        "proof_verify_ms": [],
        "proof_signing_ms": [],
        "server_processing_ms": [],
        "refresh_overlap": [],
        "response_payload_bytes": [],
        "raw_quote_bytes": [],
        "runtime_evidence_bytes": [],
        "ima_log_bytes": [],
        "command_log_bytes": [],
        "ima_entry_counts": [],
        "command_log_entries": [],
        "errors": [],
    }
    workers = [
        asyncio.create_task(
            open_loop_worker(
                worker_id=i,
                host=host,
                port=port,
                ssl_ctx=ssl_ctx,
                proof_secret=args.proof_secret,
                proof_public_key=proof_public_key,
                verify_proof=not args.no_verify_proof,
                evidence_mode=args.evidence_mode,
                request_queue=request_queue,
                ready_queue=ready_queue,
                start_event=start_event,
                result=result,
            )
        )
        for i in range(args.connections)
    ]
    for _ in range(args.connections):
        await asyncio.wait_for(ready_queue.get(), timeout=args.client_ready_timeout_s)

    rng = random.Random(args.random_seed)
    measurement_started = time.perf_counter()
    start_event.set()
    request_id = 0
    max_queue_depth = 0
    offset_s = 0.0
    while offset_s < args.duration_s:
        intended_at = measurement_started + offset_s
        delay = intended_at - time.perf_counter()
        if delay > 0:
            await asyncio.sleep(delay)
        await request_queue.put(
            {"request_id": float(request_id), "intended_at": intended_at}
        )
        max_queue_depth = max(max_queue_depth, request_queue.qsize())
        request_id += 1
        if args.arrival_process == "poisson":
            offset_s += rng.expovariate(offered_rate)
        else:
            offset_s += 1.0 / offered_rate
    result["attempted"] = request_id

    drain_timed_out = False
    try:
        await asyncio.wait_for(request_queue.join(), timeout=args.open_loop_drain_s)
    except asyncio.TimeoutError:
        drain_timed_out = True
        if len(result["errors"]) < 20:
            result["errors"].append(
                f"open-loop drain exceeded {args.open_loop_drain_s}s"
            )
    measurement_elapsed_s = time.perf_counter() - measurement_started

    if drain_timed_out:
        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
    else:
        for _ in workers:
            await request_queue.put(None)
        await request_queue.join()
        await asyncio.gather(*workers)

    result["failed"] = max(
        result["failed"], result["attempted"] - result["successful"]
    )
    details = {
        "offered_rate_rps": offered_rate,
        "arrival_process": args.arrival_process,
        "connections": args.connections,
        "scheduled_requests": request_id,
        "max_generator_queue_depth": max_queue_depth,
        "drain_timed_out": drain_timed_out,
    }
    return [result], measurement_elapsed_s, details


def summarize_run(
    *,
    users: int,
    duration_s: float,
    configured_duration_s: float,
    workload_model: str,
    connection_model: str,
    response_auth: str,
    proof_key_id: str,
    proof_secret: str,
    verify_proof: bool,
    transport: str,
    server_runtime: str,
    user_results: list[dict[str, Any]],
    start_stats: dict[str, Any],
    end_stats: dict[str, Any],
) -> dict[str, Any]:
    latencies = [item for result in user_results for item in result["latencies_ms"]]
    service_latencies = [item for result in user_results for item in result.get("service_latencies_ms", [])]
    connection_times = [item for result in user_results for item in result.get("connection_ms", [])]
    generator_queue_delays = [item for result in user_results for item in result.get("generator_queue_delay_ms", [])]
    proof_verify_times = [item for result in user_results for item in result.get("proof_verify_ms", [])]
    proof_signing_times = [item for result in user_results for item in result.get("proof_signing_ms", [])]
    server_processing_times = [item for result in user_results for item in result.get("server_processing_ms", [])]
    refresh_overlap = [item for result in user_results for item in result.get("refresh_overlap", [])]
    staleness = [item for result in user_results for item in result["staleness_ms"]]
    response_payload_bytes = [item for result in user_results for item in result["response_payload_bytes"]]
    raw_quote_bytes = [item for result in user_results for item in result["raw_quote_bytes"]]
    runtime_evidence_bytes = [item for result in user_results for item in result["runtime_evidence_bytes"]]
    ima_log_bytes = [item for result in user_results for item in result["ima_log_bytes"]]
    command_log_bytes = [item for result in user_results for item in result["command_log_bytes"]]
    ima_entry_counts = [item for result in user_results for item in result["ima_entry_counts"]]
    command_log_entries = [item for result in user_results for item in result["command_log_entries"]]
    successful = sum(result["successful"] for result in user_results)
    failed = sum(result["failed"] for result in user_results)
    sent = sum(result["sent"] for result in user_results)
    attempted = sum(result.get("attempted", result["sent"]) for result in user_results)
    refresh_total = int(end_stats.get("refresh_count", 0))
    refresh_delta = max(0, refresh_total - int(start_stats.get("refresh_count", 0)))
    latency_stats = summarize_samples(latencies)
    service_stats = summarize_samples(service_latencies)
    connection_stats = summarize_samples(connection_times)
    generator_queue_stats = summarize_samples(generator_queue_delays)
    proof_verify_stats = summarize_samples(proof_verify_times)
    proof_signing_stats = summarize_samples(proof_signing_times)
    server_processing_stats = summarize_samples(server_processing_times)
    staleness_stats = summarize_samples(staleness)
    payload_stats = summarize_samples(response_payload_bytes)
    raw_quote_stats = summarize_samples(raw_quote_bytes)
    runtime_evidence_stats = summarize_samples(runtime_evidence_bytes)
    ima_log_stats = summarize_samples(ima_log_bytes)
    command_log_stats = summarize_samples(command_log_bytes)
    ima_entry_stats = summarize_samples(ima_entry_counts)
    command_entry_stats = summarize_samples(command_log_entries)

    return {
        "model": "vordr-single-wen",
        "evidence_mode": end_stats.get("evidence_mode", "light"),
        "users": users,
        "workload_model": workload_model,
        "connection_model": connection_model,
        "configured_duration_s": configured_duration_s,
        "duration_s": duration_s,
        "response_auth": response_auth,
        "proof_key_id": proof_key_id,
        "proof_key_origin": end_stats.get("proof_key_origin", ""),
        "transport": transport,
        "server_runtime": server_runtime,
        "peak_active_connections": end_stats.get("peak_active_connections", 0),
        "active_connections_end": max(0, int(end_stats.get("active_connections", 0)) - 1),
        "verify_proof": verify_proof,
        "attempted": attempted,
        "sent": sent,
        "successful": successful,
        "failed": failed,
        "error_rate_pct": (failed / attempted * 100.0) if attempted else 0.0,
        "throughput_rps": (successful / duration_s) if duration_s > 0 else 0.0,
        "mean_ms": latency_stats["mean"],
        "median_ms": latency_stats["median"],
        "p95_ms": latency_stats["p95"],
        "p99_ms": latency_stats["p99"],
        "p999_ms": latency_stats["p999"],
        "mean_service_ms": service_stats["mean"],
        "p99_service_ms": service_stats["p99"],
        "mean_connection_ms": connection_stats["mean"],
        "p99_connection_ms": connection_stats["p99"],
        "mean_generator_queue_delay_ms": generator_queue_stats["mean"],
        "p99_generator_queue_delay_ms": generator_queue_stats["p99"],
        "mean_proof_verify_ms": proof_verify_stats["mean"],
        "mean_proof_signing_ms": proof_signing_stats["mean"],
        "mean_server_processing_ms": server_processing_stats["mean"],
        "refresh_overlap_responses": sum(1 for item in refresh_overlap if item),
        "min_ms": latency_stats["min"],
        "max_ms": latency_stats["max"],
        "stdev_ms": latency_stats["stdev"],
        "mean_staleness_ms": staleness_stats["mean"],
        "p95_staleness_ms": staleness_stats["p95"],
        "max_staleness_ms": staleness_stats["max"],
        "refresh_count_total": refresh_total,
        "refresh_count_delta": refresh_delta,
        "amplification_total_refreshes": (successful / refresh_total) if refresh_total > 0 else 0.0,
        "amplification_run_refreshes": (successful / refresh_delta) if refresh_delta > 0 else 0.0,
        "last_refresh_ms": end_stats.get("last_refresh_ms", 0.0),
        "tdx_verdict": end_stats.get("tdx_verdict", ""),
        "tdx_runtime_verdict": end_stats.get("tdx_runtime_verdict", ""),
        "mean_response_payload_bytes": payload_stats["mean"],
        "p99_response_payload_bytes": payload_stats["p99"],
        "mean_raw_quote_bytes": raw_quote_stats["mean"],
        "mean_runtime_evidence_bytes": runtime_evidence_stats["mean"],
        "mean_ima_log_bytes": ima_log_stats["mean"],
        "mean_command_log_bytes": command_log_stats["mean"],
        "mean_ima_entries": ima_entry_stats["mean"],
        "mean_command_log_entries": command_entry_stats["mean"],
        "snapshot_raw_quote_bytes": end_stats.get("raw_quote_size", 0.0),
        "snapshot_runtime_evidence_bytes": end_stats.get("runtime_evidence_size", 0.0),
        "snapshot_ima_log_bytes": end_stats.get("ima_log_size", 0.0),
        "snapshot_command_log_bytes": end_stats.get("command_log_size", 0.0),
        "snapshot_ima_entries": end_stats.get("ima_entry_count", 0.0),
        "snapshot_command_log_entries": end_stats.get("command_log_entries", 0.0),
    }


def build_server_cmd(args: argparse.Namespace, port: int) -> list[str]:
    if args.server_runtime == "python":
        cmd = [sys.executable, str(SERVER_SCRIPT)]
    else:
        cmd = [args.server_runtime, str(GRAMINE_APP), GRAMINE_ENTRYPOINT]

    cmd.extend(
        [
            "--listen-host",
            args.host,
            "--port",
            str(port),
            "--controller-id",
            args.controller_id,
            "--evidence-mode",
            args.evidence_mode,
            "--refresh-backend",
            args.refresh_backend,
            "--refresh-interval-s",
            str(args.refresh_interval_s),
            "--synthetic-refresh-ms",
            str(args.synthetic_refresh_ms),
            "--synthetic-ima-entries",
            str(args.synthetic_ima_entries),
            "--tdx-method",
            args.tdx_method,
            "--proof-secret",
            args.proof_secret,
            "--response-auth",
            args.response_auth,
        ]
    )
    if args.server_runtime == "gramine-sgx" and args.response_auth == "ed25519":
        cmd.append("--require-sgx-signing-key")
    if args.refresh_backend == "sgx-verifier":
        cmd.extend(["--tdx-host", args.tdx_host, "--tdx-port", str(args.tdx_port)])
        if args.tdx_ca_cert:
            cmd.extend(["--tdx-ca-cert", map_server_path(args.tdx_ca_cert, args.server_runtime)])
        if args.no_verify_tdx:
            cmd.append("--no-verify-tdx")
    if args.transport == "tls":
        cmd.extend(
            [
                "--tls-cert",
                map_server_path(args.tls_cert, args.server_runtime),
                "--tls-key",
                map_server_path(args.tls_key, args.server_runtime),
            ]
        )
    if args.command_log_file:
        cmd.extend(["--command-log-file", map_server_path(args.command_log_file, args.server_runtime)])
    return cmd


def map_server_path(path_value: str | None, server_runtime: str) -> str | None:
    if not path_value or server_runtime == "python":
        return path_value
    if path_value.startswith("/app/"):
        return path_value
    path = Path(path_value).expanduser()
    if not path.is_absolute():
        # Resolve relative paths from the caller's current working directory
        # first, since the sweep is commonly invoked from evaluation/scalability.
        path = (Path.cwd() / path).resolve(strict=False)
    else:
        path = path.resolve(strict=False)
    try:
        relative = path.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise ValueError(
            f"Gramine server runtime only supports files under the repo root: {path_value}"
        ) from exc
    return f"/app/{relative.as_posix()}"


def server_workdir(server_runtime: str) -> Path:
    return SCALABILITY_DIR if server_runtime in GRAMINE_RUNTIMES else REPO_ROOT


def prepare_server_runtime(args: argparse.Namespace) -> None:
    if args.no_spawn_server or args.server_runtime not in GRAMINE_RUNTIMES or args.skip_server_build:
        return
    build_cmd = ["make", "-C", str(SCALABILITY_DIR), "all"]
    if args.gramine_log_level:
        build_cmd.append(f"LOG_LEVEL={args.gramine_log_level}")
    subprocess.run(build_cmd, check=True, cwd=str(REPO_ROOT))


def is_local_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "0.0.0.0"}


def port_is_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex((host, port)) == 0


def choose_spawn_port(host: str, requested_port: int) -> int:
    if not is_local_host(host):
        return requested_port
    if not port_is_open("127.0.0.1", requested_port):
        return requested_port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def run_one_point(
    args: argparse.Namespace,
    users: int,
    out_dir: Path,
    offered_rate: float = 0.0,
    repeat: int = 1,
) -> tuple[dict[str, Any], dict[str, Any]]:
    transport = args.transport
    ssl_ctx = None
    if transport == "tls":
        ssl_ctx = build_client_ssl_context(args.client_ca_cert, verify=not args.no_verify_server_cert)

    server_proc: subprocess.Popen[str] | None = None
    server_log = None
    active_port = args.port
    if not args.no_spawn_server:
        active_port = choose_spawn_port(args.host, args.port)
        if active_port != args.port:
            print(f"  note: port {args.port} already in use locally, using {active_port} instead")
        point_label = (
            f"rate{offered_rate:g}" if offered_rate else f"users{users}"
        ) + f"-repeat{repeat}"
        server_log_path = out_dir / f"server-{point_label}.log"
        server_log = server_log_path.open("w", encoding="utf-8")
        server_cmd = build_server_cmd(args, active_port)
        server_env = dict(os.environ)
        server_env["PYTHONUNBUFFERED"] = "1"
        server_proc = subprocess.Popen(
            server_cmd,
            stdout=server_log,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(server_workdir(args.server_runtime)),
            env=server_env,
        )
        await asyncio.sleep(0.25)
        if server_proc.poll() is not None:
            raise RuntimeError(f"spawned server exited early; see {server_log_path}")
        await wait_for_server(
            args.host, active_port, ssl_ctx, timeout_s=args.server_ready_timeout_s
        )
        if args.warmup_s > 0:
            await asyncio.sleep(args.warmup_s)
    else:
        await wait_for_server(
            args.host, active_port, ssl_ctx, timeout_s=args.server_ready_timeout_s
        )
        if args.warmup_s > 0:
            await asyncio.sleep(args.warmup_s)

    try:
        identity_stats = await query_server(args.host, active_port, ssl_ctx, "stats")
        preflight_rtts = await measure_control_rtt(args.host, active_port, ssl_ctx)
        proof_public_key, proof_key_id = validate_server_proof_identity(
            identity_stats,
            expected_auth=args.response_auth,
            expected_key_sha256=args.expected_signing_key_sha256,
        )
        await warmup_delegated_requests(
            args.host,
            active_port,
            ssl_ctx,
            count=args.client_warmup_requests,
            proof_secret=args.proof_secret,
            proof_public_key=proof_public_key,
            verify_proof=not args.no_verify_proof,
            evidence_mode=args.evidence_mode,
        )
        start_stats = await query_server(args.host, active_port, ssl_ctx, "stats")
        open_loop_details: dict[str, Any] = {}
        if args.workload_model == "open-loop":
            user_results, measurement_elapsed_s, open_loop_details = await run_open_loop(
                args=args,
                host=args.host,
                port=active_port,
                ssl_ctx=ssl_ctx,
                proof_public_key=proof_public_key,
                offered_rate=offered_rate,
            )
        elif args.workload_model == "one-shot":
            ready_queue: asyncio.Queue[int] = asyncio.Queue()
            start_event = asyncio.Event()
            timing: dict[str, float] = {}
            tasks = [
                asyncio.create_task(
                    one_shot_user(
                        user_id=i,
                        host=args.host,
                        port=active_port,
                        ssl_ctx=ssl_ctx,
                        proof_secret=args.proof_secret,
                        proof_public_key=proof_public_key,
                        verify_proof=not args.no_verify_proof,
                        evidence_mode=args.evidence_mode,
                        connection_model=args.connection_model,
                        ready_queue=ready_queue,
                        start_event=start_event,
                        timing=timing,
                    )
                )
                for i in range(users)
            ]
            for _ in range(users):
                await asyncio.wait_for(
                    ready_queue.get(), timeout=args.client_ready_timeout_s
                )
            measurement_started = time.perf_counter()
            timing["started_perf"] = measurement_started
            timing["started_wall"] = time.time()
            start_event.set()
            user_results = await asyncio.gather(*tasks)
            final_completion = max(
                result["completion_perf"] for result in user_results
            )
            measurement_elapsed_s = final_completion - measurement_started
        else:
            measurement_started = time.perf_counter()
            deadline = measurement_started + args.duration_s
            user_results = await asyncio.gather(
                *[
                    one_user(
                        user_id=i,
                        host=args.host,
                        port=active_port,
                        ssl_ctx=ssl_ctx,
                        deadline=deadline,
                        proof_secret=args.proof_secret,
                        proof_public_key=proof_public_key,
                        verify_proof=not args.no_verify_proof,
                        requests_per_user=args.requests_per_user,
                        evidence_mode=args.evidence_mode,
                    )
                    for i in range(users)
                ]
            )
            measurement_elapsed_s = time.perf_counter() - measurement_started
        end_stats = await query_server(args.host, active_port, ssl_ctx, "stats")
    finally:
        if server_proc is not None:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()
                server_proc.wait(timeout=5)
        if server_log is not None:
            server_log.close()

    summary = summarize_run(
        users=users,
        duration_s=measurement_elapsed_s,
        configured_duration_s=args.duration_s,
        workload_model=args.workload_model,
        connection_model=args.connection_model,
        response_auth=args.response_auth,
        proof_key_id=proof_key_id,
        proof_secret=args.proof_secret,
        verify_proof=not args.no_verify_proof,
        transport=transport,
        server_runtime=args.server_runtime,
        user_results=user_results,
        start_stats=start_stats,
        end_stats=end_stats,
    )
    summary.update(open_loop_details)
    summary["repeat"] = repeat
    preflight_stats = summarize_samples(preflight_rtts)
    summary["preflight_mean_rtt_ms"] = preflight_stats["mean"]
    summary["preflight_p99_rtt_ms"] = preflight_stats["p99"]
    raw = {
        "preflight_rtt_ms": preflight_rtts,
        "measurement": {
            "repeat": repeat,
            "workload_model": args.workload_model,
            "configured_duration_s": args.duration_s,
            "actual_duration_s": measurement_elapsed_s,
            **open_loop_details,
        },
        "summary": summary,
        "start_stats": start_stats,
        "end_stats": end_stats,
        "user_results": user_results,
    }
    return summary, raw


def main() -> None:
    parser = argparse.ArgumentParser(description="Single-WEN scalability sweep")
    parser.add_argument("--users", default="1,4,16,64,256,512", help="Concurrent end-user counts")
    parser.add_argument("--duration-s", type=float, default=10.0)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument(
        "--workload-model",
        choices=["closed-loop", "one-shot", "open-loop"],
        default="closed-loop",
        help="Arrival model used for this sweep",
    )
    parser.add_argument(
        "--connection-model",
        choices=["pre-established", "new"],
        default="pre-established",
        help="For one-shot bursts, connect before or after barrier release",
    )
    parser.add_argument("--client-ready-timeout-s", type=float, default=60.0)
    parser.add_argument(
        "--client-warmup-requests",
        type=int,
        default=10,
        help="Verified delegated responses completed before each measured point",
    )
    parser.add_argument(
        "--offered-rates",
        default="1000,2500,5000,7500,9000,10000,11000,12500",
        help="Comma-separated request rates for open-loop mode",
    )
    parser.add_argument("--connections", type=int, default=64)
    parser.add_argument(
        "--arrival-process",
        choices=["poisson", "constant"],
        default="poisson",
    )
    parser.add_argument("--random-seed", type=int, default=2027)
    parser.add_argument("--open-loop-drain-s", type=float, default=30.0)
    parser.add_argument(
        "--evidence-mode",
        choices=["light", "full"],
        default="light",
        help="Return either lightweight cached verdicts or the full evidence bundle",
    )
    parser.add_argument(
        "--requests-per-user",
        type=int,
        default=0,
        help="Optional cap on requests per user connection; 0 means unbounded until duration expires",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--controller-id", default="wen-1")
    parser.add_argument("--transport", choices=["tcp", "tls"], default="tcp")
    parser.add_argument(
        "--server-runtime",
        choices=["python", "gramine-direct", "gramine-sgx"],
        default="python",
        help="How to launch the local WEN server for each sweep point",
    )
    parser.add_argument("--skip-server-build", action="store_true", help="Skip the Gramine build step for enclave runtimes")
    parser.add_argument("--gramine-log-level", default="error")
    parser.add_argument("--client-ca-cert", default=None)
    parser.add_argument("--no-verify-server-cert", action="store_true")
    parser.add_argument("--proof-secret", default="vordr-benchmark-secret")
    parser.add_argument(
        "--response-auth",
        choices=["hmac-sha256", "ed25519"],
        default="ed25519",
        help="Expected delegated-response authentication mode",
    )
    parser.add_argument(
        "--expected-signing-key-sha256",
        default="",
        help="Optional pinned SHA-256 fingerprint of the WEN Ed25519 public key",
    )
    parser.add_argument("--require-signing-key-pin", action="store_true")
    parser.add_argument("--no-verify-proof", action="store_true")
    parser.add_argument("--no-spawn-server", action="store_true")
    parser.add_argument("--server-ready-timeout-s", type=float, default=20.0)
    parser.add_argument("--warmup-s", type=float, default=0.5)
    parser.add_argument("--refresh-backend", choices=["synthetic", "sgx-verifier"], default="synthetic")
    parser.add_argument("--refresh-interval-s", type=float, default=30.0)
    parser.add_argument("--synthetic-refresh-ms", type=float, default=42.0)
    parser.add_argument("--synthetic-ima-entries", type=int, default=128)
    parser.add_argument("--tdx-host", default="")
    parser.add_argument("--tdx-port", type=int, default=8443)
    parser.add_argument("--tdx-method", default="dcap")
    parser.add_argument("--tdx-ca-cert", default=None)
    parser.add_argument("--no-verify-tdx", action="store_true")
    parser.add_argument("--command-log-file", default=None)
    parser.add_argument(
        "--tls-cert",
        default=str(REPO_ROOT / "research" / "sgx-tdx-attestation" / "certs" / "server.crt"),
    )
    parser.add_argument(
        "--tls-key",
        default=str(REPO_ROOT / "research" / "sgx-tdx-attestation" / "certs" / "server.key"),
    )
    parser.add_argument("--experiment-label", default="")
    parser.add_argument("--load-generator-location", default="")
    parser.add_argument("--load-generator-hardware", default="")
    parser.add_argument("--loadgen-wen-rtt-ms", type=float, default=0.0)
    parser.add_argument("--loadgen-wen-rtt-method", default="")
    parser.add_argument("--wen-cvm-rtt-ms", type=float, default=0.0)
    parser.add_argument("--wen-cvm-rtt-method", default="")
    parser.add_argument("--wen-location", default="")
    parser.add_argument("--wen-hardware", default="")
    parser.add_argument("--cvm-hardware", default="")
    parser.add_argument("--cvm-location", default="")
    parser.add_argument("--cvm-image", default="")
    parser.add_argument("--cvm-kernel", default="")
    parser.add_argument("--ima-policy", default="")
    parser.add_argument("--baseline-ima-count", type=int, default=0)
    parser.add_argument("--tpm2-tools-version", default="")
    parser.add_argument("--gotpm-version", default="")
    parser.add_argument("--dcap-version", default="")
    parser.add_argument(
        "--out-dir",
        default=str(REPO_ROOT / "evaluation" / "results" / "scalability" / time.strftime("vordr-single-wen-%Y%m%d-%H%M%S")),
    )
    args = parser.parse_args()

    users_list = [int(item.strip()) for item in args.users.split(",") if item.strip()]
    offered_rates = parse_float_list(args.offered_rates)
    if not users_list:
        parser.error("--users must contain at least one value")
    if not args.no_spawn_server and args.refresh_backend == "sgx-verifier" and not args.tdx_host:
        parser.error("--tdx-host is required with --refresh-backend sgx-verifier")
    if args.require_signing_key_pin and not args.expected_signing_key_sha256:
        parser.error("--require-signing-key-pin requires --expected-signing-key-sha256")
    if args.require_signing_key_pin and args.response_auth != "ed25519":
        parser.error("--require-signing-key-pin is only valid with --response-auth ed25519")
    if args.expected_signing_key_sha256 and len(args.expected_signing_key_sha256) != 64:
        parser.error("--expected-signing-key-sha256 must contain 64 hexadecimal characters")
    if args.expected_signing_key_sha256:
        try:
            int(args.expected_signing_key_sha256, 16)
        except ValueError:
            parser.error("--expected-signing-key-sha256 must be hexadecimal")
    if args.transport == "tls" and not args.no_verify_server_cert and not args.client_ca_cert:
        parser.error("verified TLS requires --client-ca-cert (or explicitly use --no-verify-server-cert)")
    if args.no_spawn_server and args.host == "0.0.0.0":
        parser.error("--host must name the remote WEN when --no-spawn-server is used")
    if (
        args.evidence_mode == "full"
        and not args.no_spawn_server
        and not args.command_log_file
    ):
        parser.error("--command-log-file is required with --evidence-mode full")

    if args.duration_s <= 0:
        parser.error("--duration-s must be positive")
    if args.repetitions <= 0:
        parser.error("--repetitions must be positive")
    if args.connections <= 0:
        parser.error("--connections must be positive")
    if args.client_warmup_requests < 0:
        parser.error("--client-warmup-requests cannot be negative")
    if any(rate <= 0 for rate in offered_rates):
        parser.error("--offered-rates values must be positive")
    out_dir = ensure_dir(Path(args.out_dir))
    raw_dir = ensure_dir(out_dir / "raw")
    summaries: list[dict[str, Any]] = []

    prepare_server_runtime(args)
    metadata = collect_reproducibility_metadata(args)
    metadata_path = out_dir / "run_metadata.json"
    metadata_path.write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )

    print("=" * 72)
    print("Single-WEN Vordr Scalability Sweep")
    print("=" * 72)
    print(f"Model:       {args.workload_model}")
    if args.workload_model == "open-loop":
        print(f"Rates:       {offered_rates} req/s")
        print(f"Connections: {args.connections}")
    else:
        print(f"Users:       {users_list}")
    print(f"Duration:    {args.duration_s}s")
    print(f"Repetitions: {args.repetitions}")
    print(f"Transport:   {args.transport}")
    print(f"Runtime:     {args.server_runtime}")
    print(f"Proof:       {args.response_auth}")
    print(f"Backend:     {args.refresh_backend}")
    print(f"Evidence:    {args.evidence_mode}")
    print(f"Out dir:     {out_dir}")
    print("=" * 72)

    points = (
        [(args.connections, rate) for rate in offered_rates]
        if args.workload_model == "open-loop"
        else [(users, 0.0) for users in users_list]
    )
    repeated_points = [
        (users, offered_rate, repeat)
        for users, offered_rate in points
        for repeat in range(1, args.repetitions + 1)
    ]
    for users, offered_rate, repeat in repeated_points:
        point_text = f"rate={offered_rate:g} rps" if offered_rate else f"users={users}"
        print(f"\n[vordr] {point_text}, repeat={repeat}/{args.repetitions}")
        summary, raw = asyncio.run(
            run_one_point(
                args, users, out_dir, offered_rate, repeat=repeat
            )
        )
        summaries.append(summary)
        raw_path = raw_dir / raw_point_filename(
            workload_model=args.workload_model,
            connection_model=args.connection_model,
            users=users,
            offered_rate=offered_rate,
            repeat=repeat,
        )
        write_gzip_json(raw_path, raw)
        metadata["completed_points"].append(
            {
                "repeat": repeat,
                "users": users,
                "offered_rate_rps": offered_rate,
                "proof_key_id": summary.get("proof_key_id", ""),
                "throughput_rps": summary.get("throughput_rps", 0.0),
                "error_rate_pct": summary.get("error_rate_pct", 0.0),
                "raw_file": str(raw_path.relative_to(out_dir)),
                "raw_compressed_bytes": raw_path.stat().st_size,
            }
        )
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        write_csv(out_dir / "vordr_single_wen_summary.csv", summaries)
        del raw
        print(
            "  "
            f"throughput={summary['throughput_rps']:.2f} rps "
            f"mean={summary['mean_ms']:.2f}ms "
            f"p99={summary['p99_ms']:.2f}ms "
            f"run-amp={summary['amplification_run_refreshes']:.1f}x"
        )

    write_csv(out_dir / "vordr_single_wen_summary.csv", summaries)

    print(f"\nSaved summary to: {out_dir / 'vordr_single_wen_summary.csv'}")
    print(f"Saved compressed per-point raw data under: {raw_dir}")


if __name__ == "__main__":
    main()
