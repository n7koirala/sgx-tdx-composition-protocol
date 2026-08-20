#!/usr/bin/env python3
"""High-throughput single-WEN service for the Vordr scalability evaluation."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import resource
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

# Gramine launches the Python entrypoint through an external wrapper, and in
# practice that has not always preserved the script directory on sys.path.
THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from scale_common import ResponseProofSigner, generate_nonce, recv_json, send_json


REPO_ROOT = Path(__file__).resolve().parents[2]
SGX_TDX_ROOT = REPO_ROOT / "research" / "sgx-tdx-attestation"
STREAM_LIMIT_BYTES = 256 * 1024 * 1024

AUDIT_EVIDENCE_MODES = frozenset({"ima-audit", "full-audit", "full"})
RAW_QUOTE_EVIDENCE_MODES = frozenset({"full-audit", "full"})


def is_audit_evidence_mode(mode: str) -> bool:
    return mode in AUDIT_EVIDENCE_MODES


def includes_raw_tdx_quote(mode: str) -> bool:
    return mode in RAW_QUOTE_EVIDENCE_MODES


def ensure_nofile_soft_limit(minimum: int) -> tuple[int, int]:
    """Raise RLIMIT_NOFILE without lowering an already larger limit."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard < minimum:
        raise RuntimeError(
            f"RLIMIT_NOFILE hard limit {hard} is below required minimum {minimum}"
        )
    if soft < minimum:
        resource.setrlimit(resource.RLIMIT_NOFILE, (minimum, hard))
    return resource.getrlimit(resource.RLIMIT_NOFILE)


@dataclass
class CachedTDXState:
    verified: bool = False
    verdict: str = "PENDING"
    attestation_method: str = "dcap"
    mrtd: str = ""
    quote_hash: str = ""
    tcb_status: str = ""
    is_debuggable: bool = False
    ima_verified: bool = False
    runtime_verdict: str = ""
    verification_time: float = 0.0
    refresh_count: int = 0
    last_refresh_ms: float = 0.0
    cvm_update_in_progress: bool = False
    raw_quote: str = ""
    raw_quote_sha256: str = ""
    raw_quote_size: int = 0
    ima_log: str = ""
    ima_log_sha256: str = ""
    ima_log_size: int = 0
    ima_entry_count: int = 0
    pcr10: str = ""
    pcr10_sha256: str = ""
    runtime_evidence: dict[str, Any] = field(default_factory=dict)
    runtime_evidence_sha256: str = ""
    runtime_evidence_size: int = 0
    command_log: str = ""
    command_log_sha256: str = ""
    command_log_size: int = 0
    command_log_entries: int = 0
    command_log_format: str = ""
    warnings: list[str] = field(default_factory=list)
    error: str = ""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class CommandLogSnapshot:
    text: str = ""
    entry_count: int = 0
    log_format: str = "jsonl"

    @property
    def encoded(self) -> str:
        return base64.b64encode(self.text.encode("utf-8")).decode("ascii") if self.text else ""

    @property
    def size_bytes(self) -> int:
        return len(self.text.encode("utf-8"))

    @property
    def sha256(self) -> str:
        return sha256_hex(self.text.encode("utf-8"))


class NullCommandLogProvider:
    def snapshot(self) -> CommandLogSnapshot:
        return CommandLogSnapshot()


class FileCommandLogProvider:
    def __init__(self, path: Path) -> None:
        self.path = path

    def snapshot(self) -> CommandLogSnapshot:
        if not self.path.exists():
            raise FileNotFoundError(f"command log file not found: {self.path}")
        text = self.path.read_text(encoding="utf-8")
        stripped = text.strip()
        if not stripped:
            return CommandLogSnapshot(log_format=self._detect_format(""))

        log_format = self._detect_format(stripped)
        if log_format == "jsonl":
            entry_count = len([line for line in stripped.splitlines() if line.strip()])
        else:
            payload = json.loads(stripped)
            if isinstance(payload, dict) and isinstance(payload.get("entries"), list):
                entry_count = len(payload["entries"])
            elif isinstance(payload, list):
                entry_count = len(payload)
            else:
                entry_count = 1
        return CommandLogSnapshot(text=text, entry_count=entry_count, log_format=log_format)

    def _detect_format(self, text: str) -> str:
        if not text:
            return "jsonl"
        if self.path.suffix.lower() == ".jsonl":
            return "jsonl"
        if self.path.suffix.lower() == ".json":
            return "json"
        if "\n" in text:
            return "jsonl"
        return "json"


class SyntheticRefreshBackend:
    """Refresh backend for harness bring-up and dry-run benchmarking."""

    def __init__(
        self,
        latency_ms: float,
        method: str = "dcap",
        evidence_mode: str = "light",
        synthetic_ima_entries: int = 128,
        command_log_provider: FileCommandLogProvider | NullCommandLogProvider | None = None,
    ) -> None:
        self.latency_ms = latency_ms
        self.method = method
        self.evidence_mode = evidence_mode
        self.synthetic_ima_entries = synthetic_ima_entries
        self.command_log_provider = command_log_provider or NullCommandLogProvider()

    def refresh(self, refresh_count: int) -> CachedTDXState:
        start = time.perf_counter()
        time.sleep(self.latency_ms / 1000.0)
        refresh_time = time.time()
        quote_material = f"synthetic:{refresh_count}:{refresh_time:.6f}".encode("utf-8")
        state = CachedTDXState(
            verified=True,
            verdict="TRUSTED",
            attestation_method=self.method,
            mrtd=hashlib.sha256(b"synthetic-mrtd").hexdigest(),
            quote_hash=sha256_hex(quote_material),
            tcb_status="UpToDate",
            is_debuggable=False,
            ima_verified=True,
            runtime_verdict="CLEAN",
            verification_time=refresh_time,
            refresh_count=refresh_count,
            last_refresh_ms=(time.perf_counter() - start) * 1000.0,
        )
        if is_audit_evidence_mode(self.evidence_mode):
            quote_bytes = (quote_material * 128)[:4096]
            ima_lines = [
                f"10 {i:040x} ima-ng sha256:{hashlib.sha256(f'synthetic-{refresh_count}-{i}'.encode('utf-8')).hexdigest()} "
                f"/usr/local/bin/synth-{i:04d}"
                for i in range(self.synthetic_ima_entries)
            ]
            ima_log_text = "\n".join(ima_lines) + "\n"
            ima_log_bytes = ima_log_text.encode("utf-8")
            runtime_evidence = {
                "version": "ima-rtmr3-vtpm-v2",
                "ima_binary_log_b64": base64.b64encode(ima_log_bytes).decode("ascii"),
                "ima_ascii_log_b64": base64.b64encode(ima_log_bytes).decode("ascii"),
                "ima_entry_count": len(ima_lines),
                "ima_start_index": 0,
                "synthetic": True,
            }
            runtime_evidence_bytes = json.dumps(
                runtime_evidence,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            command_log = self.command_log_provider.snapshot()
            state.raw_quote = base64.b64encode(quote_bytes).decode("ascii")
            state.raw_quote_sha256 = sha256_hex(quote_bytes)
            state.raw_quote_size = len(quote_bytes)
            state.ima_log = runtime_evidence["ima_ascii_log_b64"]
            state.ima_log_sha256 = sha256_hex(ima_log_bytes + ima_log_bytes)
            state.ima_log_size = len(ima_log_bytes) * 2
            state.ima_entry_count = len(ima_lines)
            state.pcr10 = hashlib.sha256(ima_log_text.encode("utf-8")).hexdigest()
            state.pcr10_sha256 = sha256_hex(state.pcr10.encode("utf-8"))
            state.runtime_evidence = runtime_evidence
            state.runtime_evidence_sha256 = sha256_hex(runtime_evidence_bytes)
            state.runtime_evidence_size = len(runtime_evidence_bytes)
            state.command_log = command_log.encoded
            state.command_log_sha256 = command_log.sha256
            state.command_log_size = command_log.size_bytes
            state.command_log_entries = command_log.entry_count
            state.command_log_format = command_log.log_format
        return state


class SGXVerifierRefreshBackend:
    """Refresh backend that performs real background TDX attestation via SGXTDXVerifier."""

    def __init__(
        self,
        tdx_host: str,
        tdx_port: int,
        method: str,
        verify_cert: bool,
        ca_cert: str | None,
        evidence_mode: str = "light",
        command_log_provider: FileCommandLogProvider | NullCommandLogProvider | None = None,
    ) -> None:
        sys.path.insert(0, str(SGX_TDX_ROOT / "sgx-verifier"))
        from sgx_tdx_verifier import SGXTDXVerifier  # type: ignore

        self.SGXTDXVerifier = SGXTDXVerifier
        self.tdx_host = tdx_host
        self.tdx_port = tdx_port
        self.method = method
        self.verify_cert = verify_cert
        self.ca_cert = ca_cert
        self.evidence_mode = evidence_mode
        self.command_log_provider = command_log_provider or NullCommandLogProvider()
        self._audit_binary = b""
        self._audit_ascii = b""
        self._audit_entry_count = 0

        checkpoint_id = hashlib.sha256(
            f"scalability|{tdx_host}|{tdx_port}|{method}".encode("utf-8")
        ).hexdigest()[:24]
        checkpoint_file = (
            "/app/research/sgx-tdx-attestation/runtime-state/"
            f"sealed-checkpoints/scalability-{checkpoint_id}.checkpoint"
        )
        self.verifier = self.SGXTDXVerifier(
            tdx_host=self.tdx_host,
            tdx_port=self.tdx_port,
            method=self.method,
            verify_cert=self.verify_cert,
            ca_cert=self.ca_cert,
            verbose=False,
            checkpoint_file=checkpoint_file,
            checkpoint_namespace="scalability-vtpm-1.2",
            reset_checkpoint=is_audit_evidence_mode(self.evidence_mode),
        )

    def _accumulate_audit_evidence(self, evidence: dict[str, Any]) -> dict[str, Any]:
        """Build a start-at-zero audit snapshot from verified wire deltas."""
        start = int(evidence.get("ima_start_index", 0))
        total = int(evidence.get("ima_entry_count", 0))
        binary_delta = base64.b64decode(evidence.get("ima_binary_log_b64", ""))
        ascii_delta = base64.b64decode(evidence.get("ima_ascii_log_b64", ""))

        if start == 0:
            self._audit_binary = binary_delta
            self._audit_ascii = ascii_delta
        elif start == self._audit_entry_count:
            self._audit_binary += binary_delta
            self._audit_ascii += ascii_delta
        else:
            raise RuntimeError(
                "verified IMA delta does not continue the WEN audit archive: "
                f"start={start}, archived={self._audit_entry_count}, total={total}"
            )
        self._audit_entry_count = total

        archived = dict(evidence)
        archived["ima_start_index"] = 0
        archived["ima_binary_log_b64"] = base64.b64encode(
            self._audit_binary
        ).decode("ascii")
        archived["ima_ascii_log_b64"] = base64.b64encode(
            self._audit_ascii
        ).decode("ascii")
        stream = dict(archived.get("stream", {}))
        stream.update(
            {
                "wire_delta_entries": total,
                "wire_binary_bytes": len(self._audit_binary),
                "wire_ascii_bytes": len(self._audit_ascii),
                "audit_archive": {
                    "source": "verified-delta-accumulation",
                    "entry_count": total,
                },
            }
        )
        archived["stream"] = stream
        return archived

    def refresh(self, refresh_count: int) -> CachedTDXState:
        start = time.perf_counter()
        result = self.verifier.attest_tdx()
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        response = self.verifier.last_response
        raw_quote_b64 = getattr(response, "raw_quote", "") if response else ""
        raw_quote_bytes = (
            base64.b64decode(raw_quote_b64)
            if raw_quote_b64
            else b""
        )
        runtime_evidence = getattr(response, "runtime_evidence", {}) if response else {}
        if runtime_evidence:
            runtime_evidence = dict(runtime_evidence)
            # Preserve the challenge that the enclave already verified so a
            # Mode-2 auditor can independently check the exported vTPM quote.
            runtime_evidence["wen_cvm_nonce_b64"] = getattr(
                response, "nonce_echo", ""
            )
        runtime_evidence_bytes = (
            json.dumps(runtime_evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if runtime_evidence
            else b""
        )
        include_audit = is_audit_evidence_mode(self.evidence_mode)
        if include_audit and result.verified and runtime_evidence:
            runtime_evidence = self._accumulate_audit_evidence(runtime_evidence)
            runtime_evidence_bytes = json.dumps(
                runtime_evidence, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        command_log = self.command_log_provider.snapshot()
        ima_binary_b64 = runtime_evidence.get("ima_binary_log_b64", "")
        ima_ascii_b64 = runtime_evidence.get("ima_ascii_log_b64", "")
        ima_binary_bytes = base64.b64decode(ima_binary_b64) if ima_binary_b64 else b""
        ima_ascii_bytes = base64.b64decode(ima_ascii_b64) if ima_ascii_b64 else b""
        pcr10 = getattr(response, "pcr10", "") if response else ""
        return CachedTDXState(
            verified=result.verified,
            verdict=result.verdict or ("TRUSTED" if result.verified else "ERROR"),
            attestation_method=result.attestation_method or self.method,
            mrtd=result.mrtd,
            quote_hash=sha256_hex(raw_quote_bytes) if raw_quote_bytes else "",
            tcb_status=result.tcb_status,
            is_debuggable=result.is_debuggable,
            ima_verified=result.ima_verified,
            runtime_verdict=result.runtime_verdict,
            verification_time=time.time(),
            refresh_count=refresh_count,
            last_refresh_ms=elapsed_ms,
            raw_quote=raw_quote_b64 if include_audit else "",
            raw_quote_sha256=sha256_hex(raw_quote_bytes) if raw_quote_bytes else "",
            raw_quote_size=len(raw_quote_bytes),
            ima_log=ima_ascii_b64 if include_audit else "",
            ima_log_sha256=sha256_hex(ima_binary_bytes + ima_ascii_bytes) if runtime_evidence else "",
            ima_log_size=len(ima_binary_bytes) + len(ima_ascii_bytes),
            pcr10=pcr10 if include_audit else "",
            pcr10_sha256=sha256_hex(pcr10.encode("utf-8")) if pcr10 else "",
            runtime_evidence=runtime_evidence if include_audit else {},
            runtime_evidence_sha256=sha256_hex(runtime_evidence_bytes) if runtime_evidence_bytes else "",
            runtime_evidence_size=len(runtime_evidence_bytes),
            command_log=command_log.encoded if include_audit else "",
            command_log_sha256=command_log.sha256,
            command_log_size=command_log.size_bytes,
            command_log_entries=command_log.entry_count,
            command_log_format=command_log.log_format,
            ima_entry_count=result.ima_entry_count,
            warnings=list(result.warnings),
            error=result.error,
        )


class FullEvidenceTDXRefreshBackend:
    """Legacy protocol <=1.1 full-evidence collector.

    Protocol 1.2 runs real refreshes through SGXVerifierRefreshBackend so audit
    responses reuse the exact composed evidence already accepted by the WEN.
    """

    def __init__(
        self,
        tdx_host: str,
        tdx_port: int,
        method: str,
        verify_cert: bool,
        ca_cert: str | None,
        command_log_provider: FileCommandLogProvider | NullCommandLogProvider | None = None,
    ) -> None:
        sys.path.insert(0, str(SGX_TDX_ROOT))
        from common.protocol import (  # type: ignore
            AttestationRequest,
            AttestationResponse,
            METHOD_DCAP,
            create_tls_context_client,
            receive_message,
            send_message,
            verify_dcap_quote,
            verify_ima_log,
        )

        self.AttestationRequest = AttestationRequest
        self.AttestationResponse = AttestationResponse
        self.METHOD_DCAP = METHOD_DCAP
        self.create_tls_context_client = create_tls_context_client
        self.receive_message = receive_message
        self.send_message = send_message
        self.verify_dcap_quote = verify_dcap_quote
        self.verify_ima_log = verify_ima_log
        self.tdx_host = tdx_host
        self.tdx_port = tdx_port
        self.method = method
        self.verify_cert = verify_cert
        self.ca_cert = ca_cert
        self.command_log_provider = command_log_provider or NullCommandLogProvider()

    def refresh(self, refresh_count: int) -> CachedTDXState:
        if self.method != self.METHOD_DCAP:
            raise ValueError("full evidence mode currently requires --tdx-method dcap")

        start = time.perf_counter()
        nonce = generate_nonce()
        command_log = self.command_log_provider.snapshot()
        tls_context = self.create_tls_context_client(
            ca_cert_file=self.ca_cert,
            verify=self.verify_cert,
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        tls_sock = tls_context.wrap_socket(sock, server_hostname=self.tdx_host)

        try:
            tls_sock.connect((self.tdx_host, self.tdx_port))
            request = self.AttestationRequest(nonce=nonce, attestation_method=self.method)
            self.send_message(tls_sock, request.to_json())
            response = self.AttestationResponse.from_json(self.receive_message(tls_sock))
        finally:
            tls_sock.close()

        if response.status != "success":
            raise RuntimeError(f"TDX server error: {response.error}")
        if not response.raw_quote:
            raise RuntimeError("TDX server did not return a raw quote")
        if not response.ima_log or not response.pcr10:
            raise RuntimeError("TDX server did not return the full IMA evidence bundle")

        quote_bytes = base64.b64decode(response.raw_quote)
        verify_result = self.verify_dcap_quote(quote_bytes, nonce, debug=False)

        ima_log_text = ""
        ima_verified = False
        runtime_verdict = "IMA_UNAVAILABLE"
        warnings = list(verify_result.warnings)
        if response.ima_log and response.pcr10:
            ima_log_text = base64.b64decode(response.ima_log).decode("utf-8")
            ima_verified, ima_count, ima_msg = self.verify_ima_log(
                ima_log_text,
                response.pcr10,
                debug=False,
            )
            if ima_verified:
                runtime_verdict = "CLEAN"
            else:
                runtime_verdict = "RUNTIME_VIOLATION"
                warnings.append(f"IMA verification failed: {ima_msg}")
            if ima_count and response.ima_entry_count == 0:
                response.ima_entry_count = ima_count

        refresh_time = time.time()
        overall_verified = verify_result.verified and (runtime_verdict != "RUNTIME_VIOLATION")
        return CachedTDXState(
            verified=overall_verified,
            verdict=verify_result.verdict or ("TRUSTED" if overall_verified else "ERROR"),
            attestation_method=response.attestation_method or self.method,
            mrtd=response.mrtd or verify_result.mrtd,
            quote_hash=sha256_hex(quote_bytes),
            tcb_status=verify_result.tcb_status,
            is_debuggable=verify_result.is_debuggable,
            ima_verified=ima_verified,
            runtime_verdict=runtime_verdict,
            verification_time=refresh_time,
            refresh_count=refresh_count,
            last_refresh_ms=(time.perf_counter() - start) * 1000.0,
            raw_quote=response.raw_quote,
            raw_quote_sha256=sha256_hex(quote_bytes),
            raw_quote_size=len(quote_bytes),
            ima_log=response.ima_log,
            ima_log_sha256=sha256_hex(ima_log_text.encode("utf-8")) if ima_log_text else "",
            ima_log_size=len(ima_log_text.encode("utf-8")),
            ima_entry_count=response.ima_entry_count,
            pcr10=response.pcr10,
            pcr10_sha256=sha256_hex(response.pcr10.encode("utf-8")) if response.pcr10 else "",
            command_log=command_log.encoded,
            command_log_sha256=command_log.sha256,
            command_log_size=command_log.size_bytes,
            command_log_entries=command_log.entry_count,
            command_log_format=command_log.log_format,
            warnings=warnings,
            error=verify_result.error,
        )


class VordrServer:
    def __init__(
        self,
        listen_host: str,
        port: int,
        listen_backlog: int,
        nofile_soft_limit: int,
        nofile_hard_limit: int,
        controller_id: str,
        evidence_mode: str,
        refresh_interval_s: float,
        backend: Any,
        proof_secret: str,
        response_auth: str,
        require_sgx_signing_key: bool,
        ssl_context: ssl.SSLContext | None,
        cvm_update_in_progress: bool = False,
    ) -> None:
        self.listen_host = listen_host
        self.port = port
        self.listen_backlog = listen_backlog
        self.nofile_soft_limit = nofile_soft_limit
        self.nofile_hard_limit = nofile_hard_limit
        self.controller_id = controller_id
        self.evidence_mode = evidence_mode
        self.refresh_interval_s = refresh_interval_s
        self.backend = backend
        self.proof_signer = ResponseProofSigner(
            response_auth,
            controller_id=controller_id,
            proof_secret=proof_secret,
            require_sgx_key=require_sgx_signing_key,
        )
        self.ssl_context = ssl_context
        self.cvm_update_in_progress = cvm_update_in_progress
        self.state = CachedTDXState()
        self._state_lock = asyncio.Lock()
        self._server: asyncio.base_events.Server | None = None
        self._refresh_task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()
        self.started_at = time.time()
        self.refresh_active = False
        self.refresh_started_at = 0.0
        self.refresh_completed_at = 0.0
        self.active_connections = 0
        self.peak_active_connections = 0
        self.stats = {
            "requests": 0,
            "served": 0,
            "errors": 0,
        }

    async def _refresh_once(self) -> None:
        refresh_number = self.state.refresh_count + 1
        self.refresh_active = True
        self.refresh_started_at = time.time()
        try:
            new_state = await asyncio.to_thread(self.backend.refresh, refresh_number)
        except Exception as exc:
            now = time.time()
            new_state = CachedTDXState(
                verified=False,
                verdict="ERROR",
                verification_time=now,
                refresh_count=refresh_number,
                last_refresh_ms=0.0,
                cvm_update_in_progress=self.cvm_update_in_progress,
                error=str(exc),
            )

        self.refresh_active = False
        self.refresh_completed_at = time.time()
        new_state.cvm_update_in_progress = self.cvm_update_in_progress

        async with self._state_lock:
            self.state = new_state

        status = "ok" if new_state.verified else "error"
        print(
            f"[vordr] refresh #{new_state.refresh_count}: "
            f"{status} verdict={new_state.verdict} "
            f"latency={new_state.last_refresh_ms:.1f}ms"
        )

    async def _refresh_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=self.refresh_interval_s)
            except asyncio.TimeoutError:
                await self._refresh_once()

    async def _snapshot_state(self) -> CachedTDXState:
        async with self._state_lock:
            # Refresh replaces the whole state object; it never mutates a published
            # runtime-evidence dict. Avoid recursively copying a multi-megabyte log.
            return replace(self.state)

    async def _handle_verify(self, request: dict[str, Any]) -> dict[str, Any]:
        self.stats["requests"] += 1
        start = time.perf_counter()
        nonce = request.get("nonce", "")
        refresh_in_progress = self.refresh_active
        if not nonce:
            self.stats["errors"] += 1
            return {"status": "error", "error": "missing nonce"}

        snapshot = await self._snapshot_state()
        if snapshot.refresh_count == 0:
            self.stats["errors"] += 1
            return {"status": "error", "error": "controller not ready"}

        now = time.time()
        staleness_ms = max(0.0, (now - snapshot.verification_time) * 1000.0)
        nonce_hash = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
        proof_fields = {
            "controller_id": self.controller_id,
            "evidence_mode": self.evidence_mode,
            "nonce_echo": nonce,
            "nonce_hash": nonce_hash,
            "wen_refresh_in_progress": refresh_in_progress,
            "cvm_update_in_progress": snapshot.cvm_update_in_progress,
            "tdx_verdict": snapshot.verdict,
            "tdx_mrtd": snapshot.mrtd,
            "tdx_quote_hash": snapshot.quote_hash,
            "runtime_verdict": snapshot.runtime_verdict,
            "tdx_verification_time": snapshot.verification_time,
            "refresh_count": snapshot.refresh_count,
            "raw_quote_sha256": snapshot.raw_quote_sha256,
            "runtime_evidence_sha256": snapshot.runtime_evidence_sha256,
            "ima_log_sha256": snapshot.ima_log_sha256,
            "pcr10_sha256": snapshot.pcr10_sha256,
            "command_log_sha256": snapshot.command_log_sha256,
            "ima_entry_count": snapshot.ima_entry_count,
            "command_log_entries": snapshot.command_log_entries,
            "issued_at": now,
        }

        proof_start = time.perf_counter()
        proof = self.proof_signer.authenticate(proof_fields)
        proof_signing_ms = (time.perf_counter() - proof_start) * 1000.0
        response = {
            "status": "success" if snapshot.verified else "error",
            "controller_id": self.controller_id,
            "evidence_mode": self.evidence_mode,
            "nonce_echo": nonce,
            "nonce_hash": nonce_hash,
            **proof,
            "wen_refresh_in_progress": refresh_in_progress,
            "issued_at": now,
            "tdx_verified": snapshot.verified,
            "cvm_update_in_progress": snapshot.cvm_update_in_progress,
            "tdx_verdict": snapshot.verdict,
            "tdx_attestation_method": snapshot.attestation_method,
            "tdx_mrtd": snapshot.mrtd,
            "tdx_quote_hash": snapshot.quote_hash,
            "tdx_tcb_status": snapshot.tcb_status,
            "tdx_is_debuggable": snapshot.is_debuggable,
            "tdx_ima_verified": snapshot.ima_verified,
            "tdx_runtime_verdict": snapshot.runtime_verdict,
            "tdx_verification_time": snapshot.verification_time,
            "refresh_count": snapshot.refresh_count,
            "last_refresh_ms": snapshot.last_refresh_ms,
            "staleness_ms": staleness_ms,
            "raw_quote_sha256": snapshot.raw_quote_sha256,
            "raw_quote_size": snapshot.raw_quote_size,
            "runtime_evidence_sha256": snapshot.runtime_evidence_sha256,
            "runtime_evidence_size": snapshot.runtime_evidence_size,
            "ima_log_sha256": snapshot.ima_log_sha256,
            "ima_log_size": snapshot.ima_log_size,
            "ima_entry_count": snapshot.ima_entry_count,
            "pcr10_sha256": snapshot.pcr10_sha256,
            "command_log_sha256": snapshot.command_log_sha256,
            "command_log_size": snapshot.command_log_size,
            "command_log_entries": snapshot.command_log_entries,
            "command_log_format": snapshot.command_log_format,
            "warnings": snapshot.warnings,
            "error": snapshot.error,
            "proof_signing_ms": proof_signing_ms,
            "server_processing_ms": (time.perf_counter() - start) * 1000.0,
        }
        if is_audit_evidence_mode(self.evidence_mode):
            response.update(
                {
                    "runtime_evidence": snapshot.runtime_evidence,
                    "command_log": snapshot.command_log,
                }
            )
            if includes_raw_tdx_quote(self.evidence_mode):
                response["raw_quote"] = snapshot.raw_quote
            if self.evidence_mode == "full":
                # Preserve the old wire schema for existing result scripts.
                response["ima_log"] = snapshot.ima_log
                response["pcr10"] = snapshot.pcr10
        if snapshot.verified:
            self.stats["served"] += 1
        else:
            self.stats["errors"] += 1
        return response

    async def _handle_stats(self) -> dict[str, Any]:
        snapshot = await self._snapshot_state()
        now = time.time()
        return {
            "status": "success",
            "controller_id": self.controller_id,
            "evidence_mode": self.evidence_mode,
            **self.proof_signer.metadata(),
            "requests": self.stats["requests"],
            "served": self.stats["served"],
            "errors": self.stats["errors"],
            "refresh_count": snapshot.refresh_count,
            "last_refresh_ms": snapshot.last_refresh_ms,
            "refresh_in_progress": self.refresh_active,
            "refresh_started_at": self.refresh_started_at,
            "refresh_completed_at": self.refresh_completed_at,
            "cvm_update_in_progress": snapshot.cvm_update_in_progress,
            "tdx_verification_time": snapshot.verification_time,
            "staleness_ms": max(0.0, (now - snapshot.verification_time) * 1000.0) if snapshot.verification_time else 0.0,
            "tdx_verdict": snapshot.verdict,
            "tdx_quote_hash": snapshot.quote_hash,
            "tdx_runtime_verdict": snapshot.runtime_verdict,
            "warnings": snapshot.warnings,
            "error": snapshot.error,
            "raw_quote_size": snapshot.raw_quote_size,
            "runtime_evidence_size": snapshot.runtime_evidence_size,
            "runtime_evidence_sha256": snapshot.runtime_evidence_sha256,
            "ima_log_size": snapshot.ima_log_size,
            "ima_entry_count": snapshot.ima_entry_count,
            "command_log_size": snapshot.command_log_size,
            "command_log_entries": snapshot.command_log_entries,
            "active_connections": self.active_connections,
            "peak_active_connections": self.peak_active_connections,
            "listen_backlog": self.listen_backlog,
            "nofile_soft_limit": self.nofile_soft_limit,
            "nofile_hard_limit": self.nofile_hard_limit,
            "uptime_s": now - self.started_at,
        }

    async def _handle_health(self) -> dict[str, Any]:
        snapshot = await self._snapshot_state()
        return {
            "status": "success",
            "ready": snapshot.refresh_count > 0 and snapshot.verified,
            "verified": snapshot.verified,
            **self.proof_signer.metadata(),
            "cvm_update_in_progress": snapshot.cvm_update_in_progress,
            "refresh_count": snapshot.refresh_count,
            "verdict": snapshot.verdict,
            "runtime_verdict": snapshot.runtime_verdict,
            "warnings": snapshot.warnings,
            "error": snapshot.error,
        }

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.active_connections += 1
        self.peak_active_connections = max(
            self.peak_active_connections, self.active_connections
        )
        try:
            while not reader.at_eof():
                request = await recv_json(reader)
                action = request.get("action", "verify")
                if action == "verify":
                    response = await self._handle_verify(request)
                elif action == "stats":
                    response = await self._handle_stats()
                elif action == "health":
                    response = await self._handle_health()
                elif action == "reset_peak":
                    self.peak_active_connections = self.active_connections
                    response = await self._handle_stats()
                else:
                    self.stats["errors"] += 1
                    response = {"status": "error", "error": f"unknown action: {action}"}
                await send_json(writer, response)
        except ConnectionError:
            pass
        finally:
            self.active_connections -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def serve(self) -> None:
        print(
            f"[vordr] starting controller={self.controller_id} "
            f"listen={self.listen_host}:{self.port} backlog={self.listen_backlog} "
            f"nofile={self.nofile_soft_limit}/{self.nofile_hard_limit} "
            f"refresh_interval={self.refresh_interval_s}s "
            f"evidence_mode={self.evidence_mode} "
            f"response_auth={self.proof_signer.mode} "
            f"key_origin={self.proof_signer.key_origin} "
            f"key_id={self.proof_signer.key_id or 'session-hmac'}"
        )
        await self._refresh_once()
        self._refresh_task = asyncio.create_task(self._refresh_loop())
        self._server = await asyncio.start_server(
            self._handle_connection,
            self.listen_host,
            self.port,
            ssl=self.ssl_context,
            reuse_address=True,
            backlog=self.listen_backlog,
            limit=STREAM_LIMIT_BYTES,
        )
        sockets = self._server.sockets or []
        if sockets:
            addr = sockets[0].getsockname()
            print(f"[vordr] listening on {addr[0]}:{addr[1]}")
        async with self._server:
            await self._server.serve_forever()

    async def shutdown(self) -> None:
        self._stopping.set()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        if self._refresh_task is not None:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass


def build_ssl_context(cert_file: str | None, key_file: str | None) -> ssl.SSLContext | None:
    if not cert_file or not key_file:
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def main() -> None:
    parser = argparse.ArgumentParser(description="Single-WEN Vordr benchmark service")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument(
        "--listen-backlog",
        type=int,
        default=4096,
        help="Pending TCP connection queue requested from the kernel (default: 4096)",
    )
    parser.add_argument(
        "--min-nofile",
        type=int,
        default=65536,
        help="Minimum soft RLIMIT_NOFILE required by the WEN (default: 65536)",
    )
    parser.add_argument("--controller-id", default="wen-1")
    parser.add_argument(
        "--evidence-mode",
        choices=["light", "ima-audit", "full-audit", "full"],
        default="light",
        help=(
            "light=delegated summary, ima-audit=IMA/vTPM/command evidence without "
            "the raw TDX quote, full-audit=all evidence including the raw TDX quote; "
            "full is the legacy full-audit schema"
        ),
    )
    parser.add_argument(
        "--refresh-backend",
        choices=["synthetic", "sgx-verifier"],
        default="synthetic",
        help="Background refresh backend (default: synthetic)",
    )
    parser.add_argument("--refresh-interval-s", type=float, default=30.0)
    parser.add_argument(
        "--synthetic-refresh-ms",
        type=float,
        default=42.0,
        help="Synthetic refresh latency in ms (default: 42)",
    )
    parser.add_argument(
        "--synthetic-ima-entries",
        type=int,
        default=128,
        help="Synthetic IMA entries to embed in full-evidence dry runs",
    )
    parser.add_argument("--tdx-host", help="TDX attestation server host for sgx-verifier mode")
    parser.add_argument("--tdx-port", type=int, default=8443)
    parser.add_argument("--tdx-method", default="dcap")
    parser.add_argument("--tdx-ca-cert", default=None)
    parser.add_argument("--no-verify-tdx", action="store_true")
    parser.add_argument(
        "--command-log-file",
        default=None,
        help="Path to a JSONL/JSON command log snapshot to bundle with full evidence",
    )
    parser.add_argument("--proof-secret", default="vordr-benchmark-secret")
    parser.add_argument(
        "--response-auth",
        choices=["hmac-sha256", "ed25519"],
        default="ed25519",
        help="Authenticate each delegated result with a session HMAC or Ed25519 signature",
    )
    parser.add_argument(
        "--require-sgx-signing-key",
        action="store_true",
        help="Fail unless Ed25519 is derived from Gramine's MRSIGNER sealing key",
    )
    parser.add_argument(
        "--cvm-update-in-progress",
        action="store_true",
        help="Expose that the WEN is currently applying an installation/update on the CVM",
    )
    parser.add_argument("--tls-cert", default=None)
    parser.add_argument("--tls-key", default=None)
    args = parser.parse_args()

    if args.listen_backlog <= 0:
        parser.error("--listen-backlog must be positive")
    if args.min_nofile <= 0:
        parser.error("--min-nofile must be positive")
    nofile_soft, nofile_hard = ensure_nofile_soft_limit(args.min_nofile)

    if is_audit_evidence_mode(args.evidence_mode) and not args.command_log_file:
        parser.error("--command-log-file is required for audit evidence modes")

    command_log_provider: FileCommandLogProvider | NullCommandLogProvider
    if args.command_log_file:
        command_log_provider = FileCommandLogProvider(Path(args.command_log_file))
    else:
        command_log_provider = NullCommandLogProvider()

    if args.refresh_backend == "sgx-verifier":
        if not args.tdx_host:
            parser.error("--tdx-host is required for --refresh-backend sgx-verifier")
        backend = SGXVerifierRefreshBackend(
            tdx_host=args.tdx_host,
            tdx_port=args.tdx_port,
            method=args.tdx_method,
            verify_cert=not args.no_verify_tdx,
            ca_cert=args.tdx_ca_cert,
            evidence_mode=args.evidence_mode,
            command_log_provider=command_log_provider,
        )
    else:
        backend = SyntheticRefreshBackend(
            args.synthetic_refresh_ms,
            method=args.tdx_method,
            evidence_mode=args.evidence_mode,
            synthetic_ima_entries=args.synthetic_ima_entries,
            command_log_provider=command_log_provider,
        )

    ssl_context = build_ssl_context(args.tls_cert, args.tls_key)
    server = VordrServer(
        listen_host=args.listen_host,
        port=args.port,
        listen_backlog=args.listen_backlog,
        nofile_soft_limit=nofile_soft,
        nofile_hard_limit=nofile_hard,
        controller_id=args.controller_id,
        evidence_mode=args.evidence_mode,
        refresh_interval_s=args.refresh_interval_s,
        backend=backend,
        proof_secret=args.proof_secret,
        response_auth=args.response_auth,
        require_sgx_signing_key=args.require_sgx_signing_key,
        ssl_context=ssl_context,
        cvm_update_in_progress=args.cvm_update_in_progress,
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(server.serve())
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(server.shutdown())
        loop.close()


if __name__ == "__main__":
    main()
