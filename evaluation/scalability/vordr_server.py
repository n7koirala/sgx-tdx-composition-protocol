#!/usr/bin/env python3
"""High-throughput single-WEN service for the Vordr scalability evaluation."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from scale_common import compute_proof_mac, generate_nonce, recv_json, send_json


REPO_ROOT = Path(__file__).resolve().parents[2]
SGX_TDX_ROOT = REPO_ROOT / "research" / "sgx-tdx-attestation"
STREAM_LIMIT_BYTES = 16 * 1024 * 1024


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
    raw_quote: str = ""
    raw_quote_sha256: str = ""
    raw_quote_size: int = 0
    ima_log: str = ""
    ima_log_sha256: str = ""
    ima_log_size: int = 0
    ima_entry_count: int = 0
    pcr10: str = ""
    pcr10_sha256: str = ""
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
        return sha256_hex(self.text.encode("utf-8")) if self.text else ""


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
        if self.evidence_mode == "full":
            quote_bytes = (quote_material * 128)[:4096]
            ima_lines = [
                f"10 {i:040x} ima-ng sha256:{hashlib.sha256(f'synthetic-{refresh_count}-{i}'.encode('utf-8')).hexdigest()} "
                f"/usr/local/bin/synth-{i:04d}"
                for i in range(self.synthetic_ima_entries)
            ]
            ima_log_text = "\n".join(ima_lines) + "\n"
            command_log = self.command_log_provider.snapshot()
            state.raw_quote = base64.b64encode(quote_bytes).decode("ascii")
            state.raw_quote_sha256 = sha256_hex(quote_bytes)
            state.raw_quote_size = len(quote_bytes)
            state.ima_log = base64.b64encode(ima_log_text.encode("utf-8")).decode("ascii")
            state.ima_log_sha256 = sha256_hex(ima_log_text.encode("utf-8"))
            state.ima_log_size = len(ima_log_text.encode("utf-8"))
            state.ima_entry_count = len(ima_lines)
            state.pcr10 = hashlib.sha256(ima_log_text.encode("utf-8")).hexdigest()
            state.pcr10_sha256 = sha256_hex(state.pcr10.encode("utf-8"))
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
    ) -> None:
        sys.path.insert(0, str(SGX_TDX_ROOT / "sgx-verifier"))
        from sgx_tdx_verifier import SGXTDXVerifier  # type: ignore

        self.SGXTDXVerifier = SGXTDXVerifier
        self.tdx_host = tdx_host
        self.tdx_port = tdx_port
        self.method = method
        self.verify_cert = verify_cert
        self.ca_cert = ca_cert

    def refresh(self, refresh_count: int) -> CachedTDXState:
        verifier = self.SGXTDXVerifier(
            tdx_host=self.tdx_host,
            tdx_port=self.tdx_port,
            method=self.method,
            verify_cert=self.verify_cert,
            ca_cert=self.ca_cert,
            verbose=False,
        )
        start = time.perf_counter()
        result = verifier.attest_tdx()
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        quote_material = (
            f"{result.mrtd}:{result.verdict}:{result.verification_time_ms}:{refresh_count}"
        ).encode("utf-8")
        return CachedTDXState(
            verified=result.verified,
            verdict=result.verdict or ("TRUSTED" if result.verified else "ERROR"),
            attestation_method=result.attestation_method or self.method,
            mrtd=result.mrtd,
            quote_hash=hashlib.sha256(quote_material).hexdigest(),
            tcb_status=result.tcb_status,
            is_debuggable=result.is_debuggable,
            ima_verified=result.ima_verified,
            runtime_verdict=result.runtime_verdict,
            verification_time=time.time(),
            refresh_count=refresh_count,
            last_refresh_ms=elapsed_ms,
            ima_entry_count=result.ima_entry_count,
            warnings=list(result.warnings),
            error=result.error,
        )


class FullEvidenceTDXRefreshBackend:
    """Refresh backend that fetches and verifies the full TDX evidence bundle."""

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
        controller_id: str,
        evidence_mode: str,
        refresh_interval_s: float,
        backend: Any,
        proof_secret: str,
        ssl_context: ssl.SSLContext | None,
    ) -> None:
        self.listen_host = listen_host
        self.port = port
        self.controller_id = controller_id
        self.evidence_mode = evidence_mode
        self.refresh_interval_s = refresh_interval_s
        self.backend = backend
        self.proof_secret = proof_secret
        self.ssl_context = ssl_context
        self.state = CachedTDXState()
        self._state_lock = asyncio.Lock()
        self._server: asyncio.base_events.Server | None = None
        self._refresh_task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()
        self.started_at = time.time()
        self.stats = {
            "requests": 0,
            "served": 0,
            "errors": 0,
        }

    async def _refresh_once(self) -> None:
        refresh_number = self.state.refresh_count + 1
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
                error=str(exc),
            )

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
            return CachedTDXState(**asdict(self.state))

    async def _handle_verify(self, request: dict[str, Any]) -> dict[str, Any]:
        self.stats["requests"] += 1
        start = time.perf_counter()
        nonce = request.get("nonce", "")
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
            "tdx_verdict": snapshot.verdict,
            "tdx_mrtd": snapshot.mrtd,
            "tdx_quote_hash": snapshot.quote_hash,
            "runtime_verdict": snapshot.runtime_verdict,
            "tdx_verification_time": snapshot.verification_time,
            "refresh_count": snapshot.refresh_count,
            "raw_quote_sha256": snapshot.raw_quote_sha256,
            "ima_log_sha256": snapshot.ima_log_sha256,
            "pcr10_sha256": snapshot.pcr10_sha256,
            "command_log_sha256": snapshot.command_log_sha256,
            "ima_entry_count": snapshot.ima_entry_count,
            "command_log_entries": snapshot.command_log_entries,
            "issued_at": now,
        }

        response = {
            "status": "success" if snapshot.verified else "error",
            "controller_id": self.controller_id,
            "evidence_mode": self.evidence_mode,
            "nonce_echo": nonce,
            "nonce_hash": nonce_hash,
            "proof_alg": "hmac-sha256",
            "proof_mac": compute_proof_mac(self.proof_secret, proof_fields),
            "issued_at": now,
            "tdx_verified": snapshot.verified,
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
            "server_processing_ms": (time.perf_counter() - start) * 1000.0,
        }
        if self.evidence_mode == "full":
            response.update(
                {
                    "raw_quote": snapshot.raw_quote,
                    "ima_log": snapshot.ima_log,
                    "pcr10": snapshot.pcr10,
                    "command_log": snapshot.command_log,
                }
            )
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
            "requests": self.stats["requests"],
            "served": self.stats["served"],
            "errors": self.stats["errors"],
            "refresh_count": snapshot.refresh_count,
            "last_refresh_ms": snapshot.last_refresh_ms,
            "tdx_verification_time": snapshot.verification_time,
            "staleness_ms": max(0.0, (now - snapshot.verification_time) * 1000.0) if snapshot.verification_time else 0.0,
            "tdx_verdict": snapshot.verdict,
            "tdx_quote_hash": snapshot.quote_hash,
            "tdx_runtime_verdict": snapshot.runtime_verdict,
            "raw_quote_size": snapshot.raw_quote_size,
            "ima_log_size": snapshot.ima_log_size,
            "ima_entry_count": snapshot.ima_entry_count,
            "command_log_size": snapshot.command_log_size,
            "command_log_entries": snapshot.command_log_entries,
            "uptime_s": now - self.started_at,
        }

    async def _handle_health(self) -> dict[str, Any]:
        snapshot = await self._snapshot_state()
        return {
            "status": "success",
            "ready": snapshot.refresh_count > 0,
            "verified": snapshot.verified,
            "refresh_count": snapshot.refresh_count,
            "verdict": snapshot.verdict,
        }

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
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
                else:
                    self.stats["errors"] += 1
                    response = {"status": "error", "error": f"unknown action: {action}"}
                await send_json(writer, response)
        except ConnectionError:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def serve(self) -> None:
        print(
            f"[vordr] starting controller={self.controller_id} "
            f"listen={self.listen_host}:{self.port} refresh_interval={self.refresh_interval_s}s "
            f"evidence_mode={self.evidence_mode}"
        )
        await self._refresh_once()
        self._refresh_task = asyncio.create_task(self._refresh_loop())
        self._server = await asyncio.start_server(
            self._handle_connection,
            self.listen_host,
            self.port,
            ssl=self.ssl_context,
            reuse_address=True,
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
    parser.add_argument("--controller-id", default="wen-1")
    parser.add_argument(
        "--evidence-mode",
        choices=["light", "full"],
        default="light",
        help="Whether to return only cached verdict metadata or the full evidence bundle",
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
    parser.add_argument("--tls-cert", default=None)
    parser.add_argument("--tls-key", default=None)
    args = parser.parse_args()

    if args.evidence_mode == "full" and not args.command_log_file:
        parser.error("--command-log-file is required for --evidence-mode full")

    command_log_provider: FileCommandLogProvider | NullCommandLogProvider
    if args.command_log_file:
        command_log_provider = FileCommandLogProvider(Path(args.command_log_file))
    else:
        command_log_provider = NullCommandLogProvider()

    if args.refresh_backend == "sgx-verifier":
        if not args.tdx_host:
            parser.error("--tdx-host is required for --refresh-backend sgx-verifier")
        if args.evidence_mode == "full":
            backend = FullEvidenceTDXRefreshBackend(
                tdx_host=args.tdx_host,
                tdx_port=args.tdx_port,
                method=args.tdx_method,
                verify_cert=not args.no_verify_tdx,
                ca_cert=args.tdx_ca_cert,
                command_log_provider=command_log_provider,
            )
        else:
            backend = SGXVerifierRefreshBackend(
                tdx_host=args.tdx_host,
                tdx_port=args.tdx_port,
                method=args.tdx_method,
                verify_cert=not args.no_verify_tdx,
                ca_cert=args.tdx_ca_cert,
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
        controller_id=args.controller_id,
        evidence_mode=args.evidence_mode,
        refresh_interval_s=args.refresh_interval_s,
        backend=backend,
        proof_secret=args.proof_secret,
        ssl_context=ssl_context,
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
