#!/usr/bin/env python3
"""High-throughput single-WEN service for the Vordr scalability evaluation."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import ssl
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from common import compute_proof_mac, recv_json, send_json


REPO_ROOT = Path(__file__).resolve().parents[2]
SGX_TDX_ROOT = REPO_ROOT / "research" / "sgx-tdx-attestation"


@dataclass
class CachedTDXState:
    verified: bool = False
    verdict: str = "PENDING"
    attestation_method: str = "dcap"
    mrtd: str = ""
    quote_hash: str = ""
    tcb_status: str = ""
    is_debuggable: bool = False
    verification_time: float = 0.0
    refresh_count: int = 0
    last_refresh_ms: float = 0.0
    warnings: list[str] = field(default_factory=list)
    error: str = ""


class SyntheticRefreshBackend:
    """Refresh backend for harness bring-up and dry-run benchmarking."""

    def __init__(self, latency_ms: float, method: str = "dcap") -> None:
        self.latency_ms = latency_ms
        self.method = method

    def refresh(self, refresh_count: int) -> CachedTDXState:
        start = time.perf_counter()
        time.sleep(self.latency_ms / 1000.0)
        refresh_time = time.time()
        quote_material = f"synthetic:{refresh_count}:{refresh_time:.6f}".encode("utf-8")
        return CachedTDXState(
            verified=True,
            verdict="TRUSTED",
            attestation_method=self.method,
            mrtd=hashlib.sha256(b"synthetic-mrtd").hexdigest(),
            quote_hash=hashlib.sha256(quote_material).hexdigest(),
            tcb_status="UpToDate",
            is_debuggable=False,
            verification_time=refresh_time,
            refresh_count=refresh_count,
            last_refresh_ms=(time.perf_counter() - start) * 1000.0,
        )


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
            verification_time=time.time(),
            refresh_count=refresh_count,
            last_refresh_ms=elapsed_ms,
            warnings=list(result.warnings),
            error=result.error,
        )


class VordrServer:
    def __init__(
        self,
        listen_host: str,
        port: int,
        controller_id: str,
        refresh_interval_s: float,
        backend: Any,
        proof_secret: str,
        ssl_context: ssl.SSLContext | None,
    ) -> None:
        self.listen_host = listen_host
        self.port = port
        self.controller_id = controller_id
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
            "nonce_echo": nonce,
            "nonce_hash": nonce_hash,
            "tdx_verdict": snapshot.verdict,
            "tdx_mrtd": snapshot.mrtd,
            "tdx_quote_hash": snapshot.quote_hash,
            "tdx_verification_time": snapshot.verification_time,
            "refresh_count": snapshot.refresh_count,
            "issued_at": now,
        }

        response = {
            "status": "success" if snapshot.verified else "error",
            "controller_id": self.controller_id,
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
            "tdx_verification_time": snapshot.verification_time,
            "refresh_count": snapshot.refresh_count,
            "last_refresh_ms": snapshot.last_refresh_ms,
            "staleness_ms": staleness_ms,
            "warnings": snapshot.warnings,
            "error": snapshot.error,
            "server_processing_ms": (time.perf_counter() - start) * 1000.0,
        }
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
            "requests": self.stats["requests"],
            "served": self.stats["served"],
            "errors": self.stats["errors"],
            "refresh_count": snapshot.refresh_count,
            "last_refresh_ms": snapshot.last_refresh_ms,
            "tdx_verification_time": snapshot.verification_time,
            "staleness_ms": max(0.0, (now - snapshot.verification_time) * 1000.0) if snapshot.verification_time else 0.0,
            "tdx_verdict": snapshot.verdict,
            "tdx_quote_hash": snapshot.quote_hash,
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
            await writer.wait_closed()

    async def serve(self) -> None:
        print(
            f"[vordr] starting controller={self.controller_id} "
            f"listen={self.listen_host}:{self.port} refresh_interval={self.refresh_interval_s}s"
        )
        await self._refresh_once()
        self._refresh_task = asyncio.create_task(self._refresh_loop())
        self._server = await asyncio.start_server(
            self._handle_connection,
            self.listen_host,
            self.port,
            ssl=self.ssl_context,
            reuse_address=True,
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
    parser.add_argument("--tdx-host", help="TDX attestation server host for sgx-verifier mode")
    parser.add_argument("--tdx-port", type=int, default=8443)
    parser.add_argument("--tdx-method", default="dcap")
    parser.add_argument("--tdx-ca-cert", default=None)
    parser.add_argument("--no-verify-tdx", action="store_true")
    parser.add_argument("--proof-secret", default="vordr-benchmark-secret")
    parser.add_argument("--tls-cert", default=None)
    parser.add_argument("--tls-key", default=None)
    args = parser.parse_args()

    if args.refresh_backend == "sgx-verifier":
        if not args.tdx_host:
            parser.error("--tdx-host is required for --refresh-backend sgx-verifier")
        backend: Any = SGXVerifierRefreshBackend(
            tdx_host=args.tdx_host,
            tdx_port=args.tdx_port,
            method=args.tdx_method,
            verify_cert=not args.no_verify_tdx,
            ca_cert=args.tdx_ca_cert,
        )
    else:
        backend = SyntheticRefreshBackend(args.synthetic_refresh_ms, method=args.tdx_method)

    ssl_context = build_ssl_context(args.tls_cert, args.tls_key)
    server = VordrServer(
        listen_host=args.listen_host,
        port=args.port,
        controller_id=args.controller_id,
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
