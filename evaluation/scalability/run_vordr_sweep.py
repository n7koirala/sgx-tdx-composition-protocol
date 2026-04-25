#!/usr/bin/env python3
"""Benchmark a single WEN serving many end-user attestation requests."""

from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from common import (
    compute_proof_mac,
    ensure_dir,
    generate_nonce,
    recv_json,
    send_json,
    summarize_samples,
    write_csv,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_SCRIPT = REPO_ROOT / "evaluation" / "scalability" / "vordr_server.py"


def response_proof_fields(response: dict[str, Any]) -> dict[str, Any]:
    return {
        "controller_id": response.get("controller_id", ""),
        "nonce_echo": response.get("nonce_echo", ""),
        "nonce_hash": response.get("nonce_hash", ""),
        "tdx_verdict": response.get("tdx_verdict", ""),
        "tdx_mrtd": response.get("tdx_mrtd", ""),
        "tdx_quote_hash": response.get("tdx_quote_hash", ""),
        "tdx_verification_time": response.get("tdx_verification_time", 0.0),
        "refresh_count": response.get("refresh_count", 0),
        "issued_at": response.get("issued_at", 0.0),
    }


def build_client_ssl_context(ca_cert: str | None, verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if verify and ca_cert:
        ctx.load_verify_locations(ca_cert)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


async def query_server(host: str, port: int, ssl_ctx: ssl.SSLContext | None, action: str) -> dict[str, Any]:
    reader, writer = await asyncio.open_connection(host, port, ssl=ssl_ctx)
    try:
        await send_json(writer, {"action": action})
        return await recv_json(reader)
    finally:
        writer.close()
        await writer.wait_closed()


async def wait_for_server(host: str, port: int, ssl_ctx: ssl.SSLContext | None, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_error = "timeout"
    while time.monotonic() < deadline:
        try:
            response = await query_server(host, port, ssl_ctx, "health")
            if response.get("status") == "success" and response.get("ready"):
                return
            last_error = json.dumps(response)
        except Exception as exc:  # pragma: no cover - best effort
            last_error = str(exc)
        await asyncio.sleep(0.2)
    raise TimeoutError(f"server did not become ready within {timeout_s}s: {last_error}")


async def one_user(
    user_id: int,
    host: str,
    port: int,
    ssl_ctx: ssl.SSLContext | None,
    deadline: float,
    proof_secret: str,
    verify_proof: bool,
    requests_per_user: int,
) -> dict[str, Any]:
    latencies: list[float] = []
    staleness: list[float] = []
    successful = 0
    failed = 0
    error_samples: list[str] = []
    sent = 0
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None

    try:
        reader, writer = await asyncio.open_connection(host, port, ssl=ssl_ctx)
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
                if verify_proof:
                    expected_mac = compute_proof_mac(proof_secret, response_proof_fields(response))
                    if response.get("proof_mac") != expected_mac:
                        raise ValueError("proof MAC mismatch")
                successful += 1
                latencies.append(latency_ms)
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
            await writer.wait_closed()

    return {
        "user_id": user_id,
        "sent": sent,
        "successful": successful,
        "failed": failed,
        "latencies_ms": latencies,
        "staleness_ms": staleness,
        "errors": error_samples[:5],
    }


def summarize_run(
    *,
    users: int,
    duration_s: float,
    proof_secret: str,
    verify_proof: bool,
    transport: str,
    user_results: list[dict[str, Any]],
    start_stats: dict[str, Any],
    end_stats: dict[str, Any],
) -> dict[str, Any]:
    latencies = [item for result in user_results for item in result["latencies_ms"]]
    staleness = [item for result in user_results for item in result["staleness_ms"]]
    successful = sum(result["successful"] for result in user_results)
    failed = sum(result["failed"] for result in user_results)
    sent = sum(result["sent"] for result in user_results)
    refresh_total = int(end_stats.get("refresh_count", 0))
    refresh_delta = max(0, refresh_total - int(start_stats.get("refresh_count", 0)))
    latency_stats = summarize_samples(latencies)
    staleness_stats = summarize_samples(staleness)

    return {
        "model": "vordr-single-wen",
        "users": users,
        "duration_s": duration_s,
        "transport": transport,
        "verify_proof": verify_proof,
        "sent": sent,
        "successful": successful,
        "failed": failed,
        "error_rate_pct": (failed / sent * 100.0) if sent else 0.0,
        "throughput_rps": (successful / duration_s) if duration_s > 0 else 0.0,
        "mean_ms": latency_stats["mean"],
        "median_ms": latency_stats["median"],
        "p95_ms": latency_stats["p95"],
        "p99_ms": latency_stats["p99"],
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
    }


def build_server_cmd(args: argparse.Namespace, port: int) -> list[str]:
    cmd = [
        sys.executable,
        str(SERVER_SCRIPT),
        "--listen-host",
        args.host,
        "--port",
        str(port),
        "--controller-id",
        args.controller_id,
        "--refresh-backend",
        args.refresh_backend,
        "--refresh-interval-s",
        str(args.refresh_interval_s),
        "--synthetic-refresh-ms",
        str(args.synthetic_refresh_ms),
        "--tdx-method",
        args.tdx_method,
        "--proof-secret",
        args.proof_secret,
    ]
    if args.refresh_backend == "sgx-verifier":
        cmd.extend(["--tdx-host", args.tdx_host, "--tdx-port", str(args.tdx_port)])
        if args.tdx_ca_cert:
            cmd.extend(["--tdx-ca-cert", args.tdx_ca_cert])
        if args.no_verify_tdx:
            cmd.append("--no-verify-tdx")
    if args.transport == "tls":
        cmd.extend(["--tls-cert", args.tls_cert, "--tls-key", args.tls_key])
    return cmd


async def run_one_point(args: argparse.Namespace, users: int, out_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    transport = args.transport
    ssl_ctx = None
    if transport == "tls":
        ssl_ctx = build_client_ssl_context(args.client_ca_cert, verify=not args.no_verify_server_cert)

    server_proc: subprocess.Popen[str] | None = None
    server_log = None
    if not args.no_spawn_server:
        server_log_path = out_dir / f"server-users{users}.log"
        server_log = server_log_path.open("w", encoding="utf-8")
        server_cmd = build_server_cmd(args, args.port)
        server_proc = subprocess.Popen(
            server_cmd,
            stdout=server_log,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(REPO_ROOT),
        )
        await wait_for_server(args.host, args.port, ssl_ctx, timeout_s=args.server_ready_timeout_s)
        if args.warmup_s > 0:
            await asyncio.sleep(args.warmup_s)

    try:
        start_stats = await query_server(args.host, args.port, ssl_ctx, "stats")
        deadline = time.monotonic() + args.duration_s
        user_results = await asyncio.gather(
            *[
                one_user(
                    user_id=i,
                    host=args.host,
                    port=args.port,
                    ssl_ctx=ssl_ctx,
                    deadline=deadline,
                    proof_secret=args.proof_secret,
                    verify_proof=not args.no_verify_proof,
                    requests_per_user=args.requests_per_user,
                )
                for i in range(users)
            ]
        )
        end_stats = await query_server(args.host, args.port, ssl_ctx, "stats")
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
        duration_s=args.duration_s,
        proof_secret=args.proof_secret,
        verify_proof=not args.no_verify_proof,
        transport=transport,
        user_results=user_results,
        start_stats=start_stats,
        end_stats=end_stats,
    )
    raw = {
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
    parser.add_argument("--client-ca-cert", default=None)
    parser.add_argument("--no-verify-server-cert", action="store_true")
    parser.add_argument("--proof-secret", default="vordr-benchmark-secret")
    parser.add_argument("--no-verify-proof", action="store_true")
    parser.add_argument("--no-spawn-server", action="store_true")
    parser.add_argument("--server-ready-timeout-s", type=float, default=20.0)
    parser.add_argument("--warmup-s", type=float, default=0.5)
    parser.add_argument("--refresh-backend", choices=["synthetic", "sgx-verifier"], default="synthetic")
    parser.add_argument("--refresh-interval-s", type=float, default=30.0)
    parser.add_argument("--synthetic-refresh-ms", type=float, default=42.0)
    parser.add_argument("--tdx-host", default="")
    parser.add_argument("--tdx-port", type=int, default=8443)
    parser.add_argument("--tdx-method", default="dcap")
    parser.add_argument("--tdx-ca-cert", default=None)
    parser.add_argument("--no-verify-tdx", action="store_true")
    parser.add_argument(
        "--tls-cert",
        default=str(REPO_ROOT / "research" / "sgx-tdx-attestation" / "certs" / "server.crt"),
    )
    parser.add_argument(
        "--tls-key",
        default=str(REPO_ROOT / "research" / "sgx-tdx-attestation" / "certs" / "server.key"),
    )
    parser.add_argument(
        "--out-dir",
        default=str(REPO_ROOT / "evaluation" / "results" / "scalability" / time.strftime("vordr-single-wen-%Y%m%d-%H%M%S")),
    )
    args = parser.parse_args()

    users_list = [int(item.strip()) for item in args.users.split(",") if item.strip()]
    if not users_list:
        parser.error("--users must contain at least one value")
    if args.refresh_backend == "sgx-verifier" and not args.tdx_host:
        parser.error("--tdx-host is required with --refresh-backend sgx-verifier")

    out_dir = ensure_dir(Path(args.out_dir))
    summaries: list[dict[str, Any]] = []
    raws: list[dict[str, Any]] = []

    print("=" * 72)
    print("Single-WEN Vordr Scalability Sweep")
    print("=" * 72)
    print(f"Users:       {users_list}")
    print(f"Duration:    {args.duration_s}s")
    print(f"Transport:   {args.transport}")
    print(f"Backend:     {args.refresh_backend}")
    print(f"Out dir:     {out_dir}")
    print("=" * 72)

    for users in users_list:
        print(f"\n[vordr] users={users}")
        summary, raw = asyncio.run(run_one_point(args, users, out_dir))
        summaries.append(summary)
        raws.append(raw)
        print(
            "  "
            f"throughput={summary['throughput_rps']:.2f} rps "
            f"mean={summary['mean_ms']:.2f}ms "
            f"p99={summary['p99_ms']:.2f}ms "
            f"amp={summary['amplification_total_refreshes']:.1f}x"
        )

    write_csv(out_dir / "vordr_single_wen_summary.csv", summaries)
    (out_dir / "vordr_single_wen_raw.json").write_text(
        json.dumps(raws, indent=2),
        encoding="utf-8",
    )

    print(f"\nSaved summary to: {out_dir / 'vordr_single_wen_summary.csv'}")
    print(f"Saved raw data to: {out_dir / 'vordr_single_wen_raw.json'}")


if __name__ == "__main__":
    main()

