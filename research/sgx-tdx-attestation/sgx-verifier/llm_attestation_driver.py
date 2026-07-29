#!/usr/bin/env python3
"""Periodic Protocol 1.2 verifier for PETS LLM experiments."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import DEFAULT_PORT, METHOD_DCAP, PROTOCOL_VERSION
from sgx_tdx_verifier import SGXTDXVerifier


SCHEMA_VERSION = "pets2027-llm-attestation-v1"

FIELDS = [
    "schema_version", "campaign_id", "run_id", "phase", "round_idx",
    "scheduled_epoch", "t_start_epoch", "t_end_epoch", "schedule_lag_ms",
    "wall_ms", "epoch_sec", "effective_evidence_age_ms",
    "skipped_schedule_slots", "protocol_version", "environment", "overall_ok",
    "boot_verdict", "runtime_verdict", "error", "verification_mode",
    "ima_total_count", "ima_wire_entries", "ima_wire_start",
    "ima_binary_bytes", "ima_ascii_bytes", "ima_response_json_bytes",
    "ima_agent_delta_entries", "ima_anchored_count",
    "pcr10_signed_prefix_entries", "post_quote_drift", "fd_generation",
    "fd_fast_path", "checkpoint_generation", "checkpoint_sealed",
    "vtpm_quote_attempts", "t_nonce_ms", "t_tls_connect_ms",
    "t_request_send_ms", "t_response_receive_ms", "t_server_ima_extract_ms",
    "t_server_rtmr_extend_ms", "t_server_vtpm_quote_ms",
    "t_server_tdx_quote_ms", "t_wen_dcap_verify_ms",
    "t_wen_runtime_verify_ms", "t_wen_checkpoint_commit_ms",
    "runtime_checks_json", "warnings_json",
]


def _float(mapping: dict[str, Any], key: str) -> float:
    try:
        return float(mapping.get(key, 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _int(mapping: dict[str, Any], key: str) -> int:
    try:
        return int(mapping.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def _is_sgx() -> bool:
    return os.path.exists("/dev/attestation")


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def _wait_for_start_signal(path: Path, timeout_sec: float) -> float:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        try:
            with path.open("r", encoding="utf-8") as handle:
                value = json.load(handle)
            start = float(value["start_at_epoch"])
            if start <= 0:
                raise ValueError("start_at_epoch must be positive")
            return start
        except FileNotFoundError:
            time.sleep(0.1)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"invalid start signal {path}: {exc}") from exc
    raise TimeoutError(f"timed out waiting for start signal {path}")


def _row_from_result(
    result,
    *,
    args,
    phase: str,
    round_idx: int,
    scheduled_epoch: float,
    started_epoch: float,
    ended_epoch: float,
    wall_ms: float,
    skipped_slots: int,
) -> dict[str, Any]:
    details = result.runtime_details or {}
    timing = details.get("timing", {})
    stream = details.get("stream", {})
    agent_stream = details.get("agent_stream", {})
    agent_timing = details.get("agent_timing", {})
    checkpoint = details.get("checkpoint", {})
    snapshot = details.get("snapshot", {})
    checks = result.runtime_checks or {}

    overall_ok = bool(result.verified and result.ima_verified)
    total_ms = _float(timing, "total_ms") or float(wall_ms)
    effective_age = (
        0.0 if phase == "baseline" else args.epoch_sec * 1000.0 + total_ms
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "campaign_id": args.campaign_id,
        "run_id": args.run_id,
        "phase": phase,
        "round_idx": round_idx,
        "scheduled_epoch": round(scheduled_epoch, 6),
        "t_start_epoch": round(started_epoch, 6),
        "t_end_epoch": round(ended_epoch, 6),
        "schedule_lag_ms": round(
            max(0.0, (started_epoch - scheduled_epoch) * 1000.0), 6
        ),
        "wall_ms": round(wall_ms, 6),
        "epoch_sec": args.epoch_sec,
        "effective_evidence_age_ms": round(effective_age, 6),
        "skipped_schedule_slots": skipped_slots,
        "protocol_version": PROTOCOL_VERSION,
        "environment": "sgx" if _is_sgx() else "python",
        "overall_ok": overall_ok,
        "boot_verdict": result.verdict,
        "runtime_verdict": result.runtime_verdict,
        "error": result.error,
        "verification_mode": details.get("verification_mode", ""),
        "ima_total_count": _int(details, "ima_entries"),
        "ima_wire_entries": _int(details, "wire_ima_entries"),
        "ima_wire_start": _int(stream, "requested_start_index"),
        "ima_binary_bytes": _int(stream, "wire_binary_bytes"),
        "ima_ascii_bytes": _int(stream, "wire_ascii_bytes"),
        "ima_response_json_bytes": _int(timing, "response_json_bytes"),
        "ima_agent_delta_entries": _int(agent_stream, "delta_entries"),
        "ima_anchored_count": _int(details, "anchored_count"),
        "pcr10_signed_prefix_entries": _int(details, "pcr10_prefix_entries"),
        "post_quote_drift": _int(snapshot, "post_quote_drift"),
        "fd_generation": _int(agent_stream, "fd_generation"),
        "fd_fast_path": bool(agent_stream.get("fast_path", False)),
        "checkpoint_generation": _int(checkpoint, "generation"),
        "checkpoint_sealed": bool(checkpoint.get("sealed", False)),
        "vtpm_quote_attempts": _int(details, "vtpm_quote_attempts"),
        "t_nonce_ms": _float(timing, "nonce_ms"),
        "t_tls_connect_ms": _float(timing, "tls_connect_ms"),
        "t_request_send_ms": _float(timing, "request_send_ms"),
        "t_response_receive_ms": _float(timing, "response_receive_ms"),
        "t_server_ima_extract_ms": _float(agent_timing, "ima_extraction_ms"),
        "t_server_rtmr_extend_ms": _float(agent_timing, "rtmr_extend_ms"),
        "t_server_vtpm_quote_ms": _float(agent_timing, "vtpm_quote_ms"),
        "t_server_tdx_quote_ms": _float(agent_timing, "tdx_quote_ms"),
        "t_wen_dcap_verify_ms": _float(timing, "dcap_verify_ms"),
        "t_wen_runtime_verify_ms": _float(timing, "runtime_verify_ms"),
        "t_wen_checkpoint_commit_ms": _float(timing, "checkpoint_commit_ms"),
        "runtime_checks_json": json.dumps(checks, sort_keys=True),
        "warnings_json": json.dumps(result.warnings, sort_keys=True),
    }


class ResultWriter:
    def __init__(self, output_dir: Path):
        output_dir.mkdir(parents=True, exist_ok=True)
        self.csv_path = output_dir / "attestations.csv"
        self.jsonl_path = output_dir / "attestations.jsonl"
        self.csv_handle = self.csv_path.open("w", newline="", encoding="utf-8")
        self.jsonl_handle = self.jsonl_path.open("w", encoding="utf-8")
        self.csv_writer = csv.DictWriter(self.csv_handle, fieldnames=FIELDS)
        self.csv_writer.writeheader()
        self.csv_handle.flush()

    def write(self, row: dict[str, Any], result) -> None:
        self.csv_writer.writerow(row)
        self.csv_handle.flush()
        record = {
            "schema_version": SCHEMA_VERSION,
            "campaign_id": row["campaign_id"],
            "run_id": row["run_id"],
            "phase": row["phase"],
            "round_idx": row["round_idx"],
            "schedule": {
                "scheduled_epoch": row["scheduled_epoch"],
                "started_epoch": row["t_start_epoch"],
                "ended_epoch": row["t_end_epoch"],
                "schedule_lag_ms": row["schedule_lag_ms"],
                "skipped_schedule_slots": row["skipped_schedule_slots"],
            },
            "result": result.to_dict(),
        }
        self.jsonl_handle.write(json.dumps(record, sort_keys=True) + "\n")
        self.jsonl_handle.flush()

    def close(self) -> None:
        self.csv_handle.close()
        self.jsonl_handle.close()


def _attest_once(
    verifier: SGXTDXVerifier,
    writer: ResultWriter,
    args,
    *,
    phase: str,
    round_idx: int,
    scheduled_epoch: float,
    skipped_slots: int = 0,
) -> tuple[bool, dict[str, Any]]:
    started_epoch = time.time()
    started_monotonic = time.perf_counter()
    result = verifier.attest_tdx()
    wall_ms = (time.perf_counter() - started_monotonic) * 1000.0
    ended_epoch = time.time()
    row = _row_from_result(
        result,
        args=args,
        phase=phase,
        round_idx=round_idx,
        scheduled_epoch=scheduled_epoch,
        started_epoch=started_epoch,
        ended_epoch=ended_epoch,
        wall_ms=wall_ms,
        skipped_slots=skipped_slots,
    )
    writer.write(row, result)
    print(
        f"[attest] phase={phase} round={round_idx} ok={row['overall_ok']} "
        f"mode={row['verification_mode'] or '<none>'} "
        f"total={row['ima_total_count']:,} wire={row['ima_wire_entries']:,} "
        f"wall={row['wall_ms']:.1f}ms checkpoint={row['checkpoint_generation']}",
        flush=True,
    )
    if not row["overall_ok"]:
        print(f"[attest] error={row['error']}", file=sys.stderr, flush=True)
    return bool(row["overall_ok"]), row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tdx-host", required=True)
    parser.add_argument("--tdx-port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--epoch-sec", type=float, required=True)
    parser.add_argument("--duration-sec", type=float, required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--start-at-epoch", type=float)
    parser.add_argument("--start-signal")
    parser.add_argument("--start-signal-timeout-sec", type=float, default=600.0)
    parser.add_argument("--ready-file")
    parser.add_argument("--baseline-before-measurement", action="store_true")
    parser.add_argument("--max-rounds", type=int)
    parser.add_argument("--ca-cert")
    parser.add_argument("--client-cert")
    parser.add_argument("--client-key")
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--expected-rtmr3-base", default="auto")
    parser.add_argument("--golden-file")
    parser.add_argument("--require-golden", action="store_true")
    parser.add_argument("--require-ak-cert", action="store_true")
    parser.add_argument("--checkpoint-file")
    parser.add_argument("--checkpoint-namespace")
    parser.add_argument("--no-sealed-checkpoint", action="store_true")
    parser.add_argument("--reset-checkpoint", action="store_true")
    parser.add_argument("--reset-cvm-stream", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.epoch_sec <= 0 or args.duration_sec <= 0:
        parser.error("--epoch-sec and --duration-sec must be positive")
    if (args.start_at_epoch is None) == (args.start_signal is None):
        parser.error("provide exactly one of --start-at-epoch or --start-signal")
    if args.max_rounds is not None and args.max_rounds < 1:
        parser.error("--max-rounds must be at least 1")

    output_dir = Path(args.output_dir)
    writer = ResultWriter(output_dir)
    namespace = args.checkpoint_namespace or (
        f"pets2027-llm|{args.campaign_id}|{args.run_id}"
    )
    verifier = SGXTDXVerifier(
        tdx_host=args.tdx_host,
        tdx_port=args.tdx_port,
        ca_cert=args.ca_cert,
        verify_cert=not args.no_verify,
        client_cert=args.client_cert,
        client_key=args.client_key,
        method=METHOD_DCAP,
        verbose=args.verbose,
        expected_rtmr3_base=args.expected_rtmr3_base,
        golden_file=args.golden_file,
        require_golden=args.require_golden,
        require_ak_cert=args.require_ak_cert,
        checkpoint_file=args.checkpoint_file,
        checkpoint_namespace=namespace,
        enable_sealed_checkpoint=not args.no_sealed_checkpoint,
        reset_checkpoint=args.reset_checkpoint,
        reset_cvm_stream=args.reset_cvm_stream,
    )

    attempted = 0
    successful = 0
    measured = 0
    skipped_total = 0
    first_measured_mode = ""
    exit_code = 0

    try:
        if args.baseline_before_measurement:
            ok, _ = _attest_once(
                verifier,
                writer,
                args,
                phase="baseline",
                round_idx=0,
                scheduled_epoch=time.time(),
            )
            attempted += 1
            successful += int(ok)
            if not ok:
                return 1

        if args.ready_file:
            _atomic_json(
                Path(args.ready_file),
                {
                    "schema_version": SCHEMA_VERSION,
                    "campaign_id": args.campaign_id,
                    "run_id": args.run_id,
                    "baseline_complete": args.baseline_before_measurement,
                    "ready_epoch": time.time(),
                    "environment": "sgx" if _is_sgx() else "python",
                },
            )

        if args.start_signal:
            start_epoch = _wait_for_start_signal(
                Path(args.start_signal), args.start_signal_timeout_sec
            )
        else:
            start_epoch = float(args.start_at_epoch)

        delay = start_epoch - time.time()
        if delay > 0:
            time.sleep(delay)

        deadline = start_epoch + args.duration_sec
        slot = 0
        round_idx = 1
        next_fire = start_epoch

        while next_fire < deadline:
            if args.max_rounds is not None and measured >= args.max_rounds:
                break
            now = time.time()
            if now < next_fire:
                time.sleep(next_fire - now)
            else:
                skipped = 0
                while next_fire + args.epoch_sec <= now:
                    next_fire += args.epoch_sec
                    slot += 1
                    skipped += 1
                skipped_total += skipped

            ok, row = _attest_once(
                verifier,
                writer,
                args,
                phase="measurement",
                round_idx=round_idx,
                scheduled_epoch=next_fire,
                skipped_slots=skipped_total,
            )
            attempted += 1
            successful += int(ok)
            measured += 1
            if not first_measured_mode:
                first_measured_mode = str(row["verification_mode"])
            if not ok:
                exit_code = 1
                if args.fail_fast:
                    break

            round_idx += 1
            slot += 1
            next_fire = start_epoch + slot * args.epoch_sec
    finally:
        writer.close()
        _atomic_json(
            output_dir / "attestation_summary.json",
            {
                "schema_version": SCHEMA_VERSION,
                "campaign_id": args.campaign_id,
                "run_id": args.run_id,
                "protocol_version": PROTOCOL_VERSION,
                "environment": "sgx" if _is_sgx() else "python",
                "epoch_sec": args.epoch_sec,
                "duration_sec": args.duration_sec,
                "attempted_rounds": attempted,
                "successful_rounds": successful,
                "measured_rounds": measured,
                "skipped_schedule_slots": skipped_total,
                "first_measured_verification_mode": first_measured_mode,
                "all_successful": attempted > 0 and attempted == successful,
            },
        )

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
