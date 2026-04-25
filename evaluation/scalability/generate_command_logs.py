#!/usr/bin/env python3
"""Generate realistic command-audit logs for the full-evidence scalability runs."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


COMMAND_TEMPLATES = [
    "apt-get update",
    "systemctl restart vordr-agent.service",
    "python3 /opt/asp/apply_policy.py --profile strict",
    "bash /opt/asp/install_patch.sh --package openssl",
    "journalctl -u vordr-agent.service --since -5m",
    "sha256sum /usr/local/bin/vordr-agent",
    "cp /etc/vordr/policy.json /var/lib/vordr/policy.json.bak",
    "python3 /opt/asp/push_model.py --model fraud-detect-v4",
    "bash /opt/asp/reload_conf.sh",
    "cat /etc/os-release",
]

STDOUT_SNIPPETS = [
    "completed successfully",
    "updated policy cache",
    "service restarted",
    "package already current",
    "delta applied",
    "measurement exported",
]

STDERR_SNIPPETS = [
    "",
    "",
    "",
    "warning: cache miss on first access",
    "note: restarting helper process",
]


def generate_log_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"log-{timestamp}-{secrets.token_hex(8)}"


def one_command_entry(
    *,
    index: int,
    base_time: float,
    asp_id: str,
    target_vm: str,
) -> dict[str, Any]:
    command = COMMAND_TEMPLATES[index % len(COMMAND_TEMPLATES)]
    command_timestamp = base_time + index * 0.25
    exec_time = random.uniform(8.0, 125.0)
    execution_timestamp = command_timestamp + random.uniform(0.005, 0.2)
    success = random.random() > 0.04
    exit_code = 0 if success else random.choice([1, 2, 126])
    stdout = f"{STDOUT_SNIPPETS[index % len(STDOUT_SNIPPETS)]} [{index}]"
    stderr = "" if success else random.choice(STDERR_SNIPPETS[3:]) or "command failed"

    return {
        "log_id": generate_log_id(),
        "asp_id": asp_id,
        "target_vm": target_vm,
        "command": command,
        "command_timestamp": command_timestamp,
        "execution_timestamp": execution_timestamp,
        "result": {
            "success": success,
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "execution_time_ms": exec_time,
            "timestamp": execution_timestamp,
        },
        "enclave_signature": hashlib.sha256(
            f"{asp_id}:{target_vm}:{command}:{execution_timestamp:.6f}".encode("utf-8")
        ).hexdigest(),
    }


def one_transition_entry(
    *,
    index: int,
    prev_hash: str,
    controller_id: str,
    asp_id: str,
    cvm_id: str,
    timestamp: float,
) -> dict[str, Any]:
    command = COMMAND_TEMPLATES[index % len(COMMAND_TEMPLATES)]
    payload = {
        "seq": index,
        "prev_hash": prev_hash,
        "cvm_id": cvm_id,
        "command": command,
        "command_hash": hashlib.sha256(command.encode("utf-8")).hexdigest(),
        "asp_id": asp_id,
        "asp_signature": hashlib.sha256(f"{asp_id}:{command}".encode("utf-8")).hexdigest(),
        "controller_id": controller_id,
        "timestamp": timestamp,
        "result_success": True,
        "result_exit_code": 0,
        "result_rtmr": hashlib.sha256(f"rtmr-{index}".encode("utf-8")).hexdigest(),
    }
    entry_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    payload["entry_hash"] = entry_hash
    return payload


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, separators=(",", ":")) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic command audit logs")
    parser.add_argument("--entries", type=int, default=2000, help="Number of audit log entries to generate")
    parser.add_argument("--asp-id", default="asp-demo")
    parser.add_argument("--target-vm", default="146.148.46.72")
    parser.add_argument("--controller-id", default="wen-1")
    parser.add_argument("--with-transition-log", action="store_true")
    parser.add_argument(
        "--out-dir",
        default=f"evaluation/results/scalability/command-log-{time.strftime('%Y%m%d-%H%M%S')}",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    base_time = time.time() - (args.entries * 0.25)

    audit_rows = [
        one_command_entry(
            index=index,
            base_time=base_time,
            asp_id=args.asp_id,
            target_vm=args.target_vm,
        )
        for index in range(args.entries)
    ]
    audit_path = out_dir / "audit_log.jsonl"
    write_jsonl(audit_path, audit_rows)

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entries": args.entries,
        "audit_log": str(audit_path),
        "audit_log_sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(),
    }

    if args.with_transition_log:
        transition_rows = []
        prev_hash = "0" * 64
        for index in range(args.entries):
            entry = one_transition_entry(
                index=index,
                prev_hash=prev_hash,
                controller_id=args.controller_id,
                asp_id=args.asp_id,
                cvm_id=args.target_vm,
                timestamp=base_time + index * 0.25,
            )
            transition_rows.append(entry)
            prev_hash = entry["entry_hash"]
        transition_path = out_dir / "transition_log.jsonl"
        write_jsonl(transition_path, transition_rows)
        manifest["transition_log"] = str(transition_path)
        manifest["transition_log_sha256"] = hashlib.sha256(transition_path.read_bytes()).hexdigest()
        manifest["transition_head_hash"] = prev_hash

    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Generated audit log: {audit_path}")
    if args.with_transition_log:
        print(f"Generated transition log: {out_dir / 'transition_log.jsonl'}")
    print(f"Manifest: {out_dir / 'manifest.json'}")


if __name__ == "__main__":
    main()
