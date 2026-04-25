#!/usr/bin/env python3
"""Shared helpers for the scalability evaluation harness."""

from __future__ import annotations

import asyncio
import base64
import csv
import hashlib
import hmac
import json
import secrets
import statistics
import time
from pathlib import Path
from typing import Any


NONCE_BYTES = 32


def generate_nonce() -> str:
    """Return a base64-encoded nonce for end-user requests."""
    return base64.b64encode(secrets.token_bytes(NONCE_BYTES)).decode("ascii")


def parse_int_list(raw: str) -> list[int]:
    values = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        values.append(int(item))
    if not values:
        raise ValueError("expected at least one integer value")
    return values


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    if pct <= 0:
        return min(values)
    if pct >= 100:
        return max(values)
    ordered = sorted(values)
    idx = int(round((len(ordered) - 1) * (pct / 100.0)))
    return ordered[idx]


def summarize_samples(values: list[float]) -> dict[str, float]:
    if not values:
        return {
            "min": 0.0,
            "mean": 0.0,
            "median": 0.0,
            "p95": 0.0,
            "p99": 0.0,
            "max": 0.0,
            "stdev": 0.0,
        }
    return {
        "min": min(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
        "max": max(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    ensure_dir(path.parent)
    if not rows:
        path.write_text("", encoding="utf-8")
        return

    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def stable_json_bytes(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_proof_mac(secret: str, proof_fields: dict[str, Any]) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        stable_json_bytes(proof_fields),
        hashlib.sha256,
    )
    return digest.hexdigest()


async def send_json(writer: asyncio.StreamWriter, payload: dict[str, Any]) -> None:
    writer.write(stable_json_bytes(payload) + b"\n")
    await writer.drain()


async def recv_json(reader: asyncio.StreamReader) -> dict[str, Any]:
    line = await reader.readline()
    if not line:
        raise ConnectionError("peer closed connection")
    return json.loads(line.decode("utf-8"))


def now_ms() -> float:
    return time.time() * 1000.0

