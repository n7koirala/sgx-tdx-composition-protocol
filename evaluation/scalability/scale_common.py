#!/usr/bin/env python3
"""Shared helpers for the scalability evaluation harness."""

from __future__ import annotations

import asyncio
import base64
import csv
import hashlib
import hmac
import json
import os
import secrets
import statistics
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


NONCE_BYTES = 32
SGX_MRSIGNER_KEY_PATH = "/dev/attestation/keys/_sgx_mrsigner"
ED25519_KDF_INFO = b"Vordr delegated-response Ed25519 key v1"


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
            "p999": 0.0,
            "max": 0.0,
            "stdev": 0.0,
        }
    return {
        "min": min(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
        "p999": percentile(values, 99.9),
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


class ResponseProofSigner:
    """Authenticate nonce-bound delegated results with HMAC or Ed25519.

    Under Gramine/SGX, Ed25519 key material is deterministically derived from
    the enclave-only MRSIGNER sealing key. This keeps the private key inside the
    measured WEN and makes it recoverable after restart. Outside SGX, an
    ephemeral key is generated solely for functional and control experiments.
    """

    def __init__(
        self,
        mode: str,
        *,
        controller_id: str,
        proof_secret: str,
        require_sgx_key: bool = False,
        sgx_key_path: str = SGX_MRSIGNER_KEY_PATH,
    ) -> None:
        self.mode = mode
        self.proof_secret = proof_secret
        self.private_key: Ed25519PrivateKey | None = None
        self.public_key_bytes = b""
        self.key_origin = "shared-session-secret"

        if mode == "hmac-sha256":
            self.key_id = ""
            return
        if mode != "ed25519":
            raise ValueError(f"unsupported response authentication mode: {mode}")

        try:
            with open(sgx_key_path, "rb") as handle:
                root_key = handle.read()
            if len(root_key) < 16:
                raise ValueError("SGX sealing key is unexpectedly short")
            seed = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"VORDR-DELEGATED-RESPONSE-KDF-v1",
                info=ED25519_KDF_INFO + b"\x00" + controller_id.encode("utf-8"),
            ).derive(root_key)
            self.key_origin = "sgx-mrsigner-derived"
        except (OSError, ValueError) as exc:
            if require_sgx_key:
                raise RuntimeError(
                    "Ed25519 response authentication requires the Gramine SGX "
                    f"sealing key at {sgx_key_path}: {exc}"
                ) from exc
            seed = os.urandom(32)
            self.key_origin = "process-ephemeral"

        self.private_key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key_bytes = self.private_key.public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )
        self.key_id = hashlib.sha256(self.public_key_bytes).hexdigest()

    def metadata(self) -> dict[str, str]:
        metadata = {
            "proof_alg": self.mode,
            "proof_key_origin": self.key_origin,
            "proof_key_id": self.key_id,
        }
        if self.public_key_bytes:
            metadata["proof_public_key_b64"] = base64.b64encode(
                self.public_key_bytes
            ).decode("ascii")
        return metadata

    def authenticate(self, proof_fields: dict[str, Any]) -> dict[str, str]:
        if self.mode == "hmac-sha256":
            return {
                **self.metadata(),
                "proof_mac": compute_proof_mac(self.proof_secret, proof_fields),
            }
        if self.private_key is None:
            raise RuntimeError("Ed25519 signer was not initialized")
        signature = self.private_key.sign(stable_json_bytes(proof_fields))
        return {
            **self.metadata(),
            "proof_signature_b64": base64.b64encode(signature).decode("ascii"),
        }


def verify_ed25519_proof(
    public_key_bytes: bytes,
    signature_b64: str,
    proof_fields: dict[str, Any],
) -> None:
    """Raise when an Ed25519 delegated-result signature is invalid."""
    signature = base64.b64decode(signature_b64, validate=True)
    Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
        signature,
        stable_json_bytes(proof_fields),
    )


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

