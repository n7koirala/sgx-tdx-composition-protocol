"""SGX-sealed persistence for compact WEN runtime checkpoints."""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


SEAL_MAGIC = b"VORDR-SGX-CKPT\x01"
DEFAULT_SEAL_KEY = "/dev/attestation/keys/_sgx_mrsigner"
HKDF_INFO = b"Vordr WEN runtime checkpoint AEAD v1"


class CheckpointSealError(RuntimeError):
    pass


class SealedCheckpointStore:
    """AEAD-seal checkpoint JSON using a key derived from Gramine's SGX key."""

    def __init__(
        self,
        path: str,
        context: str,
        *,
        key_path: str = DEFAULT_SEAL_KEY,
        key_material: Optional[bytes] = None,
    ):
        self.path = Path(path)
        self.context = context.encode("utf-8")
        raw_key = key_material if key_material is not None else self._read_key(key_path)
        self._key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"VORDR-SGX-SEAL-KDF-v1",
            info=HKDF_INFO + b"\x00" + self.context,
        ).derive(raw_key)

    @staticmethod
    def _read_key(path: str) -> bytes:
        try:
            with open(path, "rb") as handle:
                key = handle.read()
        except OSError as exc:
            raise CheckpointSealError(
                f"SGX sealing key is unavailable at {path}: {exc}"
            ) from exc
        if len(key) < 16:
            raise CheckpointSealError(
                f"SGX sealing key at {path} is unexpectedly short"
            )
        return key

    @property
    def exists(self) -> bool:
        return self.path.exists()

    def save(self, checkpoint: dict) -> None:
        plaintext = json.dumps(
            checkpoint, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext, self.context)
        payload = (
            SEAL_MAGIC
            + struct.pack(">I", len(self.context))
            + self.context
            + nonce
            + ciphertext
        )

        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(
            f".{self.path.name}.{os.getpid()}.tmp"
        )
        try:
            with open(temporary, "wb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            directory_fd = os.open(
                str(self.path.parent),
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def load(self) -> Optional[dict]:
        if not self.exists:
            return None
        try:
            payload = self.path.read_bytes()
            minimum = len(SEAL_MAGIC) + 4 + 12 + 16
            if len(payload) < minimum or not payload.startswith(SEAL_MAGIC):
                raise CheckpointSealError("invalid sealed checkpoint header")
            offset = len(SEAL_MAGIC)
            context_len = struct.unpack_from(">I", payload, offset)[0]
            offset += 4
            context = payload[offset:offset + context_len]
            offset += context_len
            if context != self.context:
                raise CheckpointSealError(
                    "sealed checkpoint belongs to a different WEN target"
                )
            nonce = payload[offset:offset + 12]
            ciphertext = payload[offset + 12:]
            plaintext = AESGCM(self._key).decrypt(
                nonce, ciphertext, self.context
            )
            value = json.loads(plaintext.decode("utf-8"))
            if not isinstance(value, dict):
                raise CheckpointSealError("checkpoint payload is not an object")
            return value
        except CheckpointSealError:
            raise
        except Exception as exc:
            raise CheckpointSealError(
                f"sealed checkpoint authentication failed: {exc}"
            ) from exc

    def delete(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
