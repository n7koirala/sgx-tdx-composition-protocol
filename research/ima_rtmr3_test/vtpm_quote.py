#!/usr/bin/env python3
"""
vTPM AK management plus PCR-10 quoting and verification.

Shared by cvm_rtmr3_agent.py on the CVM side and wen_rtmr3_verifier.py on the
WEN side. The CVM side needs a TPM and tpm2-tools. The verifier side does not
need a TPM, but it does need tpm2_checkquote for the pure signature/nonce/PCR
composite check.

Design:
  * Signing key = the GCP-provisioned AK, not a self-created AK.
  * RTMR3 bind value = SHA-384(marshalled TPM2B_PUBLIC).
  * The exact ak.pub bytes are transmitted so both sides hash identical bytes.
"""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional


GCP_AK_HANDLE = os.environ.get("GCP_AK_HANDLE", "0x810000801")
GCP_AK_CERT_NV = os.environ.get("GCP_AK_CERT_NV", "0x1c10000")
TPM2TOOLS_TCTI = os.environ.get("TPM2TOOLS_TCTI", "device:/dev/tpmrm0")

RTMR_DIGEST_LEN = 48
PCR_SHA256_LEN = 32


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    if os.path.basename(cmd[0]) == "tpm2_checkquote":
        # Offline verifier path: do not require or probe a TPM device on the WEN.
        env.pop("TPM2TOOLS_TCTI", None)
    else:
        env.setdefault("TPM2TOOLS_TCTI", TPM2TOOLS_TCTI)
    return subprocess.run(cmd, capture_output=True, check=True, env=env, **kw)


def rtmr_extend(base: bytes, digest48: bytes) -> bytes:
    """One TDX RTMR extend step: RTMR_new = SHA384(RTMR_old || digest)."""
    if len(base) != RTMR_DIGEST_LEN:
        raise ValueError(f"RTMR base must be 48 bytes, got {len(base)}")
    if len(digest48) != RTMR_DIGEST_LEN:
        raise ValueError(f"RTMR digest must be 48 bytes, got {len(digest48)}")
    return hashlib.sha384(base + digest48).digest()


class VtpmAk:
    """Loads the GCP-provisioned AK and produces nonce-bound PCR-10 quotes."""

    def __init__(
        self,
        handle: str = GCP_AK_HANDLE,
        cert_nv: str = GCP_AK_CERT_NV,
        allow_self_ak: bool = False,
    ):
        self.handle = handle
        self.cert_nv = cert_nv
        self._dir = tempfile.mkdtemp(prefix="vtpm_ak_")
        self.ak_pub_path = os.path.join(self._dir, "ak.pub")
        self.ak_pem_path = os.path.join(self._dir, "ak.pem")
        self.cert_path = os.path.join(self._dir, "ak_cert.der")

        if not self._load_provisioned_ak():
            if allow_self_ak:
                self._create_self_ak()
            else:
                raise RuntimeError(
                    f"No AK at handle {self.handle}. Provision the Google AK first:\n"
                    "  trustauthority-cli provision-ak-template "
                    "--ak-template-index 0x1c10001 -c config.json\n"
                    "or run: gotpm attest --key AK --nonce $(openssl rand -hex 20) "
                    "--format textproto\n"
                    "(or pass allow_self_ak=True for local mechanism testing only)"
                )

        with open(self.ak_pub_path, "rb") as f:
            self.ak_pub_bytes = f.read()
        with open(self.ak_pem_path, "rb") as f:
            self.ak_pem_bytes = f.read()
        self.cert_der: Optional[bytes] = (
            open(self.cert_path, "rb").read()
            if os.path.exists(self.cert_path)
            else None
        )
        self.ak_pub_sha384 = hashlib.sha384(self.ak_pub_bytes).digest()

    def _load_provisioned_ak(self) -> bool:
        try:
            _run([
                "tpm2_readpublic",
                "-c",
                self.handle,
                "-o",
                self.ak_pub_path,
                "-f",
                "tss",
            ])
            _run([
                "tpm2_readpublic",
                "-c",
                self.handle,
                "-o",
                self.ak_pem_path,
                "-f",
                "pem",
            ])
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

        try:
            _run(["tpm2_nvread", self.cert_nv, "-o", self.cert_path])
            if os.path.getsize(self.cert_path) < 64:
                os.remove(self.cert_path)
        except (subprocess.CalledProcessError, OSError):
            pass
        return True

    def _create_self_ak(self) -> None:
        ek = os.path.join(self._dir, "ek.ctx")
        akctx = os.path.join(self._dir, "ak.ctx")
        _run([
            "tpm2_createek",
            "-c",
            ek,
            "-G",
            "rsa",
            "-u",
            os.path.join(self._dir, "ek.pub"),
        ])
        _run([
            "tpm2_createak",
            "-C",
            ek,
            "-c",
            akctx,
            "-G",
            "rsa",
            "-g",
            "sha256",
            "-s",
            "rsassa",
            "-u",
            self.ak_pub_path,
            "-n",
            os.path.join(self._dir, "ak.name"),
        ])
        _run(["tpm2_readpublic", "-c", akctx, "-o", self.ak_pem_path, "-f", "pem"])
        self.handle = akctx

    def quote_pcr10(self, nonce_bytes: bytes, bank: str = "sha256") -> dict:
        """Nonce-bound TPM2_Quote over <bank>:10. Returns base64 artifacts."""
        q = nonce_bytes.hex()
        msg = os.path.join(self._dir, "q.msg")
        sig = os.path.join(self._dir, "q.sig")
        pcr = os.path.join(self._dir, "q.pcr")
        _run([
            "tpm2_quote",
            "-c",
            self.handle,
            "-l",
            f"{bank}:10",
            "-q",
            q,
            "-m",
            msg,
            "-s",
            sig,
            "-o",
            pcr,
            "-g",
            "sha256",
        ])
        with open(msg, "rb") as f:
            msg_bytes = f.read()
        with open(sig, "rb") as f:
            sig_bytes = f.read()
        with open(pcr, "rb") as f:
            pcr_bytes = f.read()
        return {
            "vtpm_quote_bank": bank,
            "vtpm_quote_msg_b64": base64.b64encode(msg_bytes).decode("ascii"),
            "vtpm_quote_sig_b64": base64.b64encode(sig_bytes).decode("ascii"),
            "vtpm_pcr_bin_b64": base64.b64encode(pcr_bytes).decode("ascii"),
            "ak_pub_b64": base64.b64encode(self.ak_pub_bytes).decode("ascii"),
            "ak_pem_b64": base64.b64encode(self.ak_pem_bytes).decode("ascii"),
            "ak_pub_sha384": self.ak_pub_sha384.hex(),
            "google_ak_cert_b64": (
                base64.b64encode(self.cert_der).decode("ascii")
                if self.cert_der
                else ""
            ),
        }


@dataclass
class VtpmVerdict:
    ok: bool
    signature_ok: bool
    nonce_ok: bool
    quoted_pcr10: str
    ak_sha384: str
    cert_binds_ak: bool
    detail: str = ""


def verify_pcr10_quote(resp: dict, nonce_bytes: bytes) -> VtpmVerdict:
    """
    Verify the vTPM PCR-10 quote from an agent response dict.

    tpm2_checkquote validates the signature under ak_pub, nonce binding, and
    that pcr.bin matches the signed PCR composite digest.
    """
    ak_pub = base64.b64decode(resp["ak_pub_b64"])
    msg = base64.b64decode(resp["vtpm_quote_msg_b64"])
    sig = base64.b64decode(resp["vtpm_quote_sig_b64"])
    pcr = base64.b64decode(resp["vtpm_pcr_bin_b64"])
    ak_sha384 = hashlib.sha384(ak_pub).hexdigest()

    d = tempfile.mkdtemp(prefix="vtpm_vfy_")
    ak_pub_p = os.path.join(d, "ak.pub")
    msg_p = os.path.join(d, "q.msg")
    sig_p = os.path.join(d, "q.sig")
    pcr_p = os.path.join(d, "q.pcr")
    for path, blob in ((ak_pub_p, ak_pub), (msg_p, msg), (sig_p, sig), (pcr_p, pcr)):
        with open(path, "wb") as f:
            f.write(blob)

    sig_ok = False
    detail = ""
    try:
        _run([
            "tpm2_checkquote",
            "-u",
            ak_pub_p,
            "-m",
            msg_p,
            "-s",
            sig_p,
            "-f",
            pcr_p,
            "-q",
            nonce_bytes.hex(),
            "-g",
            "sha256",
        ])
        sig_ok = True
    except subprocess.CalledProcessError as exc:
        detail = (
            "checkquote failed: "
            + exc.stderr.decode("utf-8", errors="replace")[:200]
        )
    except FileNotFoundError:
        detail = "checkquote failed: tpm2_checkquote not found"

    quoted_pcr10 = pcr[:PCR_SHA256_LEN].hex() if len(pcr) >= PCR_SHA256_LEN else ""
    cert_binds = _ak_matches_cert(resp)

    return VtpmVerdict(
        ok=sig_ok and bool(quoted_pcr10),
        signature_ok=sig_ok,
        nonce_ok=sig_ok,
        quoted_pcr10=quoted_pcr10,
        ak_sha384=ak_sha384,
        cert_binds_ak=cert_binds,
        detail=detail,
    )


def _ak_matches_cert(resp: dict) -> bool:
    """True if ak_pub PEM key equals the Google leaf cert public key."""
    cert_b64 = resp.get("google_ak_cert_b64", "")
    pem_b64 = resp.get("ak_pem_b64", "")
    if not cert_b64 or not pem_b64:
        return False
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
            load_pem_public_key,
        )

        cert = x509.load_der_x509_certificate(base64.b64decode(cert_b64))
        ak_key = load_pem_public_key(base64.b64decode(pem_b64))
        cert_pub = cert.public_key().public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        )
        ak_pub = ak_key.public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        )
        return cert_pub == ak_pub
    except Exception:
        return False


if __name__ == "__main__":
    nonce = os.urandom(20)
    ak = VtpmAk(allow_self_ak=True)
    print("ak_pub_sha384 (RTMR3 bind value):", ak.ak_pub_sha384.hex())
    print("google cert present:", ak.cert_der is not None)
    resp = ak.quote_pcr10(nonce)
    verdict = verify_pcr10_quote(resp, nonce)
    print("signature_ok:", verdict.signature_ok)
    print("quoted_pcr10:", verdict.quoted_pcr10)
    print("cert_binds_ak:", verdict.cert_binds_ak)
