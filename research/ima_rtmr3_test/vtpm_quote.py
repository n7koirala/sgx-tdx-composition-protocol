#!/usr/bin/env python3
"""
vTPM AK management plus PCR-10 quoting and verification.

Shared by cvm_rtmr3_agent.py on the CVM side and wen_rtmr3_verifier.py on the
WEN side.

Supported CVM sources:
  * tpm2-tools persistent AK handle, if available.
  * gotpm's GCP-provisioned logical key name, default "AK".

The gotpm path is the important one for GCP CVMs where:

    sudo gotpm attest --key AK --nonce <hex> --format textproto

succeeds, but the AK is not available at a normal persistent TPM handle like
0x810000801.

Design:
  * Signing key = the GCP-provisioned AK, not a self-created AK.
  * RTMR3 bind value = SHA-384(marshalled TPM public area bytes from ak_pub).
  * The exact ak_pub bytes are transmitted so both sides hash identical bytes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils


GCP_AK_HANDLE = os.environ.get("GCP_AK_HANDLE", "0x810000801")
GCP_AK_CERT_NV = os.environ.get("GCP_AK_CERT_NV", "0x1c10000")
GCP_AK_NAME = os.environ.get("GCP_AK_NAME", "AK")
TPM2TOOLS_TCTI = os.environ.get("TPM2TOOLS_TCTI", "device:/dev/tpmrm0")

RTMR_DIGEST_LEN = 48
PCR_SHA256_LEN = 32

TPM_ALG_RSA = 0x0001
TPM_ALG_SHA1 = 0x0004
TPM_ALG_SHA256 = 0x000B
TPM_ALG_SHA384 = 0x000C
TPM_ALG_NULL = 0x0010
TPM_ALG_RSASSA = 0x0014
TPM_ALG_RSAPSS = 0x0016
TPM_ALG_ECDSA = 0x0018
TPM_ALG_ECC = 0x0023
TPM_ST_ATTEST_QUOTE = 0x8018

HASH_BY_ID = {
    TPM_ALG_SHA1: "sha1",
    TPM_ALG_SHA256: "sha256",
    TPM_ALG_SHA384: "sha384",
}
HASH_OBJ_BY_ID = {
    TPM_ALG_SHA1: hashes.SHA1,
    TPM_ALG_SHA256: hashes.SHA256,
    TPM_ALG_SHA384: hashes.SHA384,
}


@dataclass(frozen=True)
class GotpmQuote:
    bank: str
    quote: bytes
    signature: bytes
    pcrs: dict[int, bytes]


@dataclass(frozen=True)
class ParsedQuoteInfo:
    extra_data: bytes
    pcr_digest: bytes
    selections: list[tuple[str, list[int]]]


@dataclass
class VtpmVerdict:
    ok: bool
    signature_ok: bool
    nonce_ok: bool
    quoted_pcr10: str
    ak_sha384: str
    cert_binds_ak: bool
    detail: str = ""


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    if os.path.basename(cmd[0]) == "tpm2_checkquote":
        # Offline verifier path: do not require or probe a TPM device on the WEN.
        env.pop("TPM2TOOLS_TCTI", None)
    elif os.path.basename(cmd[0]).startswith("tpm2_"):
        env.setdefault("TPM2TOOLS_TCTI", TPM2TOOLS_TCTI)
    return subprocess.run(cmd, capture_output=True, check=True, env=env, **kw)


def rtmr_extend(base: bytes, digest48: bytes) -> bytes:
    """One TDX RTMR extend step: RTMR_new = SHA384(RTMR_old || digest)."""
    if len(base) != RTMR_DIGEST_LEN:
        raise ValueError(f"RTMR base must be 48 bytes, got {len(base)}")
    if len(digest48) != RTMR_DIGEST_LEN:
        raise ValueError(f"RTMR digest must be 48 bytes, got {len(digest48)}")
    return hashlib.sha384(base + digest48).digest()


def _u16(buf: bytes, off: int) -> tuple[int, int]:
    return struct.unpack_from(">H", buf, off)[0], off + 2


def _u32(buf: bytes, off: int) -> tuple[int, int]:
    return struct.unpack_from(">I", buf, off)[0], off + 4


def _u64(buf: bytes, off: int) -> tuple[int, int]:
    return struct.unpack_from(">Q", buf, off)[0], off + 8


def _tpm2b(buf: bytes, off: int) -> tuple[bytes, int]:
    size, off = _u16(buf, off)
    end = off + size
    if end > len(buf):
        raise ValueError("truncated TPM2B")
    return buf[off:end], end


def _c_unescape(value: str) -> bytes:
    try:
        from google.protobuf import text_encoding

        return text_encoding.CUnescape(value)
    except Exception:
        out = bytearray()
        i = 0
        while i < len(value):
            ch = value[i]
            if ch != "\\":
                out.extend(ch.encode("utf-8"))
                i += 1
                continue
            i += 1
            if i >= len(value):
                out.append(ord("\\"))
                break
            esc = value[i]
            i += 1
            simple = {
                "a": 0x07,
                "b": 0x08,
                "f": 0x0C,
                "n": 0x0A,
                "r": 0x0D,
                "t": 0x09,
                "v": 0x0B,
                "\\": 0x5C,
                "'": 0x27,
                '"': 0x22,
            }
            if esc in simple:
                out.append(simple[esc])
            elif esc == "x":
                out.append(int(value[i:i + 2], 16))
                i += 2
            elif esc == "u":
                cp = int(value[i:i + 4], 16)
                out.extend(chr(cp).encode("utf-8"))
                i += 4
            elif esc == "U":
                cp = int(value[i:i + 8], 16)
                out.extend(chr(cp).encode("utf-8"))
                i += 8
            elif esc in "01234567":
                octal = esc
                for _ in range(2):
                    if i < len(value) and value[i] in "01234567":
                        octal += value[i]
                        i += 1
                    else:
                        break
                out.append(int(octal, 8))
            else:
                out.extend(esc.encode("utf-8"))
        return bytes(out)


def _read_proto_string(text: str, quote_pos: int) -> tuple[bytes, int]:
    if quote_pos >= len(text) or text[quote_pos] != '"':
        raise ValueError("expected textproto string")
    i = quote_pos + 1
    escaped = False
    raw = []
    while i < len(text):
        ch = text[i]
        if escaped:
            raw.append("\\")
            raw.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            return _c_unescape("".join(raw)), i + 1
        else:
            raw.append(ch)
        i += 1
    raise ValueError("unterminated textproto string")


def _extract_bytes_field(text: str, field: str) -> Optional[bytes]:
    pat = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(field)}\s*:")
    match = pat.search(text)
    if not match:
        return None
    pos = match.end()
    while pos < len(text) and text[pos].isspace():
        pos += 1
    if pos >= len(text) or text[pos] != '"':
        return None
    value, _ = _read_proto_string(text, pos)
    return value


def _iter_named_blocks(text: str, name: str):
    pat = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(name)}\s*:??\s*{{")
    pos = 0
    while True:
        match = pat.search(text, pos)
        if not match:
            return
        start = match.end() - 1
        depth = 0
        i = start
        in_str = False
        escaped = False
        while i < len(text):
            ch = text[i]
            if in_str:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        yield text[start + 1:i]
                        pos = i + 1
                        break
            i += 1
        else:
            raise ValueError(f"unterminated {name} block")


def _parse_hash_name(block: str) -> str:
    match = re.search(r"(?<![A-Za-z0-9_])hash\s*:\s*([A-Za-z0-9_]+)", block)
    if not match:
        return ""
    name = match.group(1).lower()
    if name.startswith("sha"):
        return name
    return ""


def _parse_pcrs_block(block: str) -> dict[int, bytes]:
    pcrs: dict[int, bytes] = {}
    for inner in _iter_named_blocks(block, "pcrs"):
        if "key" not in inner or "value" not in inner:
            continue
        key_match = re.search(r"(?<![A-Za-z0-9_])key\s*:\s*(\d+)", inner)
        value = _extract_bytes_field(inner, "value")
        if key_match and value is not None:
            pcrs[int(key_match.group(1))] = value
    return pcrs


def _parse_gotpm_textproto(text: str, preferred_bank: str = "sha256") -> tuple[bytes, list[GotpmQuote], Optional[bytes]]:
    ak_pub = _extract_bytes_field(text, "ak_pub")
    if not ak_pub:
        raise ValueError("gotpm output did not include ak_pub")

    cert = _find_certificate_bytes(text, ak_pub)
    quotes: list[GotpmQuote] = []
    for quote_block in _iter_named_blocks(text, "quotes"):
        quote = _extract_bytes_field(quote_block, "quote")
        sig = _extract_bytes_field(quote_block, "raw_sig")
        if not quote or not sig:
            continue
        bank = ""
        pcrs: dict[int, bytes] = {}
        for pcrs_block in _iter_named_blocks(quote_block, "pcrs"):
            block_bank = _parse_hash_name(pcrs_block)
            if not block_bank:
                continue
            block_pcrs = _parse_pcrs_block(pcrs_block)
            if block_pcrs:
                bank = block_bank
                pcrs = block_pcrs
                break
        if bank and pcrs:
            quotes.append(GotpmQuote(bank=bank, quote=quote, signature=sig, pcrs=pcrs))

    quotes.sort(key=lambda q: 0 if q.bank == preferred_bank else 1)
    return ak_pub, quotes, cert


def _certificate_candidates(text: str) -> list[bytes]:
    values: list[bytes] = []
    cert_fields = re.finditer(
        r"(?<![A-Za-z0-9_])([A-Za-z0-9_]*(?:cert|certificate)[A-Za-z0-9_]*)\s*:",
        text,
        re.I,
    )
    for match in cert_fields:
        pos = match.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text) or text[pos] != '"':
            continue
        try:
            value, _ = _read_proto_string(text, pos)
        except ValueError:
            continue
        if b"BEGIN CERTIFICATE" in value or _load_certificate(value) is not None:
            values.append(value)
    return values


def _find_certificate_bytes(text: str, ak_pub: Optional[bytes] = None) -> Optional[bytes]:
    candidates = _certificate_candidates(text)
    if ak_pub:
        for value in candidates:
            if _cert_binds_public_area(value, ak_pub):
                return value
    return candidates[0] if candidates else None


def _hashlib_name(bank: str) -> str:
    bank = bank.lower().replace("sha-", "sha")
    if bank in ("sha1", "sha256", "sha384"):
        return bank
    raise ValueError(f"unsupported PCR bank: {bank}")


def _select_gotpm_quote(quotes: list[GotpmQuote], bank: str) -> GotpmQuote:
    bank = _hashlib_name(bank)
    for quote in quotes:
        if quote.bank == bank and 10 in quote.pcrs:
            return quote
    for quote in quotes:
        if 10 in quote.pcrs:
            return quote
    raise ValueError("gotpm output did not include a quote with PCR 10")


def _parse_tpmt_public(public: bytes):
    off = 0
    typ, off = _u16(public, off)
    _name_alg, off = _u16(public, off)
    _attrs, off = _u32(public, off)
    _auth_policy, off = _tpm2b(public, off)

    if typ == TPM_ALG_RSA:
        sym_alg, off = _u16(public, off)
        if sym_alg != TPM_ALG_NULL:
            off += 4  # keyBits + mode for the symmetric algorithms used here.
        scheme, off = _u16(public, off)
        if scheme != TPM_ALG_NULL:
            _scheme_hash, off = _u16(public, off)
        key_bits, off = _u16(public, off)
        exponent, off = _u32(public, off)
        modulus, off = _tpm2b(public, off)
        exponent = exponent or 65537
        if len(modulus) * 8 != key_bits:
            # Some TPMs include leading zero bytes; cryptography handles them.
            pass
        numbers = rsa.RSAPublicNumbers(exponent, int.from_bytes(modulus, "big"))
        return numbers.public_key()

    if typ == TPM_ALG_ECC:
        sym_alg, off = _u16(public, off)
        if sym_alg != TPM_ALG_NULL:
            off += 4
        scheme, off = _u16(public, off)
        if scheme != TPM_ALG_NULL:
            _scheme_hash, off = _u16(public, off)
        curve_id, off = _u16(public, off)
        kdf, off = _u16(public, off)
        if kdf != TPM_ALG_NULL:
            _kdf_hash, off = _u16(public, off)
        x, off = _tpm2b(public, off)
        y, off = _tpm2b(public, off)
        curve = ec.SECP256R1() if curve_id == 0x0003 else ec.SECP384R1()
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"),
            int.from_bytes(y, "big"),
            curve,
        )
        return numbers.public_key()

    raise ValueError(f"unsupported TPMT_PUBLIC type: 0x{typ:04x}")


def _parse_tpmt_signature(signature: bytes):
    off = 0
    sig_alg, off = _u16(signature, off)
    hash_alg, off = _u16(signature, off)
    if sig_alg in (TPM_ALG_RSASSA, TPM_ALG_RSAPSS):
        sig, off = _tpm2b(signature, off)
        return sig_alg, hash_alg, sig
    if sig_alg == TPM_ALG_ECDSA:
        r, off = _tpm2b(signature, off)
        s, off = _tpm2b(signature, off)
        return sig_alg, hash_alg, utils.encode_dss_signature(
            int.from_bytes(r, "big"),
            int.from_bytes(s, "big"),
        )
    raise ValueError(f"unsupported TPMT_SIGNATURE alg: 0x{sig_alg:04x}")


def _verify_tpmt_signature(public_area: bytes, quote: bytes, signature: bytes) -> bool:
    public_key = _parse_tpmt_public(public_area)
    sig_alg, hash_alg, raw_sig = _parse_tpmt_signature(signature)
    hash_cls = HASH_OBJ_BY_ID.get(hash_alg)
    if not hash_cls:
        raise ValueError(f"unsupported TPM signature hash alg: 0x{hash_alg:04x}")
    hash_obj = hash_cls()
    if sig_alg == TPM_ALG_RSASSA:
        public_key.verify(raw_sig, quote, padding.PKCS1v15(), hash_obj)
    elif sig_alg == TPM_ALG_RSAPSS:
        public_key.verify(
            raw_sig,
            quote,
            padding.PSS(mgf=padding.MGF1(hash_obj), salt_length=hash_obj.digest_size),
            hash_obj,
        )
    elif sig_alg == TPM_ALG_ECDSA:
        public_key.verify(raw_sig, quote, ec.ECDSA(hash_obj))
    else:
        return False
    return True


def _parse_tpms_attest_quote(quote: bytes) -> ParsedQuoteInfo:
    off = 0
    magic, off = _u32(quote, off)
    attest_type, off = _u16(quote, off)
    if magic != 0xFF544347:
        raise ValueError(f"bad TPM attest magic: 0x{magic:08x}")
    if attest_type != TPM_ST_ATTEST_QUOTE:
        raise ValueError(f"TPM attest is not a quote: 0x{attest_type:04x}")
    _qualified_signer, off = _tpm2b(quote, off)
    extra_data, off = _tpm2b(quote, off)
    off += 8 + 4 + 4 + 1  # TPMS_CLOCK_INFO
    off += 8              # firmwareVersion

    count, off = _u32(quote, off)
    selections: list[tuple[str, list[int]]] = []
    for _ in range(count):
        hash_alg, off = _u16(quote, off)
        sizeof_select = quote[off]
        off += 1
        select = quote[off:off + sizeof_select]
        off += sizeof_select
        bank = HASH_BY_ID.get(hash_alg, f"unknown-{hash_alg:04x}")
        pcrs: list[int] = []
        for byte_index, value in enumerate(select):
            for bit in range(8):
                if value & (1 << bit):
                    pcrs.append(byte_index * 8 + bit)
        selections.append((bank, pcrs))
    pcr_digest, off = _tpm2b(quote, off)
    return ParsedQuoteInfo(extra_data=extra_data, pcr_digest=pcr_digest, selections=selections)


def _compute_quote_pcr_digest(info: ParsedQuoteInfo, pcr_banks: dict[str, dict[str, str]]) -> bytes:
    if len(info.selections) != 1:
        raise ValueError("only one PCR bank selection is supported in this test helper")
    bank, selected = info.selections[0]
    h = hashlib.new(_hashlib_name(bank))
    bank_values = pcr_banks.get(bank, {})
    for pcr_index in selected:
        value_hex = bank_values.get(str(pcr_index))
        if value_hex is None:
            raise ValueError(f"missing PCR {bank}:{pcr_index} from gotpm evidence")
        h.update(bytes.fromhex(value_hex))
    return h.digest()


def _load_certificate(blob: bytes):
    if not blob:
        return None
    try:
        if b"BEGIN CERTIFICATE" in blob:
            return x509.load_pem_x509_certificate(blob)
        return x509.load_der_x509_certificate(blob)
    except Exception:
        return None


def _public_key_der(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _cert_binds_public_area(cert_blob: bytes, ak_pub: bytes) -> bool:
    cert = _load_certificate(cert_blob)
    if cert is None:
        return False
    try:
        ak_key = _parse_tpmt_public(ak_pub)
        return _public_key_der(cert.public_key()) == _public_key_der(ak_key)
    except Exception:
        return False


class VtpmAk:
    """Loads the GCP-provisioned AK and produces nonce-bound PCR-10 quotes."""

    def __init__(
        self,
        handle: str = GCP_AK_HANDLE,
        cert_nv: str = GCP_AK_CERT_NV,
        ak_name: str = GCP_AK_NAME,
        allow_self_ak: bool = False,
    ):
        self.handle = handle
        self.cert_nv = cert_nv
        self.ak_name = ak_name
        self._dir = tempfile.mkdtemp(prefix="vtpm_ak_")
        self.ak_pub_path = os.path.join(self._dir, "ak.pub")
        self.ak_pem_path = os.path.join(self._dir, "ak.pem")
        self.cert_path = os.path.join(self._dir, "ak_cert.der")
        self.source = ""
        self.ak_pub_bytes = b""
        self.ak_pem_bytes = b""
        self.cert_der: Optional[bytes] = None

        if not self._load_provisioned_ak_tpm2() and not self._load_provisioned_ak_gotpm():
            if allow_self_ak:
                self._create_self_ak()
            else:
                raise RuntimeError(
                    "Could not load the GCP vTPM AK. Tried:\n"
                    f"  tpm2_readpublic -c {self.handle}\n"
                    f"  gotpm attest --key {self.ak_name} --nonce <hex> --format textproto\n"
                    "Your gotpm command works, so make sure gotpm is in PATH for sudo, "
                    "or run with sudo -E and GCP_AK_NAME=AK."
                )

        if not self.ak_pub_bytes:
            with open(self.ak_pub_path, "rb") as f:
                self.ak_pub_bytes = f.read()
        if not self.ak_pem_bytes and os.path.exists(self.ak_pem_path):
            with open(self.ak_pem_path, "rb") as f:
                self.ak_pem_bytes = f.read()
        if self.cert_der is None and os.path.exists(self.cert_path):
            with open(self.cert_path, "rb") as f:
                self.cert_der = f.read()
        self.ak_pub_sha384 = hashlib.sha384(self.ak_pub_bytes).digest()

    def _load_provisioned_ak_tpm2(self) -> bool:
        try:
            _run(["tpm2_readpublic", "-c", self.handle, "-o", self.ak_pub_path, "-f", "tss"])
            _run(["tpm2_readpublic", "-c", self.handle, "-o", self.ak_pem_path, "-f", "pem"])
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

        self.source = "tpm2-tools"
        try:
            _run(["tpm2_nvread", self.cert_nv, "-o", self.cert_path])
            if os.path.getsize(self.cert_path) < 64:
                os.remove(self.cert_path)
        except (subprocess.CalledProcessError, OSError, FileNotFoundError):
            pass
        return True

    def _load_provisioned_ak_gotpm(self) -> bool:
        try:
            result = _run([
                "gotpm",
                "attest",
                "--key",
                self.ak_name,
                "--nonce",
                os.urandom(20).hex(),
                "--format",
                "textproto",
            ], text=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

        ak_pub, quotes, cert = _parse_gotpm_textproto(result.stdout)
        if not ak_pub or not quotes:
            return False
        self.source = "gotpm"
        self.ak_pub_bytes = ak_pub
        self.cert_der = cert
        try:
            public_key = _parse_tpmt_public(ak_pub)
            self.ak_pem_bytes = public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception:
            self.ak_pem_bytes = b""
        return True

    def _create_self_ak(self) -> None:
        self.source = "self-ak"
        ek = os.path.join(self._dir, "ek.ctx")
        akctx = os.path.join(self._dir, "ak.ctx")
        _run(["tpm2_createek", "-c", ek, "-G", "rsa", "-u", os.path.join(self._dir, "ek.pub")])
        _run([
            "tpm2_createak",
            "-C", ek,
            "-c", akctx,
            "-G", "rsa",
            "-g", "sha256",
            "-s", "rsassa",
            "-u", self.ak_pub_path,
            "-n", os.path.join(self._dir, "ak.name"),
        ])
        _run(["tpm2_readpublic", "-c", akctx, "-o", self.ak_pem_path, "-f", "pem"])
        self.handle = akctx

    def quote_pcr10(self, nonce_bytes: bytes, bank: str = "sha256") -> dict:
        if self.source == "gotpm":
            return self._quote_pcr10_gotpm(nonce_bytes, bank)
        return self._quote_pcr10_tpm2(nonce_bytes, bank)

    def _quote_pcr10_tpm2(self, nonce_bytes: bytes, bank: str) -> dict:
        q = nonce_bytes.hex()
        msg = os.path.join(self._dir, "q.msg")
        sig = os.path.join(self._dir, "q.sig")
        pcr = os.path.join(self._dir, "q.pcr")
        _run([
            "tpm2_quote", "-c", self.handle, "-l", f"{bank}:10", "-q", q,
            "-m", msg, "-s", sig, "-o", pcr, "-g", "sha256",
        ])
        with open(msg, "rb") as f:
            msg_bytes = f.read()
        with open(sig, "rb") as f:
            sig_bytes = f.read()
        with open(pcr, "rb") as f:
            pcr_bytes = f.read()
        return {
            "vtpm_quote_format": "tpm2-tools",
            "vtpm_quote_bank": bank,
            "vtpm_quote_msg_b64": base64.b64encode(msg_bytes).decode("ascii"),
            "vtpm_quote_sig_b64": base64.b64encode(sig_bytes).decode("ascii"),
            "vtpm_pcr_bin_b64": base64.b64encode(pcr_bytes).decode("ascii"),
            "vtpm_pcrs": {},
            "ak_pub_b64": base64.b64encode(self.ak_pub_bytes).decode("ascii"),
            "ak_pem_b64": base64.b64encode(self.ak_pem_bytes).decode("ascii"),
            "ak_pub_sha384": self.ak_pub_sha384.hex(),
            "google_ak_cert_b64": base64.b64encode(self.cert_der).decode("ascii") if self.cert_der else "",
        }

    def _quote_pcr10_gotpm(self, nonce_bytes: bytes, bank: str) -> dict:
        nonce_arg = nonce_bytes.hex()
        result = _run([
            "gotpm",
            "attest",
            "--key",
            self.ak_name,
            "--nonce",
            nonce_arg,
            "--format",
            "textproto",
        ], text=True)
        ak_pub, quotes, cert = _parse_gotpm_textproto(result.stdout, preferred_bank=bank)
        quote = _select_gotpm_quote(quotes, bank)
        pcrs = {quote.bank: {str(k): v.hex() for k, v in sorted(quote.pcrs.items())}}
        cert_blob = cert or self.cert_der or b""
        return {
            "vtpm_quote_format": "gotpm-textproto",
            "vtpm_quote_bank": quote.bank,
            "vtpm_quote_msg_b64": base64.b64encode(quote.quote).decode("ascii"),
            "vtpm_quote_sig_b64": base64.b64encode(quote.signature).decode("ascii"),
            "vtpm_pcr_bin_b64": base64.b64encode(quote.pcrs[10]).decode("ascii"),
            "vtpm_pcrs": pcrs,
            "ak_pub_b64": base64.b64encode(ak_pub).decode("ascii"),
            "ak_pem_b64": base64.b64encode(self.ak_pem_bytes).decode("ascii"),
            "ak_pub_sha384": hashlib.sha384(ak_pub).hexdigest(),
            "google_ak_cert_b64": base64.b64encode(cert_blob).decode("ascii"),
            "google_ak_cert_binds_ak": _cert_binds_public_area(cert_blob, ak_pub) if cert_blob else False,
        }


def verify_pcr10_quote(resp: dict, nonce_bytes: bytes) -> VtpmVerdict:
    quote_format = resp.get("vtpm_quote_format", "tpm2-tools")
    if quote_format == "gotpm-textproto":
        return _verify_gotpm_quote(resp, nonce_bytes)
    return _verify_tpm2_tools_quote(resp, nonce_bytes)


def _verify_gotpm_quote(resp: dict, nonce_bytes: bytes) -> VtpmVerdict:
    ak_pub = base64.b64decode(resp["ak_pub_b64"])
    quote = base64.b64decode(resp["vtpm_quote_msg_b64"])
    sig = base64.b64decode(resp["vtpm_quote_sig_b64"])
    ak_sha384 = hashlib.sha384(ak_pub).hexdigest()
    detail_parts: list[str] = []

    signature_ok = False
    try:
        signature_ok = _verify_tpmt_signature(ak_pub, quote, sig)
    except Exception as exc:
        detail_parts.append(f"signature verify failed: {exc}")

    nonce_ok = False
    pcr_digest_ok = False
    quoted_pcr10 = ""
    try:
        info = _parse_tpms_attest_quote(quote)
        expected_nonce_forms = {nonce_bytes, nonce_bytes.hex().encode("ascii")}
        nonce_ok = info.extra_data in expected_nonce_forms
        if not nonce_ok:
            detail_parts.append(
                "nonce mismatch: quote extraData=" + info.extra_data.hex()
            )
        pcr_banks = resp.get("vtpm_pcrs", {})
        computed_digest = _compute_quote_pcr_digest(info, pcr_banks)
        pcr_digest_ok = computed_digest == info.pcr_digest
        if not pcr_digest_ok:
            detail_parts.append(
                f"PCR digest mismatch: computed={computed_digest.hex()} signed={info.pcr_digest.hex()}"
            )
        bank = resp.get("vtpm_quote_bank", "sha256")
        quoted_pcr10 = pcr_banks.get(bank, {}).get("10", "")
    except Exception as exc:
        detail_parts.append(f"quote parse failed: {exc}")

    cert_binds = _ak_matches_cert(resp)
    ok = signature_ok and nonce_ok and pcr_digest_ok and bool(quoted_pcr10)
    return VtpmVerdict(
        ok=ok,
        signature_ok=signature_ok,
        nonce_ok=nonce_ok,
        quoted_pcr10=quoted_pcr10,
        ak_sha384=ak_sha384,
        cert_binds_ak=cert_binds,
        detail="; ".join(detail_parts),
    )


def _verify_tpm2_tools_quote(resp: dict, nonce_bytes: bytes) -> VtpmVerdict:
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
            "tpm2_checkquote", "-u", ak_pub_p, "-m", msg_p, "-s", sig_p,
            "-f", pcr_p, "-q", nonce_bytes.hex(), "-g", "sha256",
        ])
        sig_ok = True
    except subprocess.CalledProcessError as exc:
        detail = "checkquote failed: " + exc.stderr.decode("utf-8", errors="replace")[:200]
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
    if resp.get("google_ak_cert_binds_ak") is True:
        return True
    cert_b64 = resp.get("google_ak_cert_b64", "")
    if not cert_b64:
        return False
    try:
        cert_blob = base64.b64decode(cert_b64)
        ak_pub = base64.b64decode(resp["ak_pub_b64"])
        if _cert_binds_public_area(cert_blob, ak_pub):
            return True

        cert = _load_certificate(cert_blob)
        if cert is None or not resp.get("ak_pem_b64"):
            return False
        ak_key = serialization.load_pem_public_key(base64.b64decode(resp["ak_pem_b64"]))
        return _public_key_der(cert.public_key()) == _public_key_der(ak_key)
    except Exception:
        return False


if __name__ == "__main__":
    nonce = os.urandom(20)
    ak = VtpmAk(allow_self_ak=True)
    print("source:", ak.source)
    print("ak_pub_sha384 (RTMR3 bind value):", ak.ak_pub_sha384.hex())
    print("google cert present:", ak.cert_der is not None)
    resp = ak.quote_pcr10(nonce)
    verdict = verify_pcr10_quote(resp, nonce)
    print("signature_ok:", verdict.signature_ok)
    print("nonce_ok:", verdict.nonce_ok)
    print("quoted_pcr10:", verdict.quoted_pcr10)
    print("cert_binds_ak:", verdict.cert_binds_ak)
    if verdict.detail:
        print("detail:", verdict.detail)
