#!/usr/bin/env python3
"""
TDX Quote Parser — Parse Binary TDX DCAP Quotes (Version 4/5)

Parses the binary TDX Quote structure according to Intel's specification
and extracts all fields including measurements, signatures, and PCK
certificate chains.

Reference: Intel TDX DCAP Quote Generation Library and Intel SGX DCAP
           Quote Verification Library documentation.
"""

import struct
import hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


# ─── Quote Version Constants ─────────────────────────────────────────────────

QUOTE_VERSION_4 = 4
QUOTE_VERSION_5 = 5

# Attestation Key Types
ATT_KEY_TYPE_ECDSA_P256 = 2
ATT_KEY_TYPE_ECDSA_P384 = 3

# TEE Type
TEE_TYPE_SGX = 0x00000000
TEE_TYPE_TDX = 0x00000081

# Certification data types
CERT_DATA_TYPE_PCK_CERT_CHAIN = 5  # PEM-encoded PCK cert chain
CERT_DATA_TYPE_PLATFORM_MANIFEST = 6
CERT_DATA_TYPE_QE_REPORT_CERT = 7


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class QuoteHeader:
    """TDX Quote Header (48 bytes)."""
    version: int             # 2 bytes - Quote version (4 or 5)
    att_key_type: int        # 2 bytes - Attestation key type
    tee_type: int            # 4 bytes - TEE type (0x81 for TDX)
    reserved: bytes          # 2 bytes
    reserved2: bytes         # 2 bytes
    qe_vendor_id: bytes      # 16 bytes - QE vendor UUID
    user_data: bytes         # 20 bytes - User-defined data

    @property
    def tee_type_str(self) -> str:
        if self.tee_type == TEE_TYPE_TDX:
            return "TDX"
        elif self.tee_type == TEE_TYPE_SGX:
            return "SGX"
        return f"Unknown(0x{self.tee_type:08x})"

    @property
    def att_key_type_str(self) -> str:
        if self.att_key_type == ATT_KEY_TYPE_ECDSA_P256:
            return "ECDSA-P256"
        elif self.att_key_type == ATT_KEY_TYPE_ECDSA_P384:
            return "ECDSA-P384"
        return f"Unknown({self.att_key_type})"


@dataclass
class TDQuoteBody:
    """TDX TD Quote Body (584 bytes).

    Contains the TDX-specific measurements and identity information.
    """
    tee_tcb_svn: bytes       # 16 bytes - TEE TCB SVN
    mrseam: bytes            # 48 bytes - SEAM module measurement
    mrsigner_seam: bytes     # 48 bytes - SEAM signer measurement
    seam_attributes: bytes   # 8 bytes
    td_attributes: bytes     # 8 bytes
    xfam: bytes              # 8 bytes - Extended features
    mrtd: bytes              # 48 bytes - TD measurement (initial image)
    mrconfigid: bytes        # 48 bytes - Config ID
    mrowner: bytes           # 48 bytes - Owner measurement
    mrownerconfig: bytes     # 48 bytes - Owner configuration
    rtmr0: bytes             # 48 bytes - Runtime measurement 0
    rtmr1: bytes             # 48 bytes - Runtime measurement 1
    rtmr2: bytes             # 48 bytes - Runtime measurement 2
    rtmr3: bytes             # 48 bytes - Runtime measurement 3
    report_data: bytes       # 64 bytes - User-supplied data (nonce)

    @property
    def is_debuggable(self) -> bool:
        attr_val = int.from_bytes(self.td_attributes, 'little')
        return bool(attr_val & 1)


@dataclass
class QEReportCertificationData:
    """QE Report + Certification Data from the quote signature."""
    qe_report: bytes         # 384 bytes - QE Report body
    qe_report_signature: bytes  # 64 bytes - ECDSA signature over QE Report
    qe_auth_data_size: int
    qe_auth_data: bytes
    certification_data_type: int
    certification_data_size: int
    certification_data: bytes  # Usually PEM-encoded PCK certificate chain


@dataclass
class QuoteSignatureData:
    """Quote Signature Data section."""
    signature: bytes         # 64 bytes - ECDSA P-256 signature (r || s)
    attestation_key: bytes   # 64 bytes - ECDSA P-256 public key (x || y)
    qe_report_cert_data: Optional[QEReportCertificationData] = None
    raw: bytes = b""


@dataclass
class ParsedQuote:
    """Fully parsed TDX Quote."""
    header: QuoteHeader
    body: TDQuoteBody
    signature_data_len: int
    signature_data: QuoteSignatureData
    raw: bytes = b""

    # Extracted certificate chain (PEM format)
    pck_cert_chain_pem: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for JSON serialization."""
        return {
            "header": {
                "version": self.header.version,
                "att_key_type": self.header.att_key_type_str,
                "tee_type": self.header.tee_type_str,
                "qe_vendor_id": self.header.qe_vendor_id.hex(),
            },
            "body": {
                "mrtd": self.body.mrtd.hex(),
                "rtmr0": self.body.rtmr0.hex(),
                "rtmr1": self.body.rtmr1.hex(),
                "rtmr2": self.body.rtmr2.hex(),
                "rtmr3": self.body.rtmr3.hex(),
                "report_data": self.body.report_data.hex(),
                "td_attributes": self.body.td_attributes.hex(),
                "is_debuggable": self.body.is_debuggable,
                "tee_tcb_svn": self.body.tee_tcb_svn.hex(),
                "mrseam": self.body.mrseam.hex(),
                "mrsigner_seam": self.body.mrsigner_seam.hex(),
                "xfam": self.body.xfam.hex(),
                "mrconfigid": self.body.mrconfigid.hex(),
                "mrowner": self.body.mrowner.hex(),
                "mrownerconfig": self.body.mrownerconfig.hex(),
            },
            "signature": {
                "sig_data_len": self.signature_data_len,
                "signature": self.signature_data.signature.hex(),
                "attestation_key": self.signature_data.attestation_key.hex(),
                "has_cert_chain": self.pck_cert_chain_pem is not None,
            },
            "quote_size": len(self.raw),
        }


# ─── Quote Parsing Functions ─────────────────────────────────────────────────

def parse_quote_header(data: bytes, offset: int = 0) -> QuoteHeader:
    """Parse the 48-byte Quote Header."""
    if len(data) < offset + 48:
        raise ValueError(f"Not enough data for quote header: need {offset + 48}, have {len(data)}")

    version, att_key_type = struct.unpack_from('<HH', data, offset)
    tee_type = struct.unpack_from('<I', data, offset + 4)[0]
    reserved = data[offset + 8:offset + 10]
    reserved2 = data[offset + 10:offset + 12]
    qe_vendor_id = data[offset + 12:offset + 28]
    user_data = data[offset + 28:offset + 48]

    return QuoteHeader(
        version=version,
        att_key_type=att_key_type,
        tee_type=tee_type,
        reserved=reserved,
        reserved2=reserved2,
        qe_vendor_id=qe_vendor_id,
        user_data=user_data,
    )


def parse_td_quote_body(data: bytes, offset: int = 48) -> TDQuoteBody:
    """Parse the 584-byte TD Quote Body."""
    if len(data) < offset + 584:
        raise ValueError(f"Not enough data for TD quote body: need {offset + 584}, have {len(data)}")

    pos = offset
    def read(n):
        nonlocal pos
        result = data[pos:pos + n]
        pos += n
        return result

    return TDQuoteBody(
        tee_tcb_svn=read(16),
        mrseam=read(48),
        mrsigner_seam=read(48),
        seam_attributes=read(8),
        td_attributes=read(8),
        xfam=read(8),
        mrtd=read(48),
        mrconfigid=read(48),
        mrowner=read(48),
        mrownerconfig=read(48),
        rtmr0=read(48),
        rtmr1=read(48),
        rtmr2=read(48),
        rtmr3=read(48),
        report_data=read(64),
    )


def parse_qe_report_cert_data(data: bytes, offset: int) -> QEReportCertificationData:
    """Parse QE Report Certification Data from signature section."""
    remaining = len(data) - offset
    pos = offset

    # QE Report (384 bytes)
    if remaining < 384:
        raise ValueError(f"Not enough data for QE Report: need 384, have {remaining}")
    qe_report = data[pos:pos + 384]
    pos += 384

    # QE Report Signature (64 bytes, ECDSA P-256)
    if len(data) - pos < 64:
        raise ValueError(f"Not enough data for QE Report Signature")
    qe_report_signature = data[pos:pos + 64]
    pos += 64

    # QE Auth Data
    if len(data) - pos < 2:
        raise ValueError(f"Not enough data for QE Auth Data size")
    qe_auth_data_size = struct.unpack_from('<H', data, pos)[0]
    pos += 2
    qe_auth_data = data[pos:pos + qe_auth_data_size]
    pos += qe_auth_data_size

    # Certification Data
    if len(data) - pos < 6:
        # No certification data header available
        return QEReportCertificationData(
            qe_report=qe_report,
            qe_report_signature=qe_report_signature,
            qe_auth_data_size=qe_auth_data_size,
            qe_auth_data=qe_auth_data,
            certification_data_type=0,
            certification_data_size=0,
            certification_data=b"",
        )

    certification_data_type = struct.unpack_from('<H', data, pos)[0]
    pos += 2
    certification_data_size = struct.unpack_from('<I', data, pos)[0]
    pos += 4

    # Read available certification data (may be less than stated size)
    available = len(data) - pos
    read_size = min(certification_data_size, available)
    certification_data = data[pos:pos + read_size]

    return QEReportCertificationData(
        qe_report=qe_report,
        qe_report_signature=qe_report_signature,
        qe_auth_data_size=qe_auth_data_size,
        qe_auth_data=qe_auth_data,
        certification_data_type=certification_data_type,
        certification_data_size=certification_data_size,
        certification_data=certification_data,
    )


def parse_signature_data(data: bytes, offset: int, sig_data_len: int) -> QuoteSignatureData:
    """Parse the Quote Signature Data section."""
    sig_end = offset + sig_data_len
    pos = offset

    # ECDSA Signature (64 bytes: r(32) || s(32))
    signature = data[pos:pos + 64]
    pos += 64

    # ECDSA Attestation Key (64 bytes: x(32) || y(32))
    attestation_key = data[pos:pos + 64]
    pos += 64

    # QE Report + Certification Data (rest of signature data)
    qe_cert_data = None
    remaining = sig_end - pos
    if remaining > 384:  # Minimum for QE report
        try:
            qe_cert_data = parse_qe_report_cert_data(data[:sig_end], pos)
        except Exception as e:
            print(f"  Warning: Could not parse QE certification data: {e}")

    return QuoteSignatureData(
        signature=signature,
        attestation_key=attestation_key,
        qe_report_cert_data=qe_cert_data,
        raw=data[offset:offset + sig_data_len],
    )


def parse_quote(data: bytes) -> ParsedQuote:
    """
    Parse a complete binary TDX Quote.

    Args:
        data: Raw binary quote bytes

    Returns:
        ParsedQuote with all fields parsed

    Raises:
        ValueError: If the data is too short or has an invalid format
    """
    if len(data) < 636:  # Minimum: header(48) + body(584) + sig_len(4)
        raise ValueError(f"Quote too short: {len(data)} bytes (minimum 636)")

    # Parse header (48 bytes)
    header = parse_quote_header(data, 0)

    if header.tee_type != TEE_TYPE_TDX:
        raise ValueError(f"Not a TDX quote: TEE type = 0x{header.tee_type:08x}")

    # Parse TD Quote Body (584 bytes starting at offset 48)
    body = parse_td_quote_body(data, 48)

    # Signature Data Length (4 bytes at offset 632)
    sig_data_len = struct.unpack_from('<I', data, 632)[0]

    if len(data) < 636 + sig_data_len:
        raise ValueError(
            f"Quote truncated: need {636 + sig_data_len}, have {len(data)}"
        )

    # Parse Signature Data
    sig_data = parse_signature_data(data, 636, sig_data_len)

    # Extract PCK certificate chain if present
    pck_cert_chain_pem = None
    if (sig_data.qe_report_cert_data and
        sig_data.qe_report_cert_data.certification_data_type == CERT_DATA_TYPE_PCK_CERT_CHAIN):
        try:
            pck_cert_chain_pem = sig_data.qe_report_cert_data.certification_data.decode('ascii')
        except UnicodeDecodeError:
            pass

    return ParsedQuote(
        header=header,
        body=body,
        signature_data_len=sig_data_len,
        signature_data=sig_data,
        raw=data,
        pck_cert_chain_pem=pck_cert_chain_pem,
    )


def get_signed_data(data: bytes) -> bytes:
    """
    Extract the data that was signed by the attestation key.

    For TDX quotes, the signed data is: Header (48 bytes) + TD Quote Body (584 bytes)
    = 632 bytes total.

    The ECDSA signature in the quote signs SHA-256(header || body).
    """
    return data[:632]


# ─── Display ──────────────────────────────────────────────────────────────────

def print_parsed_quote(quote: ParsedQuote, verbose: bool = False):
    """Print parsed quote in a human-readable format."""
    print("\n" + "=" * 70)
    print("TDX DCAP QUOTE")
    print("=" * 70)

    h = quote.header
    print(f"\n  Header:")
    print(f"    Version:         {h.version}")
    print(f"    Att Key Type:    {h.att_key_type_str}")
    print(f"    TEE Type:        {h.tee_type_str}")
    print(f"    QE Vendor ID:    {h.qe_vendor_id.hex()}")

    b = quote.body
    print(f"\n  TD Measurements:")
    print(f"    MRTD:            {b.mrtd.hex()}")
    print(f"    RTMR[0]:         {b.rtmr0.hex()}")
    print(f"    RTMR[1]:         {b.rtmr1.hex()}")
    print(f"    RTMR[2]:         {b.rtmr2.hex()}")
    print(f"    RTMR[3]:         {b.rtmr3.hex()}")

    print(f"\n  Identity:")
    print(f"    Report Data:     {b.report_data.hex()[:64]}...")
    print(f"    TEE TCB SVN:     {b.tee_tcb_svn.hex()}")
    print(f"    TD Attributes:   {b.td_attributes.hex()}")
    print(f"    Debuggable:      {b.is_debuggable}")
    print(f"    XFAM:            {b.xfam.hex()}")

    print(f"\n  Signature:")
    print(f"    Sig Data Length: {quote.signature_data_len} bytes")
    print(f"    ECDSA Sig (r):   {quote.signature_data.signature[:32].hex()}")
    print(f"    ECDSA Sig (s):   {quote.signature_data.signature[32:].hex()}")
    print(f"    Att Key (x):     {quote.signature_data.attestation_key[:32].hex()}")
    print(f"    Att Key (y):     {quote.signature_data.attestation_key[32:].hex()}")

    if quote.signature_data.qe_report_cert_data:
        qe = quote.signature_data.qe_report_cert_data
        print(f"\n  QE Certification:")
        print(f"    QE Auth Data:    {qe.qe_auth_data_size} bytes")
        print(f"    Cert Data Type:  {qe.certification_data_type} "
              f"({'PCK Cert Chain' if qe.certification_data_type == 5 else 'Other'})")
        print(f"    Cert Data Size:  {qe.certification_data_size} bytes")

    if quote.pck_cert_chain_pem:
        certs = quote.pck_cert_chain_pem.count("-----BEGIN CERTIFICATE-----")
        print(f"    Cert Chain:      {certs} certificate(s)")

    if verbose:
        print(f"\n  SEAM:")
        print(f"    MRSEAM:          {b.mrseam.hex()}")
        print(f"    MRSIGNER_SEAM:   {b.mrsigner_seam.hex()}")
        print(f"    SEAM Attributes: {b.seam_attributes.hex()}")
        print(f"\n  Config:")
        print(f"    MRCONFIGID:      {b.mrconfigid.hex()}")
        print(f"    MROWNER:         {b.mrowner.hex()}")
        print(f"    MROWNERCONFIG:   {b.mrownerconfig.hex()}")

    print(f"\n  Total Quote Size:  {len(quote.raw)} bytes")
    print("=" * 70)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description="TDX Quote Parser (DCAP)")
    parser.add_argument("quote_file", help="Path to binary TDX quote file")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--extract-certs", type=str, default=None,
                        help="Extract PCK cert chain PEM to file")

    args = parser.parse_args()

    with open(args.quote_file, 'rb') as f:
        quote_bytes = f.read()

    print(f"Parsing {args.quote_file} ({len(quote_bytes)} bytes)...")

    parsed = parse_quote(quote_bytes)

    if args.json:
        print(json.dumps(parsed.to_dict(), indent=2))
    else:
        print_parsed_quote(parsed, verbose=args.verbose)

    if args.extract_certs and parsed.pck_cert_chain_pem:
        with open(args.extract_certs, 'w') as f:
            f.write(parsed.pck_cert_chain_pem)
        print(f"\nPCK certificate chain saved to: {args.extract_certs}")


if __name__ == "__main__":
    main()
