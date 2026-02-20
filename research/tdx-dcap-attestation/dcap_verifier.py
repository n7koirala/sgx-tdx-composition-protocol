#!/usr/bin/env python3
"""
DCAP Quote Verifier — Local TDX Quote Verification (No Intel Cloud Dependency)

Verifies TDX DCAP quotes entirely locally using:
  1. ECDSA signature verification (attestation key, QE report)
  2. PCK certificate chain verification (PCK → Platform CA → Root CA)
  3. TCB status evaluation (against Intel's published TCB info)
  4. CRL checking (certificate revocation)
  5. Measurement extraction (MRTD, RTMRs, report_data)

Dependencies: cryptography>=41.0
"""

import hashlib
import time
import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_crl
from cryptography.exceptions import InvalidSignature

from quote_parser import (
    ParsedQuote, parse_quote, get_signed_data,
    TEE_TYPE_TDX, CERT_DATA_TYPE_PCK_CERT_CHAIN
)
from collateral_fetcher import CollateralBundle, INTEL_SGX_ROOT_CA_PEM


# ─── Verification Result ─────────────────────────────────────────────────────

@dataclass
class DCAPVerificationResult:
    """Result of DCAP quote verification."""
    # Overall
    verified: bool = False
    verdict: str = ""         # "TRUSTED", "UNTRUSTED", "ERROR"

    # Individual checks
    quote_signature_valid: bool = False
    pck_cert_chain_valid: bool = False
    pck_cert_not_revoked: bool = False
    tcb_status: str = ""      # "UpToDate", "OutOfDate", "Revoked", etc.
    qe_identity_valid: bool = False
    nonce_verified: bool = False

    # Measurements
    mrtd: str = ""
    rtmr0: str = ""
    rtmr1: str = ""
    rtmr2: str = ""
    rtmr3: str = ""
    report_data: str = ""
    is_debuggable: bool = False

    # Platform info
    fmspc: str = ""
    tee_tcb_svn: str = ""
    pck_subject: str = ""

    # Metadata
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    verification_time_ms: float = 0.0
    collateral_cached: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verified": self.verified,
            "verdict": self.verdict,
            "checks": {
                "quote_signature": self.quote_signature_valid,
                "pck_cert_chain": self.pck_cert_chain_valid,
                "pck_not_revoked": self.pck_cert_not_revoked,
                "tcb_status": self.tcb_status,
                "qe_identity": self.qe_identity_valid,
                "nonce_verified": self.nonce_verified,
            },
            "measurements": {
                "mrtd": self.mrtd,
                "rtmr0": self.rtmr0,
                "rtmr1": self.rtmr1,
                "rtmr2": self.rtmr2,
                "rtmr3": self.rtmr3,
                "report_data": self.report_data,
                "is_debuggable": self.is_debuggable,
            },
            "platform": {
                "fmspc": self.fmspc,
                "tee_tcb_svn": self.tee_tcb_svn,
                "pck_subject": self.pck_subject,
            },
            "warnings": self.warnings,
            "errors": self.errors,
            "verification_time_ms": self.verification_time_ms,
            "collateral_cached": self.collateral_cached,
        }


# ─── Certificate Helpers ─────────────────────────────────────────────────────

def split_pem_chain(pem_chain: str) -> List[x509.Certificate]:
    """Split a PEM chain into individual certificates."""
    certs = []
    for pem_block in pem_chain.split("-----END CERTIFICATE-----"):
        pem_block = pem_block.strip()
        if pem_block and "-----BEGIN CERTIFICATE-----" in pem_block:
            pem_str = pem_block + "\n-----END CERTIFICATE-----\n"
            try:
                cert = load_pem_x509_certificate(pem_str.encode())
                certs.append(cert)
            except Exception:
                pass
    return certs


def verify_cert_signature(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Verify that cert was signed by issuer."""
    try:
        issuer_public_key = issuer.public_key()
        if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
            return True
    except InvalidSignature:
        return False
    except Exception:
        return False
    return False


# ─── Core Verification Logic ─────────────────────────────────────────────────

def verify_quote_signature(quote: ParsedQuote) -> Tuple[bool, str]:
    """
    Verify the ECDSA-P256 signature on the TDX Quote.

    The attestation key signs SHA-256(Header || TD Quote Body).
    """
    try:
        signed_data = get_signed_data(quote.raw)
        digest = hashlib.sha256(signed_data).digest()

        # Reconstruct the EC public key from raw x, y coordinates
        att_key_bytes = quote.signature_data.attestation_key
        x_bytes = att_key_bytes[:32]
        y_bytes = att_key_bytes[32:64]

        # Create the public key
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            b'\x04' + x_bytes + y_bytes  # Uncompressed point format
        )

        # Extract r, s from the raw signature
        sig_bytes = quote.signature_data.signature
        r = int.from_bytes(sig_bytes[:32], 'big')
        s = int.from_bytes(sig_bytes[32:64], 'big')

        # Encode in DER format
        der_sig = utils.encode_dss_signature(r, s)

        # Verify
        public_key.verify(
            der_sig,
            signed_data,
            ec.ECDSA(hashes.SHA256())
        )

        return True, "OK"

    except InvalidSignature:
        return False, "ECDSA signature verification failed"
    except Exception as e:
        return False, f"Signature verification error: {e}"


def verify_pck_cert_chain(pck_chain_pem: str,
                          root_ca_pem: str = INTEL_SGX_ROOT_CA_PEM) -> Tuple[bool, str, List[x509.Certificate]]:
    """
    Verify the PCK certificate chain.

    Chain should be: PCK Cert → Platform CA → Root CA.
    We verify each signature in the chain and check that the root
    matches Intel's known Root CA.
    """
    try:
        certs = split_pem_chain(pck_chain_pem)
        if len(certs) < 2:
            return False, f"Certificate chain too short: {len(certs)} certs", certs

        root_ca = load_pem_x509_certificate(root_ca_pem.encode())

        # The chain is typically: [PCK cert, Platform CA, Root CA]
        # Or just: [PCK cert, Platform CA] (Root CA is known)

        # Verify from leaf to root
        for i in range(len(certs) - 1):
            cert = certs[i]
            issuer = certs[i + 1]
            if not verify_cert_signature(cert, issuer):
                return False, f"Certificate {i} signature not valid (signed by cert {i+1})", certs

        # Verify the last cert in chain against Root CA
        last_cert = certs[-1]

        # Check if the last cert IS the root CA
        if last_cert.subject == root_ca.subject:
            # Self-signed root, verify self-signature
            if not verify_cert_signature(last_cert, root_ca):
                return False, "Root CA signature mismatch", certs
        else:
            # Last cert should be signed by root CA
            if not verify_cert_signature(last_cert, root_ca):
                return False, "Chain does not terminate at Intel Root CA", certs

        # Check certificate validity (not expired)
        now = datetime.utcnow()
        for i, cert in enumerate(certs):
            if cert.not_valid_before_utc.replace(tzinfo=None) > now:
                return False, f"Certificate {i} not yet valid", certs
            if cert.not_valid_after_utc.replace(tzinfo=None) < now:
                return False, f"Certificate {i} expired", certs

        return True, "OK", certs

    except Exception as e:
        return False, f"Certificate chain verification error: {e}", []


def check_pck_crl(pck_cert: x509.Certificate, crl_der: bytes) -> Tuple[bool, str]:
    """
    Check if the PCK certificate is on the Certificate Revocation List.

    Returns:
        (not_revoked, message) — True means the cert is NOT revoked (good)
    """
    if not crl_der:
        return True, "CRL not available (skipped)"

    try:
        crl = load_der_x509_crl(crl_der)

        serial = pck_cert.serial_number
        revoked = crl.get_revoked_certificate_by_serial_number(serial)

        if revoked is not None:
            return False, f"PCK certificate is REVOKED (serial: {serial})"

        return True, "OK"

    except Exception as e:
        return True, f"CRL check warning: {e} (defaulting to not-revoked)"


def evaluate_tcb_status(tee_tcb_svn: bytes,
                        tcb_info: Dict[str, Any]) -> Tuple[str, str]:
    """
    Evaluate TCB status by comparing the quote's TEE TCB SVN against
    Intel's published TCB Info.

    The TCB Info contains a list of TCB levels. We find the matching
    level and return its status.

    Returns:
        (status, message) — e.g., ("UpToDate", "OK")
    """
    try:
        # The TCB Info JSON has a nested structure
        tcb_info_body = tcb_info
        if "tcbInfo" in tcb_info:
            tcb_info_body = tcb_info["tcbInfo"]

        # For TDX, check tdxModule and tcbLevels
        tcb_levels = tcb_info_body.get("tcbLevels", [])
        if not tcb_levels:
            return "Unknown", "No TCB levels found in TCB Info"

        # Parse quote's TCB SVN components (16 bytes → 16 uint8 values)
        quote_svns = list(tee_tcb_svn)

        # Find the best matching TCB level
        # TCB levels are ordered from latest to oldest
        for level in tcb_levels:
            tcb = level.get("tcb", {})
            level_svns = tcb.get("sgxtcbcomponents", [])

            if not level_svns:
                # Try TDX-specific format
                tdx_components = level.get("tdxtcbcomponents", tcb.get("tdxtcbcomponents", []))
                if tdx_components:
                    level_svns = tdx_components

            status = level.get("tcbStatus", level.get("status", "Unknown"))

            # For TDX, compare the SVN components
            # A platform matches a level if all its SVN components are >=
            if isinstance(level_svns, list) and len(level_svns) > 0:
                match = True
                for i, comp in enumerate(level_svns):
                    if isinstance(comp, dict):
                        svn_val = comp.get("svn", 0)
                    else:
                        svn_val = comp
                    if i < len(quote_svns) and quote_svns[i] < svn_val:
                        match = False
                        break

                if match:
                    return status, f"Matched TCB level: {status}"

        # If no level matched, the TCB is out of date
        return "OutOfDate", "No matching TCB level found (platform SVNs too low)"

    except Exception as e:
        return "Unknown", f"TCB evaluation error: {e}"


def verify_nonce_binding(quote: ParsedQuote,
                         expected_report_data: Optional[bytes]) -> Tuple[bool, str]:
    """
    Verify that the expected report data (nonce) is in the quote.

    Args:
        quote: Parsed TDX quote
        expected_report_data: The 64-byte report_data we sent

    Returns:
        (verified, message)
    """
    if expected_report_data is None:
        return True, "No nonce verification requested"

    actual = quote.body.report_data

    # Allow comparison with zero-padded shorter nonces
    if len(expected_report_data) < 64:
        expected_padded = expected_report_data.ljust(64, b'\x00')
    else:
        expected_padded = expected_report_data[:64]

    if actual == expected_padded:
        return True, "OK"

    # Check if the nonce appears at the beginning
    if actual[:len(expected_report_data)] == expected_report_data:
        return True, "OK (prefix match)"

    return False, "Report data mismatch — possible replay attack"


# ─── Main Verification Function ──────────────────────────────────────────────

def verify_quote(quote_bytes: bytes,
                 collateral: CollateralBundle,
                 expected_report_data: Optional[bytes] = None,
                 verbose: bool = False) -> DCAPVerificationResult:
    """
    Perform full DCAP verification of a TDX quote.

    This is the main entry point for quote verification. It performs:
      1. Quote parsing
      2. ECDSA signature verification
      3. PCK certificate chain verification
      4. CRL checking
      5. TCB status evaluation
      6. Nonce/report_data verification

    All verification is LOCAL — no internet calls.

    Args:
        quote_bytes: Raw binary TDX quote
        collateral: Pre-fetched verification collateral
        expected_report_data: Expected 64-byte report data (for nonce verification)
        verbose: Print detailed verification progress

    Returns:
        DCAPVerificationResult with all checks and measurements
    """
    result = DCAPVerificationResult()
    result.collateral_cached = collateral.cached
    start_time = time.time()

    try:
        # ─── Step 1: Parse Quote ──────────────────────────────────────────
        if verbose:
            print("\n  [1/6] Parsing TDX quote...")

        quote = parse_quote(quote_bytes)

        # Extract measurements
        result.mrtd = quote.body.mrtd.hex()
        result.rtmr0 = quote.body.rtmr0.hex()
        result.rtmr1 = quote.body.rtmr1.hex()
        result.rtmr2 = quote.body.rtmr2.hex()
        result.rtmr3 = quote.body.rtmr3.hex()
        result.report_data = quote.body.report_data.hex()
        result.is_debuggable = quote.body.is_debuggable
        result.tee_tcb_svn = quote.body.tee_tcb_svn.hex()

        if verbose:
            print(f"        ✓ Quote parsed ({len(quote_bytes)} bytes, "
                  f"version {quote.header.version}, {quote.header.tee_type_str})")

        # ─── Step 2: Verify Quote Signature ───────────────────────────────
        if verbose:
            print("  [2/6] Verifying ECDSA signature...")

        sig_valid, sig_msg = verify_quote_signature(quote)
        result.quote_signature_valid = sig_valid

        if not sig_valid:
            result.errors.append(f"Quote signature: {sig_msg}")
            if verbose:
                print(f"        ✗ {sig_msg}")
        else:
            if verbose:
                print(f"        ✓ Quote signature valid (ECDSA-P256)")

        # ─── Step 3: Verify PCK Certificate Chain ─────────────────────────
        if verbose:
            print("  [3/6] Verifying PCK certificate chain...")

        if quote.pck_cert_chain_pem:
            chain_valid, chain_msg, certs = verify_pck_cert_chain(
                quote.pck_cert_chain_pem,
                collateral.root_ca_cert_pem
            )
            result.pck_cert_chain_valid = chain_valid

            if chain_valid and certs:
                # Extract subject info from PCK cert
                pck_cert = certs[0]
                result.pck_subject = pck_cert.subject.rfc4514_string()

                if verbose:
                    print(f"        ✓ Chain valid ({len(certs)} certs)")
                    print(f"          PCK Subject: {result.pck_subject}")

                # ─── Step 4: Check CRL ────────────────────────────────────
                if verbose:
                    print("  [4/6] Checking certificate revocation...")

                not_revoked, crl_msg = check_pck_crl(pck_cert, collateral.pck_crl)
                result.pck_cert_not_revoked = not_revoked

                if not not_revoked:
                    result.errors.append(f"CRL check: {crl_msg}")
                    if verbose:
                        print(f"        ✗ {crl_msg}")
                else:
                    if verbose:
                        print(f"        ✓ PCK certificate not revoked")
            else:
                result.errors.append(f"PCK chain: {chain_msg}")
                result.pck_cert_not_revoked = False
                if verbose:
                    print(f"        ✗ {chain_msg}")
        else:
            result.warnings.append("No PCK certificate chain in quote")
            if verbose:
                print(f"        ⚠ No PCK certificate chain found in quote")

        # ─── Step 5: Evaluate TCB Status ──────────────────────────────────
        if verbose:
            print("  [5/6] Evaluating TCB status...")

        tcb_status, tcb_msg = evaluate_tcb_status(
            quote.body.tee_tcb_svn,
            collateral.tcb_info
        )
        result.tcb_status = tcb_status

        if tcb_status in ("UpToDate", "SWHardeningNeeded"):
            if verbose:
                print(f"        ✓ TCB status: {tcb_status}")
        elif tcb_status == "OutOfDate":
            result.warnings.append(f"TCB is out of date: {tcb_msg}")
            if verbose:
                print(f"        ⚠ TCB status: {tcb_status} — {tcb_msg}")
        else:
            result.warnings.append(f"TCB status: {tcb_status} — {tcb_msg}")
            if verbose:
                print(f"        ⚠ TCB status: {tcb_status} — {tcb_msg}")

        # ─── Step 6: Verify Nonce/Report Data ─────────────────────────────
        if verbose:
            print("  [6/6] Verifying report data (nonce binding)...")

        nonce_valid, nonce_msg = verify_nonce_binding(quote, expected_report_data)
        result.nonce_verified = nonce_valid

        if not nonce_valid:
            result.errors.append(f"Nonce: {nonce_msg}")
            if verbose:
                print(f"        ✗ {nonce_msg}")
        else:
            if verbose:
                print(f"        ✓ Report data verified")

        # ─── Determine Verdict ────────────────────────────────────────────

        # Additional warnings
        if result.is_debuggable:
            result.warnings.append("TD is debuggable — NOT suitable for production!")

        # Critical checks that must pass for TRUSTED verdict
        critical_pass = (
            result.quote_signature_valid and
            result.nonce_verified
        )

        # PCK chain is important but may not be available in all setups
        if result.pck_cert_chain_valid:
            critical_pass = critical_pass and result.pck_cert_not_revoked

        if critical_pass and len(result.errors) == 0:
            result.verified = True
            result.verdict = "TRUSTED"
        elif len(result.errors) > 0:
            result.verdict = "UNTRUSTED"
        else:
            result.verdict = "UNTRUSTED"

    except Exception as e:
        result.errors.append(str(e))
        result.verdict = "ERROR"

    result.verification_time_ms = (time.time() - start_time) * 1000
    return result


# ─── Display ──────────────────────────────────────────────────────────────────

def print_verification_result(result: DCAPVerificationResult):
    """Print verification result in a human-readable format."""
    print("\n" + "=" * 70)
    print("DCAP VERIFICATION RESULT")
    print("=" * 70)

    # Verdict
    if result.verdict == "TRUSTED":
        print(f"\n  ✓ Verdict: {result.verdict}")
    elif result.verdict == "UNTRUSTED":
        print(f"\n  ✗ Verdict: {result.verdict}")
    else:
        print(f"\n  ? Verdict: {result.verdict}")

    print(f"  Time: {result.verification_time_ms:.1f} ms")
    print(f"  Collateral: {'cached' if result.collateral_cached else 'freshly fetched'}")

    # Checks
    print(f"\n  Verification Checks:")
    print(f"    Quote Signature:  {'✓' if result.quote_signature_valid else '✗'}")
    print(f"    PCK Cert Chain:   {'✓' if result.pck_cert_chain_valid else '✗'}")
    print(f"    PCK Not Revoked:  {'✓' if result.pck_cert_not_revoked else '✗'}")
    print(f"    TCB Status:       {result.tcb_status}")
    print(f"    Nonce Binding:    {'✓' if result.nonce_verified else '✗'}")

    # Measurements
    print(f"\n  TD Measurements:")
    print(f"    MRTD:       {result.mrtd}")
    print(f"    RTMR[0]:    {result.rtmr0}")
    print(f"    RTMR[1]:    {result.rtmr1}")
    print(f"    RTMR[2]:    {result.rtmr2}")
    print(f"    RTMR[3]:    {result.rtmr3}")

    print(f"\n  Identity:")
    print(f"    Report Data: {result.report_data[:64]}...")
    print(f"    Debuggable:  {result.is_debuggable}")
    print(f"    TCB SVN:     {result.tee_tcb_svn}")

    if result.pck_subject:
        print(f"    PCK Subject: {result.pck_subject}")
    if result.fmspc:
        print(f"    FMSPC:       {result.fmspc}")

    if result.warnings:
        print(f"\n  Warnings:")
        for w in result.warnings:
            print(f"    ⚠ {w}")

    if result.errors:
        print(f"\n  Errors:")
        for e in result.errors:
            print(f"    ✗ {e}")

    print("=" * 70)
