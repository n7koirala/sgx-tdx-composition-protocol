#!/usr/bin/env python3
"""
Intel PCS Collateral Fetcher — Fetch and Cache DCAP Verification Collateral

Fetches PCK certificates, TCB info, QE identity, and CRLs from Intel's
Provisioning Certification Service (PCS). Caches results locally so that
subsequent quote verifications don't require internet access.

Intel PCS API v4: https://api.trustedservices.intel.com/sgx/certification/v4/
"""

import os
import json
import time
import hashlib
import requests
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple
from pathlib import Path


# ─── Intel PCS Configuration ─────────────────────────────────────────────────

INTEL_PCS_BASE_URL = "https://api.trustedservices.intel.com"
PCS_API_VERSION = "v4"

# API Endpoints
PCS_ENDPOINTS = {
    "tcbinfo":    f"/sgx/certification/{PCS_API_VERSION}/tcb",
    "pckcrl":     f"/sgx/certification/{PCS_API_VERSION}/pckcrl",
    "qeidentity": f"/sgx/certification/{PCS_API_VERSION}/qe/identity",
    "fmspc":      f"/tdx/certification/{PCS_API_VERSION}/tcb",
    "root_ca":    f"/sgx/certification/{PCS_API_VERSION}/rootcacrl",
}

# Default cache directory
DEFAULT_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "collateral")

# Cache expiry (24 hours)
CACHE_EXPIRY_SECONDS = 86400

# Intel SGX Root CA certificate (hardcoded for verification)
INTEL_SGX_ROOT_CA_PEM = """-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----"""


# ─── Collateral Data Classes ─────────────────────────────────────────────────

@dataclass
class CollateralBundle:
    """All collateral needed for quote verification."""
    tcb_info: Dict[str, Any]          # TCB Info JSON
    tcb_info_issuer_chain: str        # PEM cert chain (from header)
    qe_identity: Dict[str, Any]      # QE Identity JSON
    qe_identity_issuer_chain: str     # PEM cert chain (from header)
    root_ca_crl: bytes                # Root CA CRL (DER)
    pck_crl: bytes                    # PCK CRL (DER)
    pck_crl_issuer_chain: str         # PEM cert chain (from header)
    root_ca_cert_pem: str             # Intel Root CA PEM
    fmspc: str                        # FMSPC this collateral is for
    fetched_at: str                   # ISO timestamp
    cached: bool = False              # Whether this came from cache


# ─── Cache Management ────────────────────────────────────────────────────────

def _cache_path(cache_dir: str, fmspc: str, item: str) -> str:
    """Get path for a cached collateral item."""
    return os.path.join(cache_dir, f"{fmspc}_{item}")


def _is_cache_valid(filepath: str, max_age: int = CACHE_EXPIRY_SECONDS) -> bool:
    """Check if a cached file exists and is not expired."""
    if not os.path.exists(filepath):
        return False
    mtime = os.path.getmtime(filepath)
    age = time.time() - mtime
    return age < max_age


def _save_to_cache(filepath: str, data: Any):
    """Save data to cache file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    if isinstance(data, bytes):
        with open(filepath, 'wb') as f:
            f.write(data)
    elif isinstance(data, dict):
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    else:
        with open(filepath, 'w') as f:
            f.write(str(data))


def _load_from_cache(filepath: str, as_json: bool = False) -> Any:
    """Load data from cache file."""
    if as_json:
        with open(filepath, 'r') as f:
            return json.load(f)
    else:
        with open(filepath, 'rb') as f:
            return f.read()


# ─── PCS API Calls ───────────────────────────────────────────────────────────

def _pcs_request(endpoint: str, params: Dict = None,
                 timeout: float = 30.0) -> Tuple[bytes, Dict[str, str]]:
    """
    Make a request to Intel PCS API.

    Returns:
        Tuple of (response body bytes, response headers dict)
    """
    url = INTEL_PCS_BASE_URL + endpoint

    headers = {
        "Accept": "application/json",
    }

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=timeout)
        resp.raise_for_status()
        return resp.content, dict(resp.headers)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"PCS API request failed: {url} — {e}")


def fetch_tcb_info(fmspc: str) -> Tuple[Dict[str, Any], str]:
    """
    Fetch TCB Info for a given FMSPC from Intel PCS.

    Returns:
        Tuple of (TCB Info dict, issuer cert chain PEM)
    """
    # Use the TDX-specific endpoint
    endpoint = PCS_ENDPOINTS["fmspc"]
    params = {"fmspc": fmspc}

    body, headers = _pcs_request(endpoint, params)

    tcb_info = json.loads(body)

    # The issuer cert chain is in the response headers
    issuer_chain = headers.get("SGX-TCB-Info-Issuer-Chain", "")
    issuer_chain = requests.utils.unquote(issuer_chain)

    return tcb_info, issuer_chain


def fetch_qe_identity() -> Tuple[Dict[str, Any], str]:
    """
    Fetch QE Identity from Intel PCS.

    Returns:
        Tuple of (QE Identity dict, issuer cert chain PEM)
    """
    endpoint = PCS_ENDPOINTS["qeidentity"]

    body, headers = _pcs_request(endpoint)

    qe_identity = json.loads(body)

    issuer_chain = headers.get("SGX-Enclave-Identity-Issuer-Chain", "")
    issuer_chain = requests.utils.unquote(issuer_chain)

    return qe_identity, issuer_chain


def fetch_pck_crl(ca: str = "platform") -> Tuple[bytes, str]:
    """
    Fetch PCK Certificate Revocation List from Intel PCS.

    Args:
        ca: "platform" or "processor"

    Returns:
        Tuple of (CRL bytes in DER format, issuer cert chain PEM)
    """
    endpoint = PCS_ENDPOINTS["pckcrl"]
    params = {"ca": ca, "encoding": "der"}

    body, headers = _pcs_request(endpoint, params)

    issuer_chain = headers.get("SGX-PCK-CRL-Issuer-Chain", "")
    issuer_chain = requests.utils.unquote(issuer_chain)

    return body, issuer_chain


def fetch_root_ca_crl() -> bytes:
    """
    Fetch Intel SGX Root CA CRL.

    The CRL is available from the distribution point in the Root CA certificate:
    https://certificates.trustedservices.intel.com/IntelSGXRootCA.der

    Returns:
        CRL bytes in DER format, or empty bytes if unavailable
    """
    # Intel's Root CA CRL distribution point
    crl_urls = [
        "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der",
        f"{INTEL_PCS_BASE_URL}/sgx/certification/{PCS_API_VERSION}/pckcrl?ca=processor&encoding=der",
    ]

    for url in crl_urls:
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                return resp.content
        except Exception:
            continue

    # Return empty if we couldn't fetch — verification will skip CRL check
    return b""


# ─── Main Fetcher ─────────────────────────────────────────────────────────────

def fetch_collateral(fmspc: str,
                     cache_dir: str = DEFAULT_CACHE_DIR,
                     force_refresh: bool = False,
                     verbose: bool = False) -> CollateralBundle:
    """
    Fetch all verification collateral for a given FMSPC.

    Uses local cache if available and not expired. Otherwise fetches from
    Intel PCS and caches the results.

    Args:
        fmspc: Platform FMSPC (6 bytes hex, e.g. "00806F050000")
        cache_dir: Directory for caching collateral
        force_refresh: Force re-fetch even if cache is valid
        verbose: Print progress

    Returns:
        CollateralBundle with all needed verification data
    """
    os.makedirs(cache_dir, exist_ok=True)
    used_cache = True  # Track if we used any cached data

    # Check cache for all items
    tcb_cache = _cache_path(cache_dir, fmspc, "tcb_info.json")
    tcb_chain_cache = _cache_path(cache_dir, fmspc, "tcb_issuer_chain.pem")
    qe_cache = _cache_path(cache_dir, fmspc, "qe_identity.json")
    qe_chain_cache = _cache_path(cache_dir, fmspc, "qe_issuer_chain.pem")
    root_crl_cache = _cache_path(cache_dir, fmspc, "root_ca.crl")
    pck_crl_cache = _cache_path(cache_dir, fmspc, "pck.crl")
    pck_crl_chain_cache = _cache_path(cache_dir, fmspc, "pck_crl_issuer_chain.pem")

    all_cached = all(
        _is_cache_valid(p) for p in [
            tcb_cache, tcb_chain_cache, qe_cache, qe_chain_cache,
            root_crl_cache, pck_crl_cache, pck_crl_chain_cache
        ]
    )

    if all_cached and not force_refresh:
        if verbose:
            print(f"  Using cached collateral for FMSPC {fmspc}")
        return CollateralBundle(
            tcb_info=_load_from_cache(tcb_cache, as_json=True),
            tcb_info_issuer_chain=_load_from_cache(tcb_chain_cache).decode('utf-8'),
            qe_identity=_load_from_cache(qe_cache, as_json=True),
            qe_identity_issuer_chain=_load_from_cache(qe_chain_cache).decode('utf-8'),
            root_ca_crl=_load_from_cache(root_crl_cache),
            pck_crl=_load_from_cache(pck_crl_cache),
            pck_crl_issuer_chain=_load_from_cache(pck_crl_chain_cache).decode('utf-8'),
            root_ca_cert_pem=INTEL_SGX_ROOT_CA_PEM,
            fmspc=fmspc,
            fetched_at=datetime.fromtimestamp(os.path.getmtime(tcb_cache)).isoformat(),
            cached=True,
        )

    used_cache = False
    if verbose:
        print(f"  Fetching collateral from Intel PCS for FMSPC {fmspc}...")

    # Fetch TCB Info
    if verbose:
        print(f"    Fetching TCB Info...")
    tcb_info, tcb_chain = fetch_tcb_info(fmspc)
    _save_to_cache(tcb_cache, tcb_info)
    _save_to_cache(tcb_chain_cache, tcb_chain.encode('utf-8'))

    # Fetch QE Identity
    if verbose:
        print(f"    Fetching QE Identity...")
    qe_identity, qe_chain = fetch_qe_identity()
    _save_to_cache(qe_cache, qe_identity)
    _save_to_cache(qe_chain_cache, qe_chain.encode('utf-8'))

    # Fetch Root CA CRL
    if verbose:
        print(f"    Fetching Root CA CRL...")
    root_crl = fetch_root_ca_crl()
    _save_to_cache(root_crl_cache, root_crl)

    # Fetch PCK CRL
    if verbose:
        print(f"    Fetching PCK CRL...")
    pck_crl, pck_crl_chain = fetch_pck_crl()
    _save_to_cache(pck_crl_cache, pck_crl)
    _save_to_cache(pck_crl_chain_cache, pck_crl_chain.encode('utf-8'))

    if verbose:
        print(f"    ✓ All collateral cached to {cache_dir}")

    return CollateralBundle(
        tcb_info=tcb_info,
        tcb_info_issuer_chain=tcb_chain,
        qe_identity=qe_identity,
        qe_identity_issuer_chain=qe_chain,
        root_ca_crl=root_crl,
        pck_crl=pck_crl,
        pck_crl_issuer_chain=pck_crl_chain,
        root_ca_cert_pem=INTEL_SGX_ROOT_CA_PEM,
        fmspc=fmspc,
        fetched_at=datetime.now().isoformat(),
        cached=False,
    )


def extract_fmspc_from_pck_cert(pck_cert_pem: str) -> Optional[str]:
    """
    Extract FMSPC value from a PCK certificate's SGX Extensions.

    The FMSPC is embedded in the PCK certificate as an X.509 extension
    with OID 1.2.840.113741.1.13.1.4 (Intel SGX FMSPC).

    Args:
        pck_cert_pem: PEM-encoded PCK certificate

    Returns:
        FMSPC as hex string, or None if not found
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.x509.oid import ObjectIdentifier

        cert = x509.load_pem_x509_certificate(pck_cert_pem.encode())

        # Intel SGX FMSPC OID: 1.2.840.113741.1.13.1.4
        SGX_FMSPC_OID = ObjectIdentifier("1.2.840.113741.1.13.1.4")

        # The SGX extensions are in OID 1.2.840.113741.1.13.1
        SGX_EXTENSIONS_OID = ObjectIdentifier("1.2.840.113741.1.13.1")

        try:
            sgx_ext = cert.extensions.get_extension_for_oid(SGX_EXTENSIONS_OID)
            # Parse the ASN.1 structure to find FMSPC
            from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
            import asn1  # May not be available
        except Exception:
            pass

        # Fallback: search for the FMSPC OID pattern in the certificate DER
        der_bytes = cert.public_bytes(serialization.Encoding.DER)

        # The OID 1.2.840.113741.1.13.1.4 encodes as:
        # 06 09 2A 86 48 86 F8 4D 01 0D 01 04
        fmspc_oid_bytes = bytes([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x04])

        idx = der_bytes.find(fmspc_oid_bytes)
        if idx >= 0:
            # After OID comes the value (OCTET STRING with tag 0x04)
            val_offset = idx + len(fmspc_oid_bytes)
            # Skip tag and length
            if der_bytes[val_offset] == 0x04:  # OCTET STRING
                length = der_bytes[val_offset + 1]
                fmspc_bytes = der_bytes[val_offset + 2:val_offset + 2 + length]
                if len(fmspc_bytes) >= 6:
                    return fmspc_bytes[:6].hex()

        return None

    except Exception as e:
        print(f"  Warning: Could not extract FMSPC from PCK cert: {e}")
        return None


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Intel PCS Collateral Fetcher")
    parser.add_argument("fmspc", help="FMSPC hex string (e.g., 00806F050000)")
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR,
                        help="Cache directory")
    parser.add_argument("--force-refresh", action="store_true",
                        help="Force re-fetch from Intel PCS")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    print("=" * 70)
    print("Intel PCS Collateral Fetcher")
    print("=" * 70)
    print(f"\n  FMSPC:     {args.fmspc}")
    print(f"  Cache Dir: {args.cache_dir}")

    try:
        collateral = fetch_collateral(
            fmspc=args.fmspc,
            cache_dir=args.cache_dir,
            force_refresh=args.force_refresh,
            verbose=True,
        )

        print(f"\n  ✓ Collateral {'loaded from cache' if collateral.cached else 'fetched from Intel PCS'}")
        print(f"    Fetched at:    {collateral.fetched_at}")
        print(f"    TCB Info:      {'✓' if collateral.tcb_info else '✗'}")
        print(f"    QE Identity:   {'✓' if collateral.qe_identity else '✗'}")
        print(f"    Root CA CRL:   {len(collateral.root_ca_crl)} bytes")
        print(f"    PCK CRL:       {len(collateral.pck_crl)} bytes")

    except Exception as e:
        print(f"\n  ✗ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
