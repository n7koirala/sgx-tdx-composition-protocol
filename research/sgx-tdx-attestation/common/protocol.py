"""
Hierarchical TEE Attestation Protocol - Shared Protocol Definitions

This module contains shared message formats and utilities used by both
the TDX attestation server and SGX enclave verifier.

Protocol Overview:
    1. SGX Enclave generates a nonce and sends AttestationRequest
    2. TDX Server receives request, generates quote with nonce in report_data
    3. TDX Server returns AttestationResponse with JWT token or raw DCAP quote
    4. SGX Enclave verifies token (ITA) or quote signature (DCAP)

Attestation Methods:
    - "ita":  Intel Trust Authority — cloud-based JWT verification
    - "dcap": Local DCAP — libtdx_attest quote + local ECDSA verification
"""

import json
import struct
import base64
import secrets
import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime

# Protocol version for compatibility checks
PROTOCOL_VERSION = "1.0"

# Default configuration
DEFAULT_PORT = 8443
NONCE_SIZE = 32  # bytes

# Attestation methods
METHOD_ITA = "ita"     # Intel Trust Authority (cloud JWT)
METHOD_DCAP = "dcap"   # Local DCAP (libtdx_attest + ECDSA verification)
VALID_METHODS = (METHOD_ITA, METHOD_DCAP)


@dataclass
class AttestationRequest:
    """
    Attestation challenge sent from SGX Enclave to TDX Server.
    
    The nonce ensures freshness and prevents replay attacks.
    It will be bound into the TDX quote's report_data.
    """
    action: str = "attest"
    nonce: str = ""  # Base64 encoded 32-byte nonce
    attestation_method: str = METHOD_ITA  # "ita" or "dcap"
    protocol_version: str = PROTOCOL_VERSION
    timestamp: float = field(default_factory=time.time)
    
    def to_json(self) -> str:
        return json.dumps({
            "action": self.action,
            "nonce": self.nonce,
            "attestation_method": self.attestation_method,
            "protocol_version": self.protocol_version,
            "timestamp": self.timestamp
        })
    
    @classmethod
    def from_json(cls, data: str) -> 'AttestationRequest':
        d = json.loads(data)
        return cls(
            action=d.get("action", "attest"),
            nonce=d.get("nonce", ""),
            attestation_method=d.get("attestation_method", METHOD_ITA),
            protocol_version=d.get("protocol_version", PROTOCOL_VERSION),
            timestamp=d.get("timestamp", time.time())
        )
    
    def validate(self) -> Tuple[bool, str]:
        """Validate the request fields"""
        if self.action != "attest":
            return False, f"Unknown action: {self.action}"
        
        if not self.nonce:
            return False, "Missing nonce"
        
        try:
            nonce_bytes = base64.b64decode(self.nonce)
            if len(nonce_bytes) != NONCE_SIZE:
                return False, f"Invalid nonce size: expected {NONCE_SIZE}, got {len(nonce_bytes)}"
        except Exception as e:
            return False, f"Invalid nonce encoding: {e}"
        
        return True, "OK"


@dataclass
class AttestationResponse:
    """
    Attestation response from TDX Server to SGX Enclave.
    
    Contains either:
    - ITA mode: JWT token from Intel Trust Authority
    - DCAP mode: Raw TDX quote (base64-encoded) for local verification
    """
    status: str = "success"  # "success" or "error"
    token: str = ""          # JWT token from Intel Trust Authority (ITA mode)
    nonce_echo: str = ""     # Echo of the received nonce
    mrtd: str = ""           # TD Measurement for quick reference
    error: str = ""          # Error message if status is "error"
    attestation_method: str = METHOD_ITA  # Which method was used
    raw_quote: str = ""      # Base64-encoded raw TDX quote (DCAP mode)
    protocol_version: str = PROTOCOL_VERSION
    timestamp: float = field(default_factory=time.time)
    
    def to_json(self) -> str:
        return json.dumps({
            "status": self.status,
            "token": self.token,
            "nonce_echo": self.nonce_echo,
            "mrtd": self.mrtd,
            "error": self.error,
            "attestation_method": self.attestation_method,
            "raw_quote": self.raw_quote,
            "protocol_version": self.protocol_version,
            "timestamp": self.timestamp
        })
    
    @classmethod
    def from_json(cls, data: str) -> 'AttestationResponse':
        d = json.loads(data)
        return cls(
            status=d.get("status", "error"),
            token=d.get("token", ""),
            nonce_echo=d.get("nonce_echo", ""),
            mrtd=d.get("mrtd", ""),
            error=d.get("error", ""),
            attestation_method=d.get("attestation_method", METHOD_ITA),
            raw_quote=d.get("raw_quote", ""),
            protocol_version=d.get("protocol_version", PROTOCOL_VERSION),
            timestamp=d.get("timestamp", time.time())
        )
    
    @classmethod
    def error_response(cls, error_msg: str) -> 'AttestationResponse':
        """Create an error response"""
        return cls(status="error", error=error_msg)


@dataclass
class VerificationResult:
    """
    Result of TDX attestation verification by SGX Enclave.
    """
    verified: bool = False
    verdict: str = ""  # "TRUSTED", "UNTRUSTED", "ERROR"
    mrtd: str = ""
    tcb_status: str = ""
    is_debuggable: bool = False
    nonce_verified: bool = False
    issuer_verified: bool = False
    expiry_verified: bool = False
    signature_verified: bool = False  # DCAP: ECDSA signature check
    attestation_method: str = ""     # Which method was used
    warnings: list = field(default_factory=list)
    error: str = ""
    verification_time_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "verified": self.verified,
            "verdict": self.verdict,
            "attestation_method": self.attestation_method,
            "mrtd": self.mrtd,
            "tcb_status": self.tcb_status,
            "is_debuggable": self.is_debuggable,
            "checks": {
                "nonce": self.nonce_verified,
                "issuer": self.issuer_verified,
                "expiry": self.expiry_verified,
                "signature": self.signature_verified,
            },
            "warnings": self.warnings,
            "error": self.error,
            "verification_time_ms": self.verification_time_ms
        }


def generate_nonce() -> str:
    """
    Generate a cryptographically secure nonce for attestation challenge.
    
    Returns:
        Base64-encoded 32-byte nonce
    """
    nonce_bytes = secrets.token_bytes(NONCE_SIZE)
    return base64.b64encode(nonce_bytes).decode('ascii')


def verify_nonce_binding(expected_nonce: str, report_data: str, debug: bool = False) -> bool:
    """
    Verify that the nonce is properly bound in the TDX report_data.
    
    The TDX attestation process encodes the nonce (or its hash) in the
    report_data field of the quote. The trustauthority-cli takes user_data
    as a string and encodes it as UTF-8 bytes in the report_data.
    
    Args:
        expected_nonce: Base64-encoded nonce that was sent
        report_data: report_data from TDX token (hex string)
        debug: Enable debug output
    
    Returns:
        True if nonce is properly bound, False otherwise
    """
    try:
        if not report_data:
            if debug:
                print(f"[DEBUG] report_data is empty")
            return False
        
        # Decode report_data from hex
        try:
            report_data_bytes = bytes.fromhex(report_data)
        except ValueError:
            # Try base64 decoding
            try:
                report_data_bytes = base64.b64decode(report_data)
            except:
                if debug:
                    print(f"[DEBUG] Could not decode report_data")
                return False
        
        if debug:
            print(f"[DEBUG] report_data (first 64 bytes): {report_data_bytes[:64]}")
            print(f"[DEBUG] expected_nonce[:32]: {expected_nonce[:32]}")
        
        # The TDX server passes nonce[:32] to trustauthority-cli as user_data
        # This gets encoded as UTF-8 bytes in the report_data
        nonce_prefix = expected_nonce[:32]
        nonce_prefix_bytes = nonce_prefix.encode('utf-8')
        
        # Check if the nonce prefix appears in report_data
        if nonce_prefix_bytes in report_data_bytes:
            if debug:
                print(f"[DEBUG] Found nonce prefix in report_data")
            return True
        
        # Also check for the full nonce (in case it fits)
        if len(expected_nonce) <= 64:  # Max report_data is 64 bytes
            nonce_full_bytes = expected_nonce.encode('utf-8')
            if nonce_full_bytes in report_data_bytes:
                if debug:
                    print(f"[DEBUG] Found full nonce in report_data")
                return True
        
        # Check if the decoded nonce bytes appear
        nonce_bytes = base64.b64decode(expected_nonce)
        if nonce_bytes in report_data_bytes:
            if debug:
                print(f"[DEBUG] Found decoded nonce bytes in report_data")
            return True
        
        # Check first 32 bytes of decoded nonce
        if nonce_bytes[:32] in report_data_bytes:
            if debug:
                print(f"[DEBUG] Found first 32 bytes of decoded nonce in report_data")
            return True
        
        if debug:
            print(f"[DEBUG] Nonce not found in report_data")
            print(f"[DEBUG] report_data hex: {report_data[:128]}...")
        
        return False
        
    except Exception as e:
        print(f"Nonce verification error: {e}")
        return False


def decode_jwt_payload(token: str) -> Dict[str, Any]:
    """
    Decode the payload from a JWT token (without signature verification).
    
    Args:
        token: JWT token string
    
    Returns:
        Decoded payload as dictionary
    """
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    
    # Decode payload (second part)
    payload_b64 = parts[1]
    # Add padding if needed
    padded = payload_b64 + '=' * (4 - len(payload_b64) % 4)
    payload_bytes = base64.urlsafe_b64decode(padded)
    return json.loads(payload_bytes)


def verify_jwt_simple(token: str, expected_issuer_substring: str = "trustauthority.intel.com") -> Tuple[bool, Dict[str, Any], str]:
    """
    Perform simple JWT verification (issuer + expiry, no signature check).
    
    This is a lightweight verification suitable for research purposes.
    For production, use cryptographic signature verification.
    
    Args:
        token: JWT token string
        expected_issuer_substring: Substring that must appear in issuer
    
    Returns:
        Tuple of (is_valid, payload_dict, error_message)
    """
    try:
        payload = decode_jwt_payload(token)
        
        # Check issuer
        issuer = payload.get('iss', '')
        if expected_issuer_substring not in issuer:
            return False, payload, f"Invalid issuer: {issuer}"
        
        # Check expiry
        exp = payload.get('exp', 0)
        now = time.time()
        if exp < now:
            return False, payload, f"Token expired at {datetime.fromtimestamp(exp).isoformat()}"
        
        return True, payload, "OK"
        
    except Exception as e:
        return False, {}, str(e)


class ProtocolError(Exception):
    """Custom exception for protocol errors"""
    pass


def create_tls_context_server(cert_file: str, key_file: str,
                               ca_cert_file: str = None,
                               require_client_cert: bool = False):
    """
    Create TLS context for server (TDX attestation server) with optional mTLS.
    
    Args:
        cert_file: Path to server certificate
        key_file: Path to server private key
        ca_cert_file: Path to CA certificate for client verification (required for mTLS)
        require_client_cert: If True, require client to present valid certificate
    
    Returns:
        ssl.SSLContext configured for server with optional client auth
    """
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    # mTLS: Require client certificate verification
    if require_client_cert:
        if not ca_cert_file:
            raise ValueError("CA certificate required for mTLS (require_client_cert=True)")
        context.load_verify_locations(ca_cert_file)
        context.verify_mode = ssl.CERT_REQUIRED  # Client MUST present valid cert
        print(f"[mTLS] Server will require client certificates signed by CA")
    
    return context


def create_tls_context_client(ca_cert_file: str = None, 
                               client_cert_file: str = None,
                               client_key_file: str = None,
                               verify: bool = True):
    """
    Create TLS context for client (SGX enclave) with optional mTLS.
    
    Args:
        ca_cert_file: Path to CA certificate for server verification
        client_cert_file: Path to client certificate (for mTLS)
        client_key_file: Path to client private key (for mTLS)
        verify: Whether to verify server certificate
    
    Returns:
        ssl.SSLContext configured for client with optional client auth
    """
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    
    # Verify server certificate
    if verify and ca_cert_file:
        context.load_verify_locations(ca_cert_file)
        context.check_hostname = False  # Self-signed certs won't match hostname
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    
    # mTLS: Present client certificate to server
    if client_cert_file and client_key_file:
        context.load_cert_chain(client_cert_file, client_key_file)
        print(f"[mTLS] Client will present certificate for authentication")
    
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


# Message framing for TCP stream
MESSAGE_DELIMITER = b'\n---END---\n'

def send_message(sock, message: str):
    """Send a framed message over socket"""
    data = message.encode('utf-8') + MESSAGE_DELIMITER
    sock.sendall(data)

def receive_message(sock, timeout: float = 30.0) -> str:
    """Receive a framed message from socket"""
    sock.settimeout(timeout)
    buffer = b""
    while MESSAGE_DELIMITER not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buffer += chunk
        if len(buffer) > 100000:  # 100KB max
            raise ProtocolError("Message too large")
    
    if MESSAGE_DELIMITER in buffer:
        message, _ = buffer.split(MESSAGE_DELIMITER, 1)
        return message.decode('utf-8')
    
    raise ProtocolError("Incomplete message received")


# ─── DCAP Quote Verification ─────────────────────────────────────────────────

# TDX Quote v4 layout constants
QUOTE_HEADER_SIZE = 48
QUOTE_BODY_SIZE = 584
SIGNED_DATA_SIZE = QUOTE_HEADER_SIZE + QUOTE_BODY_SIZE  # 632
TEE_TYPE_TDX = 0x00000081

# Offsets within TD Quote Body (relative to body start)
BODY_TEE_TCB_SVN_OFFSET = 0       # 16 bytes
BODY_MRSEAM_OFFSET = 16           # 48 bytes
BODY_MRSIGNERSEAM_OFFSET = 64    # 48 bytes
BODY_SEAMATTRIBUTES_OFFSET = 112  # 8 bytes
BODY_TDATTRIBUTES_OFFSET = 120   # 8 bytes
BODY_XFAM_OFFSET = 128           # 8 bytes
BODY_MRTD_OFFSET = 136           # 48 bytes
BODY_MRCONFIGID_OFFSET = 184    # 48 bytes
BODY_MROWNER_OFFSET = 232        # 48 bytes
BODY_MROWNERCONFIG_OFFSET = 280  # 48 bytes
BODY_RTMR0_OFFSET = 328          # 48 bytes
BODY_RTMR1_OFFSET = 376          # 48 bytes
BODY_RTMR2_OFFSET = 424          # 48 bytes
BODY_RTMR3_OFFSET = 472          # 48 bytes
BODY_REPORTDATA_OFFSET = 520     # 64 bytes


@dataclass
class DCAPQuoteInfo:
    """Parsed information from a DCAP TDX quote."""
    version: int = 0
    tee_type: int = 0
    mrtd: str = ""
    rtmr0: str = ""
    rtmr1: str = ""
    rtmr2: str = ""
    rtmr3: str = ""
    report_data: bytes = b""
    td_attributes: str = ""
    tee_tcb_svn: str = ""
    mrseam: str = ""
    quote_size: int = 0
    signature_valid: bool = False


def parse_dcap_quote(quote_bytes: bytes) -> DCAPQuoteInfo:
    """
    Parse a raw TDX v4 DCAP quote to extract measurements and report_data.
    
    Args:
        quote_bytes: Raw binary TDX quote
    
    Returns:
        DCAPQuoteInfo with extracted fields
    """
    info = DCAPQuoteInfo(quote_size=len(quote_bytes))
    
    if len(quote_bytes) < SIGNED_DATA_SIZE + 4:
        raise ValueError(f"Quote too short: {len(quote_bytes)} bytes (need >= {SIGNED_DATA_SIZE + 4})")
    
    # Parse header (48 bytes)
    info.version = struct.unpack_from('<H', quote_bytes, 0)[0]
    # att_key_type at offset 2 (2 bytes)
    info.tee_type = struct.unpack_from('<I', quote_bytes, 4)[0]
    
    if info.tee_type != TEE_TYPE_TDX:
        raise ValueError(f"Not a TDX quote: TEE type = 0x{info.tee_type:08x}")
    
    # Parse TD Quote Body (584 bytes starting at offset 48)
    body = quote_bytes[QUOTE_HEADER_SIZE:]
    
    info.tee_tcb_svn = body[BODY_TEE_TCB_SVN_OFFSET:BODY_TEE_TCB_SVN_OFFSET + 16].hex()
    info.mrseam = body[BODY_MRSEAM_OFFSET:BODY_MRSEAM_OFFSET + 48].hex()
    info.td_attributes = body[BODY_TDATTRIBUTES_OFFSET:BODY_TDATTRIBUTES_OFFSET + 8].hex()
    info.mrtd = body[BODY_MRTD_OFFSET:BODY_MRTD_OFFSET + 48].hex()
    info.rtmr0 = body[BODY_RTMR0_OFFSET:BODY_RTMR0_OFFSET + 48].hex()
    info.rtmr1 = body[BODY_RTMR1_OFFSET:BODY_RTMR1_OFFSET + 48].hex()
    info.rtmr2 = body[BODY_RTMR2_OFFSET:BODY_RTMR2_OFFSET + 48].hex()
    info.rtmr3 = body[BODY_RTMR3_OFFSET:BODY_RTMR3_OFFSET + 48].hex()
    info.report_data = body[BODY_REPORTDATA_OFFSET:BODY_REPORTDATA_OFFSET + 64]
    
    return info


def verify_dcap_signature(quote_bytes: bytes) -> Tuple[bool, str]:
    """
    Verify the ECDSA-P256 signature on a TDX DCAP quote.
    
    The attestation key signs SHA-256(Header || TD Quote Body) — the first 632 bytes.
    Signature (r||s, 64 bytes) is at offset 636, attestation key (x||y, 64 bytes) at 700.
    
    Args:
        quote_bytes: Raw binary TDX quote
    
    Returns:
        Tuple of (is_valid, message)
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        return False, "cryptography library not installed"
    
    # Signature data length at offset 632 (4 bytes, little-endian)
    sig_data_len = struct.unpack_from('<I', quote_bytes, SIGNED_DATA_SIZE)[0]
    sig_offset = SIGNED_DATA_SIZE + 4
    
    if len(quote_bytes) < sig_offset + 128:
        return False, f"Quote too short for signature data: {len(quote_bytes)} bytes"
    
    # Extract signature (r || s, 64 bytes) and attestation key (x || y, 64 bytes)
    sig_r_s = quote_bytes[sig_offset:sig_offset + 64]
    att_key_xy = quote_bytes[sig_offset + 64:sig_offset + 128]
    
    # Reconstruct public key
    r = int.from_bytes(sig_r_s[:32], 'big')
    s = int.from_bytes(sig_r_s[32:64], 'big')
    
    x = att_key_xy[:32]
    y = att_key_xy[32:64]
    
    try:
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), b'\x04' + x + y
        )
        
        # Encode signature in DER format
        der_sig = utils.encode_dss_signature(r, s)
        
        # Signed data is Header (48 bytes) + TD Quote Body (584 bytes)
        signed_data = quote_bytes[:SIGNED_DATA_SIZE]
        
        # Verify
        public_key.verify(der_sig, signed_data, ec.ECDSA(hashes.SHA256()))
        return True, "OK"
        
    except Exception as e:
        return False, f"Signature verification failed: {e}"


def verify_dcap_nonce(quote_bytes: bytes, expected_nonce: str, debug: bool = False) -> Tuple[bool, str]:
    """
    Verify that the nonce is properly bound in the DCAP quote's report_data.
    
    For DCAP mode, the nonce bytes (from base64 decode) are written directly
    into the report_data field of the TDX quote, left-padded with zeros if
    shorter than 64 bytes.
    
    Args:
        quote_bytes: Raw binary TDX quote
        expected_nonce: Base64-encoded nonce that was sent
        debug: Enable debug output
    
    Returns:
        Tuple of (is_valid, message)
    """
    # Extract report_data from quote body
    body_start = QUOTE_HEADER_SIZE
    report_data = quote_bytes[body_start + BODY_REPORTDATA_OFFSET:
                              body_start + BODY_REPORTDATA_OFFSET + 64]
    
    # Decode expected nonce from base64
    try:
        nonce_bytes = base64.b64decode(expected_nonce)
    except Exception:
        return False, "Could not decode nonce from base64"
    
    if debug:
        print(f"[DEBUG] report_data hex: {report_data.hex()}")
        print(f"[DEBUG] nonce bytes hex: {nonce_bytes.hex()}")
    
    # Check 1: Exact match (nonce was zero-padded to 64 bytes)
    expected_padded = nonce_bytes + b'\x00' * (64 - len(nonce_bytes))
    if report_data == expected_padded[:64]:
        return True, "Nonce matches (zero-padded)"
    
    # Check 2: Nonce bytes appear as prefix
    if report_data[:len(nonce_bytes)] == nonce_bytes:
        return True, "Nonce matches (prefix)"
    
    # Check 3: Nonce bytes appear anywhere
    if nonce_bytes in report_data:
        return True, "Nonce found in report_data"
    
    # Check 4: SHA-256 of nonce in report_data (some implementations hash it)
    nonce_hash = hashlib.sha256(nonce_bytes).digest()
    if nonce_hash in report_data or report_data[:32] == nonce_hash:
        return True, "Nonce hash matches in report_data"
    
    # Check 5: UTF-8 encoded nonce string (as trustauthority-cli does)
    nonce_str_bytes = expected_nonce[:32].encode('utf-8')
    if nonce_str_bytes in report_data:
        return True, "Nonce string found in report_data"
    
    return False, "Nonce not found in report_data"


def verify_dcap_quote(quote_bytes: bytes, expected_nonce: str = None,
                      debug: bool = False) -> VerificationResult:
    """
    Perform full DCAP verification of a raw TDX quote.
    
    Checks:
    1. Parse quote structure (version, TEE type)
    2. Verify ECDSA-P256 signature
    3. Verify nonce binding in report_data (if nonce provided)
    4. Extract measurements (MRTD, RTMRs)
    
    Args:
        quote_bytes: Raw binary TDX quote
        expected_nonce: Base64-encoded nonce (optional)
        debug: Enable debug output
    
    Returns:
        VerificationResult with verdict and details
    """
    result = VerificationResult()
    result.attestation_method = METHOD_DCAP
    start = time.time()
    
    try:
        # Step 1: Parse quote
        info = parse_dcap_quote(quote_bytes)
        result.mrtd = info.mrtd
        result.tcb_status = f"TEE_TCB_SVN={info.tee_tcb_svn}"
        
        # Check debug flag from TD attributes
        td_attr = int.from_bytes(bytes.fromhex(info.td_attributes), 'little')
        result.is_debuggable = bool(td_attr & 0x01)
        
        if debug:
            print(f"[DCAP] Quote: v{info.version}, {info.quote_size} bytes, TEE=0x{info.tee_type:08x}")
            print(f"[DCAP] MRTD: {info.mrtd[:32]}...")
        
        # Step 2: Verify ECDSA signature
        sig_valid, sig_msg = verify_dcap_signature(quote_bytes)
        result.signature_verified = sig_valid
        
        if not sig_valid:
            result.error = f"Signature verification failed: {sig_msg}"
            result.verdict = "UNTRUSTED"
            result.verification_time_ms = (time.time() - start) * 1000
            return result
        
        if debug:
            print(f"[DCAP] ✓ ECDSA signature valid")
        
        # DCAP doesn't use JWT, so issuer/expiry don't apply — mark as N/A
        result.issuer_verified = True  # N/A for DCAP, but not a failure
        result.expiry_verified = True  # N/A for DCAP
        
        # Step 3: Verify nonce binding
        if expected_nonce:
            nonce_valid, nonce_msg = verify_dcap_nonce(quote_bytes, expected_nonce, debug=debug)
            result.nonce_verified = nonce_valid
            
            if not nonce_valid:
                result.error = f"Nonce binding failed: {nonce_msg}"
                result.verdict = "UNTRUSTED"
                result.warnings.append("Possible replay attack or binding failure")
                result.verification_time_ms = (time.time() - start) * 1000
                return result
            
            if debug:
                print(f"[DCAP] ✓ Nonce bound: {nonce_msg}")
        else:
            result.nonce_verified = True  # No nonce to check
            result.warnings.append("No nonce verification (none provided)")
        
        # Step 4: Add warnings
        if result.is_debuggable:
            result.warnings.append("TD is debuggable - not for production!")
        
        # All checks passed
        result.verified = True
        result.verdict = "TRUSTED"
        
    except Exception as e:
        result.error = str(e)
        result.verdict = "ERROR"
    
    result.verification_time_ms = (time.time() - start) * 1000
    return result


# ─── Multi-Controller Protocol ───────────────────────────────────────────────

@dataclass
class EndUserRequest:
    """
    Request from an end-user to an SGX controller.
    
    The end-user sends a fresh nonce. The controller responds with
    a ControllerToken containing cached TDX verification results
    and the controller's SGX identity.
    """
    action: str = "verify"
    nonce: str = ""               # Base64-encoded 32-byte nonce
    protocol_version: str = PROTOCOL_VERSION
    timestamp: float = field(default_factory=time.time)
    
    def to_json(self) -> str:
        return json.dumps({
            "action": self.action,
            "nonce": self.nonce,
            "protocol_version": self.protocol_version,
            "timestamp": self.timestamp
        })
    
    @classmethod
    def from_json(cls, data: str) -> 'EndUserRequest':
        d = json.loads(data)
        return cls(
            action=d.get("action", "verify"),
            nonce=d.get("nonce", ""),
            protocol_version=d.get("protocol_version", PROTOCOL_VERSION),
            timestamp=d.get("timestamp", time.time())
        )
    
    def validate(self) -> Tuple[bool, str]:
        if not self.nonce:
            return False, "Missing nonce"
        if self.action != "verify":
            return False, f"Unknown action: {self.action}"
        return True, ""


@dataclass
class ControllerToken:
    """
    Token returned by an SGX controller to an end-user.
    
    Contains:
    - Cached TDX verification result (attestation method, MRTD, verdict)
    - Controller identity (controller_id, SGX MRENCLAVE)
    - Freshness proof (end-user nonce echo, controller timestamp)
    - TDX quote hash (so end-user can verify what was checked)
    
    Trust model: End-user verifies the controller's SGX quote,
    then trusts the TDX verification result transitively.
    """
    status: str = "success"
    
    # Controller identity
    controller_id: str = ""
    controller_port: int = 0
    
    # Cached TDX verification
    tdx_verified: bool = False
    tdx_verdict: str = ""          # "TRUSTED", "UNTRUSTED", "ERROR", "PENDING"
    tdx_mrtd: str = ""             # TD Measurement
    tdx_attestation_method: str = "" # "ita" or "dcap"
    tdx_verification_time: float = 0.0  # When TDX was last verified (epoch)
    tdx_quote_hash: str = ""       # SHA-256 of raw TDX quote (for auditability)
    tdx_tcb_status: str = ""
    tdx_is_debuggable: bool = False
    
    # End-user nonce binding
    nonce_echo: str = ""           # Echo of end-user's nonce
    nonce_hash: str = ""           # SHA-256(nonce) — proves controller saw nonce
    
    # Error handling
    error: str = ""
    warnings: List[str] = field(default_factory=list)
    
    protocol_version: str = PROTOCOL_VERSION
    timestamp: float = field(default_factory=time.time)
    
    def to_json(self) -> str:
        return json.dumps({
            "status": self.status,
            "controller_id": self.controller_id,
            "controller_port": self.controller_port,
            "tdx_verified": self.tdx_verified,
            "tdx_verdict": self.tdx_verdict,
            "tdx_mrtd": self.tdx_mrtd,
            "tdx_attestation_method": self.tdx_attestation_method,
            "tdx_verification_time": self.tdx_verification_time,
            "tdx_quote_hash": self.tdx_quote_hash,
            "tdx_tcb_status": self.tdx_tcb_status,
            "tdx_is_debuggable": self.tdx_is_debuggable,
            "nonce_echo": self.nonce_echo,
            "nonce_hash": self.nonce_hash,
            "error": self.error,
            "warnings": self.warnings,
            "protocol_version": self.protocol_version,
            "timestamp": self.timestamp
        })
    
    @classmethod
    def from_json(cls, data: str) -> 'ControllerToken':
        d = json.loads(data)
        return cls(
            status=d.get("status", "error"),
            controller_id=d.get("controller_id", ""),
            controller_port=d.get("controller_port", 0),
            tdx_verified=d.get("tdx_verified", False),
            tdx_verdict=d.get("tdx_verdict", ""),
            tdx_mrtd=d.get("tdx_mrtd", ""),
            tdx_attestation_method=d.get("tdx_attestation_method", ""),
            tdx_verification_time=d.get("tdx_verification_time", 0.0),
            tdx_quote_hash=d.get("tdx_quote_hash", ""),
            tdx_tcb_status=d.get("tdx_tcb_status", ""),
            tdx_is_debuggable=d.get("tdx_is_debuggable", False),
            nonce_echo=d.get("nonce_echo", ""),
            nonce_hash=d.get("nonce_hash", ""),
            error=d.get("error", ""),
            warnings=d.get("warnings", []),
            protocol_version=d.get("protocol_version", PROTOCOL_VERSION),
            timestamp=d.get("timestamp", time.time())
        )
    
    @classmethod
    def error_response(cls, error_msg: str) -> 'ControllerToken':
        return cls(status="error", error=error_msg, tdx_verdict="ERROR")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "controller_id": self.controller_id,
            "tdx": {
                "verified": self.tdx_verified,
                "verdict": self.tdx_verdict,
                "mrtd": self.tdx_mrtd,
                "method": self.tdx_attestation_method,
                "verification_time": self.tdx_verification_time,
                "quote_hash": self.tdx_quote_hash,
                "tcb_status": self.tdx_tcb_status,
                "is_debuggable": self.tdx_is_debuggable,
            },
            "nonce_echo": self.nonce_echo,
            "nonce_hash": self.nonce_hash,
            "warnings": self.warnings,
            "error": self.error,
            "timestamp": self.timestamp,
        }

