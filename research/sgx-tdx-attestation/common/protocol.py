"""
Hierarchical TEE Attestation Protocol - Shared Protocol Definitions

This module contains shared message formats and utilities used by both
the TDX attestation server and SGX enclave verifier.

Protocol Overview:
    1. SGX Enclave generates a nonce and sends AttestationRequest
    2. TDX Server receives request, generates quote with nonce in report_data
    3. TDX Server returns AttestationResponse with JWT token
    4. SGX Enclave verifies token (issuer, expiry, nonce binding)
"""

import json
import base64
import secrets
import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

# Protocol version for compatibility checks
PROTOCOL_VERSION = "1.0"

# Default configuration
DEFAULT_PORT = 8443
NONCE_SIZE = 32  # bytes


@dataclass
class AttestationRequest:
    """
    Attestation challenge sent from SGX Enclave to TDX Server.
    
    The nonce ensures freshness and prevents replay attacks.
    It will be bound into the TDX quote's report_data.
    """
    action: str = "attest"
    nonce: str = ""  # Base64 encoded 32-byte nonce
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
    def from_json(cls, data: str) -> 'AttestationRequest':
        d = json.loads(data)
        return cls(
            action=d.get("action", "attest"),
            nonce=d.get("nonce", ""),
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
    
    Contains the Intel Trust Authority JWT token with the nonce
    bound in the TDX quote's report_data.
    """
    status: str = "success"  # "success" or "error"
    token: str = ""          # JWT token from Intel Trust Authority
    nonce_echo: str = ""     # Echo of the received nonce
    mrtd: str = ""           # TD Measurement for quick reference
    error: str = ""          # Error message if status is "error"
    protocol_version: str = PROTOCOL_VERSION
    timestamp: float = field(default_factory=time.time)
    
    def to_json(self) -> str:
        return json.dumps({
            "status": self.status,
            "token": self.token,
            "nonce_echo": self.nonce_echo,
            "mrtd": self.mrtd,
            "error": self.error,
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
    warnings: list = field(default_factory=list)
    error: str = ""
    verification_time_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "verified": self.verified,
            "verdict": self.verdict,
            "mrtd": self.mrtd,
            "tcb_status": self.tcb_status,
            "is_debuggable": self.is_debuggable,
            "checks": {
                "nonce": self.nonce_verified,
                "issuer": self.issuer_verified,
                "expiry": self.expiry_verified
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
