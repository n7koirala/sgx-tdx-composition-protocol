#!/usr/bin/env python3
"""
Cryptographic utilities for SGX-TDX Runtime Update System.

Handles:
- ASP signature verification (RSA/ECDSA)
- Enclave signing of audit logs
- Key management
"""

import hashlib
import base64
from typing import Tuple, Optional


# Try to import cryptography library
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: cryptography library not available, using fallback")


def verify_signature(public_key_pem: str, data: bytes, signature_b64: str) -> Tuple[bool, str]:
    """
    Verify a signature using the ASP's public key.
    
    Args:
        public_key_pem: PEM-encoded public key
        data: The data that was signed
        signature_b64: Base64-encoded signature
    
    Returns:
        (is_valid, error_message)
    """
    if not CRYPTO_AVAILABLE:
        return _fallback_verify(public_key_pem, data, signature_b64)
    
    try:
        # Decode signature
        signature = base64.b64decode(signature_b64)
        
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        # Verify based on key type
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            return False, f"Unsupported key type: {type(public_key)}"
        
        return True, None
        
    except InvalidSignature:
        return False, "Invalid signature"
    except Exception as e:
        return False, f"Verification error: {str(e)}"


def sign_data(private_key_pem: str, data: bytes) -> Tuple[Optional[str], str]:
    """
    Sign data using a private key.
    
    Args:
        private_key_pem: PEM-encoded private key
        data: Data to sign
    
    Returns:
        (signature_b64, error_message) - signature is None on error
    """
    if not CRYPTO_AVAILABLE:
        return _fallback_sign(private_key_pem, data)
    
    try:
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Sign based on key type
        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature = private_key.sign(
                data,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            return None, f"Unsupported key type: {type(private_key)}"
        
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        return signature_b64, None
        
    except Exception as e:
        return None, f"Signing error: {str(e)}"


def generate_key_pair(key_type: str = "rsa", key_size: int = 2048) -> Tuple[str, str, str]:
    """
    Generate a new key pair.
    
    Args:
        key_type: "rsa" or "ec"
        key_size: Key size (for RSA)
    
    Returns:
        (private_key_pem, public_key_pem, error_message)
    """
    if not CRYPTO_AVAILABLE:
        return None, None, "cryptography library not available"
    
    try:
        if key_type == "rsa":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
        elif key_type == "ec":
            private_key = ec.generate_private_key(
                ec.SECP256R1(),
                backend=default_backend()
            )
        else:
            return None, None, f"Unsupported key type: {key_type}"
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return private_pem, public_pem, None
        
    except Exception as e:
        return None, None, f"Key generation error: {str(e)}"


def load_public_key_from_file(filepath: str) -> Tuple[Optional[str], str]:
    """Load a public key from a PEM file."""
    try:
        with open(filepath, 'r') as f:
            pem = f.read()
        return pem, None
    except Exception as e:
        return None, f"Failed to load key: {str(e)}"


def load_private_key_from_file(filepath: str) -> Tuple[Optional[str], str]:
    """Load a private key from a PEM file."""
    try:
        with open(filepath, 'r') as f:
            pem = f.read()
        return pem, None
    except Exception as e:
        return None, f"Failed to load key: {str(e)}"


def compute_hash(data: bytes) -> str:
    """Compute SHA-256 hash of data, return as hex string."""
    return hashlib.sha256(data).hexdigest()


# =============================================================================
# Fallback implementations (for testing without cryptography library)
# =============================================================================

def _fallback_verify(public_key_pem: str, data: bytes, signature_b64: str) -> Tuple[bool, str]:
    """
    Fallback signature verification using HMAC.
    NOT SECURE - only for testing when cryptography library unavailable.
    """
    import hmac
    # Use first 32 bytes of public key as "key" (NOT SECURE)
    key = hashlib.sha256(public_key_pem.encode()).digest()
    expected = hmac.new(key, data, hashlib.sha256).digest()
    try:
        actual = base64.b64decode(signature_b64)
        if hmac.compare_digest(expected, actual):
            return True, None
        return False, "Invalid signature (fallback mode)"
    except:
        return False, "Invalid signature format"


def _fallback_sign(private_key_pem: str, data: bytes) -> Tuple[Optional[str], str]:
    """
    Fallback signing using HMAC.
    NOT SECURE - only for testing when cryptography library unavailable.
    """
    import hmac
    key = hashlib.sha256(private_key_pem.encode()).digest()
    sig = hmac.new(key, data, hashlib.sha256).digest()
    return base64.b64encode(sig).decode('utf-8'), None
