"""
Cryptographic utilities for the CVM commissioning phase.

Provides RSA key generation, signing/verification, encryption/decryption,
and ephemeral SSH key generation for CVM access.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
    load_pem_private_key,
)


def _to_bytes(data):
    """Convert string to bytes if necessary."""
    if not isinstance(data, bytes):
        data = bytes(data, "utf-8")
    return data


# ---------------------------------------------------------------------------
# Key Generation
# ---------------------------------------------------------------------------

def generate_rsa_keypair(key_size=4096):
    """Generate an RSA key pair.

    Returns:
        tuple: (public_key, private_key) as cryptography key objects.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return public_key, private_key


def generate_ephemeral_ssh_key():
    """Generate an ephemeral RSA key pair for SSH access to a CVM.

    The public key is serialized in OpenSSH format (for injection into
    GCP instance metadata). The private key is in PEM/OpenSSH format
    (for use with Paramiko).

    Returns:
        tuple: (serialized_public_key, serialized_private_key) as strings.
    """
    public_key, private_key = generate_rsa_keypair(key_size=4096)

    serialized_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode()

    serialized_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    return serialized_public_key, serialized_private_key


def serialize_public_key_pem(public_key):
    """Serialize an RSA public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def serialize_private_key_pem(private_key):
    """Serialize an RSA private key to PEM format (unencrypted)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ---------------------------------------------------------------------------
# Signing / Verification  (RSA-PSS with SHA-256)
# ---------------------------------------------------------------------------

def sign_data(data, private_key):
    """Sign data with an RSA private key using PSS padding."""
    data = _to_bytes(data)
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def verify_signature(signature, data, public_key):
    """Verify an RSA-PSS signature. Returns True if valid, False otherwise."""
    data = _to_bytes(data)
    signature = _to_bytes(signature)
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def verify_signature_with_pem(signature, data, public_key_pem):
    """Verify signature using a PEM-encoded public key."""
    public_key_pem = _to_bytes(public_key_pem)
    public_key = load_pem_public_key(public_key_pem)
    return verify_signature(signature, data, public_key)


# ---------------------------------------------------------------------------
# Encryption / Decryption  (RSA-OAEP with SHA-256)
# ---------------------------------------------------------------------------

def encrypt_data(data, public_key):
    """Encrypt data with an RSA public key using OAEP padding."""
    data = _to_bytes(data)
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_data(encrypted_data, private_key):
    """Decrypt data with an RSA private key using OAEP padding."""
    encrypted_data = _to_bytes(encrypted_data)
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
