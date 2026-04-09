"""
Generate RSA key pair for the ASP (Application Service Provider).

The ASP signs privileged requests to the SGX controller with their
private key. The controller verifies the signature using the public key.

Outputs:
    commissioning_phase/asp_private_key          — ASP private key (keep secret!)
    commissioning_phase/asp_pub_keys/asp_private_key.pub  — ASP public key (for controller)

Usage:
    python3 -m commissioning_phase.generate_asp_keys
"""

import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def main():
    base_dir = os.path.dirname(__file__)

    # Generate 4096-bit RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # Serialize private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Serialize public key
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Write private key
    private_key_path = os.path.join(base_dir, "asp_private_key")
    with open(private_key_path, "wb") as f:
        f.write(private_key_pem)
    os.chmod(private_key_path, 0o600)
    print(f"✓ ASP private key saved to: {private_key_path}")

    # Write public key
    pub_key_dir = os.path.join(base_dir, "asp_pub_keys")
    os.makedirs(pub_key_dir, exist_ok=True)
    pub_key_path = os.path.join(pub_key_dir, "asp_private_key.pub")
    with open(pub_key_path, "wb") as f:
        f.write(public_key_pem)
    print(f"✓ ASP public key saved to:  {pub_key_path}")
    print()
    print("The public key will be loaded by the SGX controller to verify")
    print("your requests. Keep the private key secret!")


if __name__ == "__main__":
    main()
