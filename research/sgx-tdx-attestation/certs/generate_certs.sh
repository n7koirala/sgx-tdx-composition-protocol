#!/bin/bash
# Generate TLS Certificates for Hierarchical TEE Attestation
#
# Creates self-signed certificates for secure SGX <-> TDX communication.
#
# Output files:
#   ca.key      - CA private key
#   ca.crt      - CA certificate (install on SGX machine)
#   server.key  - TDX server private key
#   server.crt  - TDX server certificate
#
# Usage:
#   ./generate_certs.sh [TDX_IP_OR_HOSTNAME]
#
# Example:
#   ./generate_certs.sh 192.168.1.100
#   ./generate_certs.sh tdx-vm.local

set -e

CERT_DIR="$(dirname "$0")"
cd "$CERT_DIR"

# TDX server hostname/IP for certificate CN and SAN
TDX_HOST="${1:-localhost}"

# Certificate validity (days)
VALIDITY=365

echo "======================================"
echo "TLS Certificate Generation"
echo "======================================"
echo "TDX Host: $TDX_HOST"
echo "Output:   $CERT_DIR"
echo ""

# Step 1: Generate CA private key
echo "[1/4] Generating CA private key..."
openssl genrsa -out ca.key 4096
echo "      ✓ ca.key generated"

# Step 2: Generate CA certificate
echo "[2/4] Generating CA certificate..."
openssl req -new -x509 -days $VALIDITY -key ca.key -out ca.crt \
    -subj "/C=US/ST=Research/L=Lab/O=Hierarchical-TEE/OU=CA/CN=Hierarchical-TEE-CA"
echo "      ✓ ca.crt generated"

# Step 3: Generate server private key
echo "[3/4] Generating server private key..."
openssl genrsa -out server.key 2048
echo "      ✓ server.key generated"

# Step 4: Generate server certificate signing request and certificate
echo "[4/4] Generating server certificate..."

# Create config for SAN (Subject Alternative Name)
cat > server_ext.cnf << EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
C = US
ST = Research
L = Lab
O = Hierarchical-TEE
OU = TDX-Attestation-Server
CN = $TDX_HOST

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $TDX_HOST
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

# Add IP if TDX_HOST looks like an IP address
if [[ $TDX_HOST =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "IP.2 = $TDX_HOST" >> server_ext.cnf
fi

# Generate CSR
openssl req -new -key server.key -out server.csr -config server_ext.cnf

# Sign with CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days $VALIDITY \
    -extfile server_ext.cnf -extensions req_ext

# Cleanup
rm -f server.csr server_ext.cnf ca.srl

echo "      ✓ server.crt generated"

# Set permissions
chmod 600 *.key
chmod 644 *.crt

echo ""
echo "======================================"
echo "Certificates Generated Successfully"
echo "======================================"
echo ""
echo "Files created:"
echo "  ca.crt      - CA certificate (copy to SGX machine)"
echo "  ca.key      - CA private key (keep secure)"
echo "  server.crt  - Server certificate (for TDX server)"
echo "  server.key  - Server private key (for TDX server)"
echo ""
echo "Deployment:"
echo "  1. Copy ca.crt, server.crt, server.key to TDX machine"
echo "  2. Copy ca.crt to SGX machine"
echo "  3. Update paths in server/verifier configuration"
echo ""
echo "Verification:"
echo "  openssl x509 -in server.crt -text -noout"
echo ""
