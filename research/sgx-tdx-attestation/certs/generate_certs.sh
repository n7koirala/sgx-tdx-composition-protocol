#!/bin/bash
# Generate TLS Certificates for Hierarchical TEE Attestation (with mTLS)
#
# Creates certificates for mutual TLS authentication between SGX and TDX.
# The SGX client certificate ensures only the authorized enclave can connect.
#
# Output files:
#   ca.key          - CA private key (keep secure, do not distribute)
#   ca.crt          - CA certificate (copy to both SGX and TDX machines)
#   server.key      - TDX server private key
#   server.crt      - TDX server certificate
#   sgx_client.key  - SGX enclave client private key (bundle into enclave)
#   sgx_client.crt  - SGX enclave client certificate (bundle into enclave)
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
echo "mTLS Certificate Generation"
echo "======================================"
echo "TDX Host: $TDX_HOST"
echo "Output:   $CERT_DIR"
echo ""

# Step 1: Generate CA private key
echo "[1/6] Generating CA private key..."
openssl genrsa -out ca.key 4096
echo "      ✓ ca.key generated"

# Step 2: Generate CA certificate
echo "[2/6] Generating CA certificate..."
openssl req -new -x509 -days $VALIDITY -key ca.key -out ca.crt \
    -subj "/C=US/ST=Research/L=Lab/O=Hierarchical-TEE/OU=CA/CN=Hierarchical-TEE-CA"
echo "      ✓ ca.crt generated"

# Step 3: Generate TDX server private key
echo "[3/6] Generating TDX server private key..."
openssl genrsa -out server.key 2048
echo "      ✓ server.key generated"

# Step 4: Generate TDX server certificate
echo "[4/6] Generating TDX server certificate..."

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

# Cleanup server temp files
rm -f server.csr server_ext.cnf ca.srl

echo "      ✓ server.crt generated"

# Step 5: Generate SGX client private key
echo "[5/6] Generating SGX client private key..."
openssl genrsa -out sgx_client.key 2048
echo "      ✓ sgx_client.key generated"

# Step 6: Generate SGX client certificate
echo "[6/6] Generating SGX client certificate..."

# Create config for SGX client cert
cat > sgx_client_ext.cnf << EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn

[dn]
C = US
ST = Research
L = Lab
O = Hierarchical-TEE
OU = SGX-Controller
CN = sgx-controller-enclave
EOF

# Generate CSR
openssl req -new -key sgx_client.key -out sgx_client.csr -config sgx_client_ext.cnf

# Sign with CA
openssl x509 -req -in sgx_client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out sgx_client.crt -days $VALIDITY

# Cleanup client temp files
rm -f sgx_client.csr sgx_client_ext.cnf ca.srl

echo "      ✓ sgx_client.crt generated"

# Set permissions
chmod 600 *.key
chmod 644 *.crt

echo ""
echo "======================================"
echo "mTLS Certificates Generated Successfully"
echo "======================================"
echo ""
echo "Files created:"
echo "  ca.crt          - CA certificate (copy to BOTH machines)"
echo "  ca.key          - CA private key (keep secure, do not distribute)"
echo "  server.crt      - TDX server certificate"
echo "  server.key      - TDX server private key"
echo "  sgx_client.crt  - SGX enclave client certificate"
echo "  sgx_client.key  - SGX enclave client private key"
echo ""
echo "Deployment for mTLS:"
echo "  TDX Machine:"
echo "    - ca.crt       (to verify client certificates)"
echo "    - server.crt   (server identity)"
echo "    - server.key   (server private key)"
echo ""
echo "  SGX Machine:"
echo "    - ca.crt         (to verify server certificate)"
echo "    - sgx_client.crt (enclave identity)"
echo "    - sgx_client.key (enclave private key)"
echo ""
echo "Security Note:"
echo "  The sgx_client.key should be bundled into the SGX enclave."
echo "  Anyone with this key can authenticate as the enclave."
echo ""
echo "Verification:"
echo "  openssl x509 -in server.crt -text -noout"
echo "  openssl x509 -in sgx_client.crt -text -noout"
echo ""

