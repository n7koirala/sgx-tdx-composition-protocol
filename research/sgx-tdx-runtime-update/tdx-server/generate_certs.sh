#!/bin/bash
# Generate TLS certificates for TDX server
# Run this on the TDX VM

set -e

CERT_DIR="${1:-.}"
TDX_IP="${2:-$(hostname -I | awk '{print $1}')}"

echo "Generating TDX server certificates..."
echo "Certificate directory: $CERT_DIR"
echo "TDX IP: $TDX_IP"

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# Generate CA (or copy from SGX gateway setup)
if [ ! -f ca.key ]; then
    echo "Generating CA..."
    openssl genrsa -out ca.key 4096
    openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
        -out ca.crt -subj "/CN=TDX-SGX-CA/O=Research/C=US"
else
    echo "Using existing CA..."
fi

# Generate TDX server key and certificate
echo "Generating TDX server certificate..."
openssl genrsa -out tdx_server.key 2048

# Create config for SAN
cat > tdx_server.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = TDX Runtime Server
O = Research
C = US

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
IP.1 = $TDX_IP
IP.2 = 127.0.0.1
DNS.1 = localhost
EOF

openssl req -new -key tdx_server.key -out tdx_server.csr -config tdx_server.cnf
openssl x509 -req -in tdx_server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out tdx_server.crt -days 365 -sha256 -extensions v3_req -extfile tdx_server.cnf

# Cleanup
rm -f tdx_server.csr tdx_server.cnf

echo ""
echo "Certificates generated:"
echo "  - ca.crt (CA certificate)"
echo "  - tdx_server.crt (TDX server certificate)"
echo "  - tdx_server.key (TDX server private key)"
echo ""
echo "To start the TDX server:"
echo "  python3 tdx_server.py --cert tdx_server.crt --key tdx_server.key --ca-cert ca.crt"
