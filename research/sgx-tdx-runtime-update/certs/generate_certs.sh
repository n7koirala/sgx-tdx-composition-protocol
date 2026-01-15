#!/bin/bash
# Generate TLS Certificates for SGX-TDX Runtime Update System
#
# Creates certificates for mTLS between ASP clients and SGX Gateway.
#
# Output files:
#   ca.key          - CA private key
#   ca.crt          - CA certificate
#   server.key      - Gateway server private key
#   server.crt      - Gateway server certificate
#   asp_client.key  - ASP client private key (for mTLS)
#   asp_client.crt  - ASP client certificate (for mTLS)

set -e

CERT_DIR="$(dirname "$0")"
cd "$CERT_DIR"

# Gateway hostname/IP
GATEWAY_HOST="${1:-localhost}"

# Certificate validity (days)
VALIDITY=365

echo "======================================"
echo "Runtime Update TLS Certificate Generation"
echo "======================================"
echo "Gateway Host: $GATEWAY_HOST"
echo ""

# Step 1: Generate CA
echo "[1/6] Generating CA private key..."
openssl genrsa -out ca.key 4096
echo "      ✓ ca.key generated"

echo "[2/6] Generating CA certificate..."
openssl req -new -x509 -days $VALIDITY -key ca.key -out ca.crt \
    -subj "/C=US/ST=Research/L=Lab/O=SGX-TDX-Runtime/OU=CA/CN=Runtime-Update-CA"
echo "      ✓ ca.crt generated"

# Step 2: Generate Gateway server certificate
echo "[3/6] Generating gateway server private key..."
openssl genrsa -out server.key 2048
echo "      ✓ server.key generated"

echo "[4/6] Generating gateway server certificate..."
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
O = SGX-TDX-Runtime
OU = SGX-Gateway
CN = $GATEWAY_HOST

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $GATEWAY_HOST
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

if [[ $GATEWAY_HOST =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "IP.2 = $GATEWAY_HOST" >> server_ext.cnf
fi

openssl req -new -key server.key -out server.csr -config server_ext.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days $VALIDITY -extfile server_ext.cnf -extensions req_ext
rm -f server.csr server_ext.cnf ca.srl
echo "      ✓ server.crt generated"

# Step 3: Generate ASP client certificate (for mTLS)
echo "[5/6] Generating ASP client private key..."
openssl genrsa -out asp_client.key 2048
echo "      ✓ asp_client.key generated"

echo "[6/6] Generating ASP client certificate..."
openssl req -new -key asp_client.key -out asp_client.csr \
    -subj "/C=US/ST=Research/L=Lab/O=SGX-TDX-Runtime/OU=ASP-Client/CN=asp-client"
openssl x509 -req -in asp_client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out asp_client.crt -days $VALIDITY
rm -f asp_client.csr ca.srl
echo "      ✓ asp_client.crt generated"

# Set permissions
chmod 600 *.key
chmod 644 *.crt

echo ""
echo "======================================"
echo "Certificates Generated Successfully"
echo "======================================"
echo ""
echo "Files created:"
echo "  ca.crt          - CA certificate"
echo "  server.crt/key  - Gateway server"
echo "  asp_client.crt/key - ASP client (mTLS)"
echo ""
echo "Deployment:"
echo "  SGX Gateway: ca.crt, server.crt, server.key"
echo "  ASP Client:  ca.crt, asp_client.crt, asp_client.key"
echo ""
