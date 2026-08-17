#!/usr/bin/env bash
# Generate a private CA and SAN-bearing server certificates for the
# protocol-1.2 scalability experiments. This is server-authenticated TLS;
# delegated responses remain authenticated by the SGX-derived Ed25519 key.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_OUT="$SCRIPT_DIR/../../research/sgx-tdx-attestation/certs/scalability"

WEN_HOST="129.74.154.215"
WEN_DNS="tjws-06"
TDX_HOST="136.111.107.168"
TDX_DNS="vordr-eval-base"
OUT_DIR="$DEFAULT_OUT"
FORCE=0

usage() {
    cat <<'EOF'
Usage: setup_tls_certs.sh [options]

Options:
  --wen-host HOST   WEN address used by clients (default: 129.74.154.215)
  --wen-dns NAME    Additional WEN DNS SAN (default: tjws-06)
  --tdx-host HOST   TDX address used by WEN (default: 136.111.107.168)
  --tdx-dns NAME    Additional TDX DNS SAN (default: vordr-eval-base)
  --out-dir DIR     Certificate output directory
  --force           Replace certificates generated in the output directory
  -h, --help        Show this help

The output contains:
  ca.crt / ca.key
  wen-server.crt / wen-server.key
  tdx-server.crt / tdx-server.key

Keep ca.key and both server private keys secret. Copy only ca.crt plus the
TDX leaf certificate/key to the CVM.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --wen-host) WEN_HOST="$2"; shift 2 ;;
        --wen-dns) WEN_DNS="$2"; shift 2 ;;
        --tdx-host) TDX_HOST="$2"; shift 2 ;;
        --tdx-dns) TDX_DNS="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

command -v openssl >/dev/null 2>&1 || {
    echo "openssl is required" >&2
    exit 1
}

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

generated_files=(
    ca.key ca.crt ca.srl
    wen-server.key wen-server.csr wen-server.crt wen-server.ext
    tdx-server.key tdx-server.csr tdx-server.crt tdx-server.ext
)
for file in "${generated_files[@]}"; do
    if [[ -e "$OUT_DIR/$file" && "$FORCE" -ne 1 ]]; then
        echo "Refusing to overwrite $OUT_DIR/$file; use --force" >&2
        exit 1
    fi
done
if [[ "$FORCE" -eq 1 ]]; then
    for file in "${generated_files[@]}"; do
        rm -f "$OUT_DIR/$file"
    done
fi

is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

write_server_ext() {
    local host="$1"
    local dns_name="$2"
    local output="$3"

    cat >"$output" <<'EOF'
[v3_server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
EOF

    if is_ipv4 "$host"; then
        printf 'IP.1 = %s\n' "$host" >>"$output"
        if [[ "$host" != "127.0.0.1" ]]; then
            printf 'IP.2 = 127.0.0.1\n' >>"$output"
        fi
        if [[ -n "$dns_name" ]]; then
            printf 'DNS.1 = %s\n' "$dns_name" >>"$output"
        fi
    else
        printf 'DNS.1 = %s\n' "$host" >>"$output"
        if [[ -n "$dns_name" && "$dns_name" != "$host" ]]; then
            printf 'DNS.2 = %s\n' "$dns_name" >>"$output"
        fi
        printf 'IP.1 = 127.0.0.1\n' >>"$output"
    fi
}

generate_leaf() {
    local prefix="$1"
    local common_name="$2"
    local organizational_unit="$3"
    local ext_file="$OUT_DIR/$prefix.ext"

    openssl req -new -newkey rsa:2048 -nodes         -keyout "$OUT_DIR/$prefix.key"         -out "$OUT_DIR/$prefix.csr"         -subj "/C=US/ST=Indiana/L=Notre Dame/O=Vordr/OU=$organizational_unit/CN=$common_name"

    openssl x509 -req         -in "$OUT_DIR/$prefix.csr"         -CA "$OUT_DIR/ca.crt"         -CAkey "$OUT_DIR/ca.key"         -CAcreateserial         -days 825         -sha256         -extfile "$ext_file"         -extensions v3_server         -out "$OUT_DIR/$prefix.crt"

    rm -f "$OUT_DIR/$prefix.csr" "$ext_file"
}

echo "[1/5] Generating experiment CA"
openssl genrsa -out "$OUT_DIR/ca.key" 4096
openssl req -new -x509     -key "$OUT_DIR/ca.key"     -out "$OUT_DIR/ca.crt"     -days 3650     -sha256     -subj "/C=US/ST=Indiana/L=Notre Dame/O=Vordr/OU=Evaluation/CN=Vordr-Scalability-CA"     -addext "basicConstraints=critical,CA:TRUE,pathlen:0"     -addext "keyUsage=critical,keyCertSign,cRLSign"     -addext "subjectKeyIdentifier=hash"

echo "[2/5] Generating WEN server certificate for $WEN_HOST"
write_server_ext "$WEN_HOST" "$WEN_DNS" "$OUT_DIR/wen-server.ext"
generate_leaf "wen-server" "$WEN_HOST" "SGX-WEN"

echo "[3/5] Generating TDX server certificate for $TDX_HOST"
write_server_ext "$TDX_HOST" "$TDX_DNS" "$OUT_DIR/tdx-server.ext"
generate_leaf "tdx-server" "$TDX_HOST" "TDX-CVM"

echo "[4/5] Verifying certificate chains"
openssl verify -CAfile "$OUT_DIR/ca.crt"     "$OUT_DIR/wen-server.crt"     "$OUT_DIR/tdx-server.crt"

echo "[5/5] Setting permissions"
chmod 600 "$OUT_DIR/ca.key" "$OUT_DIR/wen-server.key" "$OUT_DIR/tdx-server.key"
chmod 644 "$OUT_DIR/ca.crt" "$OUT_DIR/wen-server.crt" "$OUT_DIR/tdx-server.crt"
rm -f "$OUT_DIR/ca.srl"

echo
echo "TLS material generated in: $OUT_DIR"
echo "WEN SANs:"
openssl x509 -in "$OUT_DIR/wen-server.crt" -noout -ext subjectAltName
echo "TDX SANs:"
openssl x509 -in "$OUT_DIR/tdx-server.crt" -noout -ext subjectAltName
echo
echo "Do not copy ca.key or wen-server.key to the CVM."

