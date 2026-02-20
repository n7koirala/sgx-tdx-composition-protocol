#!/bin/bash
# ─── TDX DCAP Setup Script ───────────────────────────────────────────────────
#
# Installs Intel DCAP packages needed for full TDX Quote generation.
# The Quote Generation Service (QGS) signs TDREPORTs with the Quoting Enclave,
# enabling remote verification without Intel Trust Authority.
#
# Usage: sudo bash setup_dcap.sh
# ─────────────────────────────────────────────────────────────────────────────

set -e

echo "=================================================="
echo "TDX DCAP Setup"
echo "=================================================="

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root (sudo bash setup_dcap.sh)"
    exit 1
fi

# Check TDX
if [ ! -e /dev/tdx_guest ]; then
    echo "Error: /dev/tdx_guest not found. Is this a TDX VM?"
    exit 1
fi
echo "✓ TDX device found"

# Check Ubuntu version
. /etc/os-release
echo "  OS: $PRETTY_NAME"
echo "  Kernel: $(uname -r)"

# ─── Step 1: Add Intel SGX APT Repository ─────────────────────────────────

echo ""
echo "[1/4] Adding Intel SGX APT repository..."

# Install prerequisites
apt-get update -qq
apt-get install -y -qq curl gnupg2 software-properties-common

# Add Intel's GPG key
curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add - 2>/dev/null

# Add repository for Ubuntu Noble (24.04)
CODENAME="${VERSION_CODENAME}"
if [ -z "$CODENAME" ]; then
    CODENAME="noble"
fi

REPO_URL="https://download.01.org/intel-sgx/sgx_repo/ubuntu"
if ! grep -q "$REPO_URL" /etc/apt/sources.list.d/* 2>/dev/null; then
    echo "deb [arch=amd64] $REPO_URL $CODENAME main" > /etc/apt/sources.list.d/intel-sgx.list
    echo "  Added: $REPO_URL $CODENAME main"
else
    echo "  Intel SGX repository already configured"
fi

apt-get update -qq

echo "✓ Intel SGX repository configured"

# ─── Step 2: Install DCAP Packages ────────────────────────────────────────

echo ""
echo "[2/4] Installing DCAP packages..."

# Core DCAP packages for quote generation
PACKAGES=(
    "libtdx-attest"
    "libtdx-attest-dev"
    "tdx-qgs"
    "libsgx-dcap-ql"
    "libsgx-dcap-default-qpl"
    "libsgx-pce-logic"
    "libsgx-qe3-logic"
)

INSTALLED=0
FAILED=0

for pkg in "${PACKAGES[@]}"; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        echo "  ✓ $pkg (already installed)"
        INSTALLED=$((INSTALLED + 1))
    else
        if apt-get install -y -qq "$pkg" 2>/dev/null; then
            echo "  ✓ $pkg (installed)"
            INSTALLED=$((INSTALLED + 1))
        else
            echo "  ⚠ $pkg (not available, skipping)"
            FAILED=$((FAILED + 1))
        fi
    fi
done

echo "  Installed: $INSTALLED, Skipped: $FAILED"

# ─── Step 3: Configure QPL for Direct Intel PCS Access ─────────────────────

echo ""
echo "[3/4] Configuring Quote Provider Library..."

QPL_CONFIG="/etc/sgx_default_qcnl.conf"

if [ ! -f "$QPL_CONFIG" ]; then
    cat > "$QPL_CONFIG" << 'EOF'
{
  "pccs_url": "https://api.trustedservices.intel.com/sgx/certification/v4/",
  "use_secure_cert": true,
  "retry_times": 6,
  "retry_delay": 10,
  "local_pck_url": "",
  "pck_cache_expire_hours": 168,
  "verify_collateral_cache_expire_hours": 168,
  "custom_request_options": {
    "get_cert": {
      "headers": {},
      "params": {}
    }
  }
}
EOF
    echo "  Created $QPL_CONFIG (direct Intel PCS access)"
else
    echo "  $QPL_CONFIG already exists"
fi

echo "✓ QPL configured"

# ─── Step 4: Start QGS Service ─────────────────────────────────────────────

echo ""
echo "[4/4] Starting QGS service..."

if systemctl list-unit-files | grep -q "qgsd"; then
    systemctl enable qgsd 2>/dev/null || true
    systemctl restart qgsd 2>/dev/null || true

    sleep 2
    if systemctl is-active --quiet qgsd; then
        echo "  ✓ QGS service running"
    else
        echo "  ⚠ QGS service failed to start"
        echo "    Check: systemctl status qgsd"
    fi
else
    echo "  ⚠ QGS service not found (package may not have installed)"
    echo "    Quote generation will fall back to ioctl (TDREPORT only)"
fi

# ─── Summary ───────────────────────────────────────────────────────────────

echo ""
echo "=================================================="
echo "Setup Complete"
echo "=================================================="
echo ""
echo "Test TDREPORT generation:"
echo "  sudo python3 dcap_attestation.py --report-only --verbose"
echo ""
echo "Test full DCAP attestation:"
echo "  sudo python3 dcap_attestation.py --verbose"
echo ""
