#!/bin/bash
# ─── Install Intel DCAP User-Space Packages for TDX Attestation ──────────────
#
# Installs the full Intel DCAP stack including:
#   - libtdx-attest:     TDX attestation library (quote generation)
#   - libsgx-dcap-ql:    Quote generation library
#   - libsgx-dcap-quote-verify: Quote verification library
#   - tdx-qgs:           Quote Generation Service daemon
#
# Usage: sudo bash install_dcap_packages.sh
# ─────────────────────────────────────────────────────────────────────────────

set -e

echo "================================================================"
echo "Intel DCAP Package Installation for Ubuntu 24.04 (Noble)"
echo "================================================================"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root: sudo bash install_dcap_packages.sh"
    exit 1
fi

# Check TDX
if [ ! -e /dev/tdx_guest ]; then
    echo "Warning: /dev/tdx_guest not found. TDX may not be available."
fi

echo ""
echo "[1/4] Adding Intel SGX/TDX APT repository..."

# Install prerequisites
apt-get install -y -qq curl gnupg2 software-properties-common

# Add Intel's GPG key
curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
    gpg --dearmor -o /usr/share/keyrings/intel-sgx-keyring.gpg 2>/dev/null || true

# Add repository for Ubuntu Noble (24.04)
CODENAME=$(lsb_release -cs 2>/dev/null || echo "noble")
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-keyring.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu $CODENAME main" \
    > /etc/apt/sources.list.d/intel-sgx.list
echo "  Repository: https://download.01.org/intel-sgx/sgx_repo/ubuntu $CODENAME"

# Update
apt-get update -qq
echo "✓ Repository configured"

echo ""
echo "[2/4] Installing DCAP packages..."

# Core DCAP libraries
PACKAGES=(
    "libtdx-attest"
    "libtdx-attest-dev"
    "libsgx-dcap-ql"
    "libsgx-dcap-ql-dev"
    "libsgx-dcap-default-qpl"
    "libsgx-dcap-quote-verify"
    "libsgx-dcap-quote-verify-dev"
    "libsgx-pce-logic"
    "libsgx-qe3-logic"
    "tdx-qgs"
    "libsgx-urts"
)

for pkg in "${PACKAGES[@]}"; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        echo "  ✓ $pkg (already installed)"
    else
        if apt-get install -y "$pkg" 2>/dev/null; then
            echo "  ✓ $pkg (installed)"
        else
            echo "  ⚠ $pkg (not available for $CODENAME, skipping)"
        fi
    fi
done

echo ""
echo "[3/4] Configuring Quote Provider Library (QPL)..."

# Configure QPL to use Intel PCS directly (no local PCCS needed)
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
  "verify_collateral_cache_expire_hours": 168
}
EOF
    echo "  Created $QPL_CONFIG"
else
    echo "  $QPL_CONFIG already exists"
fi

echo ""
echo "[4/4] Checking installed libraries..."

# Check for shared libraries
echo ""
echo "  Shared libraries:"
for lib in libtdx_attest libsgx_dcap_ql libsgx_dcap_quoteverify; do
    found=$(ldconfig -p 2>/dev/null | grep "$lib" | head -1)
    if [ -n "$found" ]; then
        echo "    ✓ $found"
    else
        echo "    ✗ $lib not found in ldconfig"
    fi
done

# Check for header files
echo ""
echo "  Header files:"
for header in /usr/include/tdx_attest.h /usr/include/sgx_dcap_ql_wrapper.h /usr/include/sgx_dcap_quoteverify.h; do
    if [ -f "$header" ]; then
        echo "    ✓ $header"
    else
        echo "    ✗ $header not found"
    fi
done

# Start QGS if available
if systemctl list-unit-files 2>/dev/null | grep -q qgsd; then
    systemctl enable qgsd 2>/dev/null || true
    systemctl restart qgsd 2>/dev/null || true
    if systemctl is-active --quiet qgsd 2>/dev/null; then
        echo ""
        echo "  ✓ QGS service running"
    else
        echo ""
        echo "  ⚠ QGS service not running (may not be needed on GCP)"
    fi
fi

echo ""
echo "================================================================"
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Verify: python3 dcap_with_library.py --check"
echo "  2. Benchmark: sudo python3 dcap_with_library.py --benchmark"
echo "================================================================"
