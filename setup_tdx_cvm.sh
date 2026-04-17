#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# TDX CVM Setup Script — DCAP Attestation + Project Dependencies
#
# Installs everything a freshly launched Intel TDX CVM (Ubuntu 24.04 Noble)
# needs for DCAP-based quote generation and to run the attestation protocols
# in this repository.
#
# What this installs:
#   1. Intel SGX/DCAP APT repository
#   2. libtdx-attest (TDX attestation library for DCAP quote generation)
#   3. DCAP infrastructure (QGS, QPL, quoting libraries)
#   4. QPL configuration (direct Intel PCS — no local PCCS needed)
#   5. Python dependencies (cryptography, requests, flask)
#   6. TLS certificate generation tools
#   7. IMA verification (checks /sys/kernel/security/ima/ is available)
#
# Tested on: Ubuntu 24.04.3 LTS (Noble Numbat), kernel 6.17.0-1009-gcp
#
# Usage:
#   sudo bash setup_tdx_cvm.sh
#   sudo bash setup_tdx_cvm.sh --check    # verify-only mode (no installs)
# ─────────────────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Color helpers ───────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; }

# ─── Check-only mode ────────────────────────────────────────────────────────
if [ "$1" = "--check" ]; then
    echo "========================================================================"
    echo "  TDX CVM Setup — Verification Check"
    echo "========================================================================"
    echo ""

    # OS
    echo "[OS]"
    echo "  $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
    echo "  Kernel: $(uname -r)"
    echo ""

    # TDX device
    echo "[TDX Hardware]"
    if [ -e /dev/tdx_guest ]; then
        ok "/dev/tdx_guest available"
    else
        fail "/dev/tdx_guest NOT found — this is not a TDX VM"
    fi
    echo ""

    # DCAP libraries
    echo "[DCAP Libraries]"
    for pkg in libtdx-attest libsgx-dcap-ql libsgx-dcap-default-qpl \
               libsgx-pce-logic libsgx-qe3-logic tdx-qgs libsgx-urts; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            ver=$(dpkg -l "$pkg" 2>/dev/null | grep "^ii" | awk '{print $3}')
            ok "$pkg ($ver)"
        else
            fail "$pkg NOT installed"
        fi
    done
    echo ""

    # Shared libraries
    echo "[Shared Libraries]"
    for lib in libtdx_attest libsgx_dcap_ql; do
        found=$(ldconfig -p 2>/dev/null | grep "$lib" | head -1)
        if [ -n "$found" ]; then
            ok "$found"
        else
            fail "$lib not found in ldconfig"
        fi
    done
    echo ""

    # QGS service
    echo "[QGS Service]"
    if systemctl is-active --quiet qgsd 2>/dev/null; then
        ok "qgsd is running"
    else
        warn "qgsd is NOT running"
    fi
    echo ""

    # QPL configuration
    echo "[QPL Configuration]"
    if [ -f /etc/sgx_default_qcnl.conf ]; then
        ok "/etc/sgx_default_qcnl.conf exists"
        pccs_url=$(grep '"pccs_url"' /etc/sgx_default_qcnl.conf 2>/dev/null | head -1)
        echo "    $pccs_url"
    else
        fail "/etc/sgx_default_qcnl.conf NOT found"
    fi
    echo ""

    # Python
    echo "[Python]"
    if command -v python3 &>/dev/null; then
        ok "python3: $(python3 --version 2>&1)"
    else
        fail "python3 not found"
    fi
    for pypkg in cryptography requests flask; do
        if python3 -c "import $pypkg" 2>/dev/null; then
            ver=$(python3 -c "import $pypkg; print($pypkg.__version__)" 2>/dev/null)
            ok "$pypkg ($ver)"
        else
            fail "$pypkg NOT installed"
        fi
    done
    echo ""

    # IMA
    echo "[IMA Runtime Measurements]"
    IMA_LOG="/sys/kernel/security/ima/ascii_runtime_measurements"
    IMA_COUNT="/sys/kernel/security/ima/runtime_measurements_count"
    PCR10="/sys/class/tpm/tpm0/pcr-sha256/10"
    if [ -f "$IMA_LOG" ]; then
        count=$(cat "$IMA_COUNT" 2>/dev/null || echo "?")
        ok "IMA log available ($count entries)"
    else
        warn "IMA log not available at $IMA_LOG"
    fi
    if [ -f "$PCR10" ]; then
        pcr=$(cat "$PCR10" 2>/dev/null | head -c 16)
        ok "PCR 10: ${pcr}..."
    else
        warn "PCR 10 not available"
    fi
    echo ""

    # TLS certs
    echo "[TLS Certificates]"
    CERTS_DIR="$SCRIPT_DIR/research/sgx-tdx-attestation/certs"
    for cert in server.crt server.key ca.crt; do
        if [ -f "$CERTS_DIR/$cert" ]; then
            ok "$cert"
        else
            warn "$cert missing (run: cd $CERTS_DIR && ./generate_certs.sh)"
        fi
    done
    echo ""

    echo "========================================================================"
    exit 0
fi

# ─── Main Installation ──────────────────────────────────────────────────────

echo "========================================================================"
echo "  TDX CVM Setup — DCAP Attestation Dependencies"
echo "========================================================================"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root: sudo bash setup_tdx_cvm.sh"
    exit 1
fi

# ─── Pre-flight checks ──────────────────────────────────────────────────────

echo "[0/7] Pre-flight checks..."

# OS version
. /etc/os-release
echo "  OS:     $PRETTY_NAME"
echo "  Kernel: $(uname -r)"

CODENAME="${VERSION_CODENAME:-noble}"
echo "  Codename: $CODENAME"

# TDX device
if [ -e /dev/tdx_guest ]; then
    ok "/dev/tdx_guest found"
else
    fail "/dev/tdx_guest NOT found"
    echo "       This script is designed for Intel TDX CVMs."
    echo "       Continuing anyway (some packages may not work)..."
fi

echo ""

# ─── Step 1: System packages ────────────────────────────────────────────────

echo "[1/7] Installing system prerequisites..."

apt-get update -qq
apt-get install -y -qq \
    curl \
    gnupg2 \
    software-properties-common \
    build-essential \
    openssl \
    ca-certificates \
    python3 \
    python3-pip \
    python3-venv \
    2>/dev/null

ok "System prerequisites installed"
echo ""

# ─── Step 2: Intel SGX/DCAP APT repository ──────────────────────────────────

echo "[2/7] Adding Intel SGX/DCAP APT repository..."

# Add Intel's GPG key (modern method — no apt-key)
curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
    gpg --dearmor -o /usr/share/keyrings/intel-sgx-keyring.gpg 2>/dev/null || true

# Add repository
REPO_LINE="deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-keyring.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu $CODENAME main"
echo "$REPO_LINE" > /etc/apt/sources.list.d/intel-sgx.list
echo "  Repository: $CODENAME"

apt-get update -qq

ok "Intel SGX/DCAP repository configured"
echo ""

# ─── Step 3: DCAP packages ──────────────────────────────────────────────────

echo "[3/7] Installing Intel DCAP packages..."

# These are the exact packages needed for TDX DCAP quote generation,
# matching what's installed on the existing CVM
DCAP_PACKAGES=(
    # Core TDX attestation library (quote generation via libtdx_attest.so)
    "libtdx-attest"
    "libtdx-attest-dev"

    # Quote Generation Service (signs TDREPORTs via Quoting Enclave)
    "tdx-qgs"

    # DCAP quoting libraries
    "libsgx-dcap-ql"
    "libsgx-dcap-ql-dev"
    "libsgx-dcap-default-qpl"

    # Quote verification (for local verification)
    "libsgx-dcap-quote-verify"
    "libsgx-dcap-quote-verify-dev"

    # Logic libraries (PCE and QE3 enclaves)
    "libsgx-pce-logic"
    "libsgx-qe3-logic"
    "libsgx-tdx-logic"

    # SGX runtime (needed by DCAP infrastructure)
    "libsgx-urts"
    "libsgx-enclave-common"
    "libsgx-launch"
    "libsgx-quote-ex"
    "libsgx-headers"

    # AESM service and plugins (manages enclaves)
    "sgx-aesm-service"
    "libsgx-aesm-ecdsa-plugin"
    "libsgx-aesm-pce-plugin"
    "libsgx-aesm-quote-ex-plugin"
    "libsgx-aesm-launch-plugin"

    # Enclave binaries
    "libsgx-ae-pce"
    "libsgx-ae-qe3"
    "libsgx-ae-qve"
    "libsgx-ae-tdqe"
    "libsgx-ae-id-enclave"
    "libsgx-ae-le"
)

INSTALLED=0
FAILED=0

for pkg in "${DCAP_PACKAGES[@]}"; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        ok "$pkg (already installed)"
        INSTALLED=$((INSTALLED + 1))
    else
        if apt-get install -y -qq "$pkg" 2>/dev/null; then
            ok "$pkg (newly installed)"
            INSTALLED=$((INSTALLED + 1))
        else
            warn "$pkg (not available for $CODENAME, skipping)"
            FAILED=$((FAILED + 1))
        fi
    fi
done

echo ""
echo "  Installed: $INSTALLED, Skipped: $FAILED"
echo ""

# ─── Step 4: QPL configuration ──────────────────────────────────────────────

echo "[4/7] Configuring Quote Provider Library (QPL)..."

QPL_CONFIG="/etc/sgx_default_qcnl.conf"

# Back up existing config if present
if [ -f "$QPL_CONFIG" ]; then
    cp "$QPL_CONFIG" "${QPL_CONFIG}.bak.$(date +%s)"
    warn "Backed up existing $QPL_CONFIG"
fi

# Write QPL config that uses Intel PCS directly (no local PCCS needed)
# This is the recommended configuration for cloud-based TDX CVMs
cat > "$QPL_CONFIG" << 'QPLEOF'
{
  // Intel PCS (Provisioning Certification Service) for direct access
  // No local PCCS needed — quotes are verified against Intel's service
  "pccs_url": "https://api.trustedservices.intel.com/sgx/certification/v4/",

  // Use secure (HTTPS) connection to Intel PCS
  "use_secure_cert": true,

  // Retry configuration for PCS requests
  "retry_times": 6,
  "retry_delay": 10,

  // No local PCK URL needed (using Intel PCS directly)
  "local_pck_url": "",

  // Cache expiration (7 days)
  "pck_cache_expire_hours": 168,
  "verify_collateral_cache_expire_hours": 168
}
QPLEOF

ok "QPL configured for direct Intel PCS access"
echo "  Config: $QPL_CONFIG"
echo ""

# ─── Step 5: Start services ─────────────────────────────────────────────────

echo "[5/7] Starting DCAP services..."

# Enable and start QGS (Quote Generation Service)
if systemctl list-unit-files 2>/dev/null | grep -q "qgsd"; then
    systemctl enable qgsd 2>/dev/null || true
    systemctl restart qgsd 2>/dev/null || true
    sleep 2

    if systemctl is-active --quiet qgsd 2>/dev/null; then
        ok "QGS service (qgsd) running"
    else
        warn "QGS service failed to start"
        echo "    Debug: systemctl status qgsd"
        echo "    This is often OK on GCP TDX VMs (GCP handles quote generation)"
    fi
else
    warn "QGS service not found"
fi

# Enable and start AESM service
if systemctl list-unit-files 2>/dev/null | grep -q "aesmd"; then
    systemctl enable aesmd 2>/dev/null || true
    systemctl restart aesmd 2>/dev/null || true
    sleep 2

    if systemctl is-active --quiet aesmd 2>/dev/null; then
        ok "AESM service (aesmd) running"
    else
        warn "AESM service failed to start"
    fi
else
    warn "AESM service not found"
fi

# Update shared library cache
ldconfig
ok "ldconfig updated"
echo ""

# ─── Step 6: Python dependencies ────────────────────────────────────────────

echo "[6/7] Installing Python dependencies..."

# Install Python packages needed by the attestation code
pip3 install --break-system-packages --quiet \
    cryptography \
    requests \
    flask \
    2>/dev/null || \
pip3 install \
    cryptography \
    requests \
    flask \
    2>/dev/null || true

# Verify Python imports
for pypkg in cryptography requests flask ssl json base64 hashlib socket struct; do
    if python3 -c "import $pypkg" 2>/dev/null; then
        ok "python3: $pypkg"
    else
        fail "python3: $pypkg NOT importable"
    fi
done

echo ""

# ─── Step 7: Verification ───────────────────────────────────────────────────

echo "[7/7] Verifying installation..."
echo ""

ERRORS=0

# Check shared libraries
echo "  Shared libraries:"
for lib in libtdx_attest libsgx_dcap_ql; do
    found=$(ldconfig -p 2>/dev/null | grep "$lib" | head -1)
    if [ -n "$found" ]; then
        ok "$found"
    else
        fail "$lib not found in ldconfig"
        ERRORS=$((ERRORS + 1))
    fi
done

# Check header files
echo ""
echo "  Header files:"
for header in /usr/include/tdx_attest.h /usr/include/sgx_dcap_ql_wrapper.h; do
    if [ -f "$header" ]; then
        ok "$header"
    else
        warn "$header not found (dev package may be missing)"
    fi
done

# Check TDX device
echo ""
echo "  TDX device:"
if [ -c /dev/tdx_guest ] || [ -e /dev/tdx_guest ]; then
    ok "/dev/tdx_guest accessible"
else
    fail "/dev/tdx_guest not accessible"
    ERRORS=$((ERRORS + 1))
fi

# Check IMA
echo ""
echo "  IMA runtime measurements:"
IMA_LOG="/sys/kernel/security/ima/ascii_runtime_measurements"
if [ -f "$IMA_LOG" ]; then
    count=$(cat /sys/kernel/security/ima/runtime_measurements_count 2>/dev/null || echo "?")
    ok "IMA log available ($count entries)"
else
    warn "IMA log not available (check kernel config / securityfs mount)"
fi

# Quick smoke test: can we load libtdx_attest from Python?
echo ""
echo "  Python libtdx_attest load test:"
if python3 -c "
import ctypes, ctypes.util, sys
for name in ['libtdx_attest.so', 'libtdx_attest.so.1', ctypes.util.find_library('tdx_attest')]:
    if name is None: continue
    try:
        lib = ctypes.CDLL(name)
        print(f'    Loaded: {name}')
        sys.exit(0)
    except SystemExit: raise
    except Exception: pass
sys.exit(1)
" 2>/dev/null; then
    ok "libtdx_attest loadable from Python"
else
    fail "libtdx_attest NOT loadable from Python"
    ERRORS=$((ERRORS + 1))
fi

# ─── Summary ────────────────────────────────────────────────────────────────

echo ""
echo "========================================================================"
if [ $ERRORS -eq 0 ]; then
    echo -e "  ${GREEN}Setup Complete — All checks passed!${NC}"
else
    echo -e "  ${YELLOW}Setup Complete — $ERRORS issue(s) detected${NC}"
fi
echo "========================================================================"
echo ""
echo "  Quick verification:"
echo "    sudo bash setup_tdx_cvm.sh --check"
echo ""
echo "  Test DCAP quote generation (Python):"
echo "    sudo python3 -c \""
echo "      import ctypes"
echo "      lib = ctypes.CDLL('libtdx_attest.so')"
echo "      print('libtdx_attest loaded successfully')"
echo "    \""
echo ""
echo "  Run attestation server:"
echo "    cd research/sgx-tdx-attestation/tdx-server"
echo "    sudo python3 tdx_attestation_server.py --port 8443 --method dcap"
echo ""
echo "  Run incremental attestation agent:"
echo "    cd incremental_attestation"
echo "    sudo python3 cvm_attestation_agent.py --port 8443 --method dcap"
echo ""
echo "========================================================================"
