#!/bin/bash
# Check SGX attestation configuration

echo "=== SGX Attestation Configuration Check ==="
echo ""

echo "[1] Checking for DCAP components..."
dpkg -l | grep sgx-dcap

echo ""
echo "[2] Checking for Quote Provider Library..."
ls -la /usr/lib/x86_64-linux-gnu/libsgx_dcap_ql.so* 2>/dev/null || echo "Not found"

echo ""
echo "[3] Checking AESM service..."
systemctl status aesmd | grep -A 3 "Active:"

echo ""
echo "[4] Checking DCAP configuration..."
if [ -f /etc/sgx_default_qcnl.conf ]; then
    echo "DCAP config found:"
    cat /etc/sgx_default_qcnl.conf | grep -v "^#" | grep -v "^$"
else
    echo "DCAP config not found"
fi

echo ""
echo "[5] Checking for Quoting Enclave..."
ls -la /usr/lib/x86_64-linux-gnu/libsgx_qe3.signed.so 2>/dev/null || echo "Not found"

echo ""
echo "[6] Testing quote generation capability..."
if command -v sgx_quote_test &> /dev/null; then
    sgx_quote_test
else
    echo "No quote test utility available"
fi

echo ""
echo "=== Configuration Check Complete ==="
