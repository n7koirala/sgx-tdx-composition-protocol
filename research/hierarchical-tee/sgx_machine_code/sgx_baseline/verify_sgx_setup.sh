#!/bin/bash
echo "=== SGX Setup Verification ==="
echo ""

# Check 1: SGX devices
echo "[1] SGX Devices:"
if [ -e /dev/sgx_enclave ]; then
    echo "  ✓ /dev/sgx_enclave exists"
else
    echo "  ✗ /dev/sgx_enclave missing"
fi

# Check 2: User groups
echo ""
echo "[2] User Groups:"
if groups | grep -q sgx; then
    echo "  ✓ User is in 'sgx' group"
else
    echo "  ✗ User NOT in 'sgx' group - run: sudo usermod -a -G sgx $USER"
fi

# Check 3: Device access
echo ""
echo "[3] Device Access:"
if [ -r /dev/sgx_enclave ] && [ -w /dev/sgx_enclave ]; then
    echo "  ✓ Can read/write /dev/sgx_enclave"
else
    echo "  ✗ Cannot access /dev/sgx_enclave"
fi

# Check 4: SGX SDK
echo ""
echo "[4] SGX SDK:"
if [ -n "$SGX_SDK" ]; then
    echo "  ✓ SGX_SDK is set: $SGX_SDK"
else
    echo "  ✗ SGX_SDK not set - run: source ~/sgxsdk/sgxsdk/environment"
fi

# Check 5: AESM service
echo ""
echo "[5] AESM Service:"
if systemctl is-active --quiet aesmd; then
    echo "  ✓ AESM service is running"
else
    echo "  ✗ AESM service not running - run: sudo systemctl start aesmd"
fi

# Check 6: SGX libraries
echo ""
echo "[6] SGX Libraries:"
if ldconfig -p | grep -q libsgx; then
    echo "  ✓ SGX libraries found"
    ldconfig -p | grep libsgx | head -3
else
    echo "  ✗ SGX libraries not found"
fi

echo ""
echo "=== Verification Complete ==="
