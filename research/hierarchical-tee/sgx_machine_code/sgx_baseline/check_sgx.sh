#!/bin/bash
echo "=== SGX Environment Check ==="
echo ""
echo "[1] CPU SGX Features:"
cpuid | grep -i sgx || echo "cpuid not installed"
cat /proc/cpuinfo | grep -i sgx
echo ""
echo "[2] SGX Devices:"
ls -la /dev/sgx* 2>/dev/null || echo "No SGX devices found"
echo ""
echo "[3] Kernel SGX Support:"
dmesg | grep -i sgx | head -10
echo ""
echo "[4] SGX Driver Version:"
modinfo intel_sgx 2>/dev/null || echo "SGX driver not loaded"
