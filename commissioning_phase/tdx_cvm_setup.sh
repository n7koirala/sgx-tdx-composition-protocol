#!/bin/bash
# Initial setup script for TDX CVM after launch.
# This script is copied to and executed on the CVM by the SGX controller
# during the commissioning phase.

set -euo pipefail

echo "=== TDX CVM Initial Setup ==="
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo "Kernel: $(uname -r)"

# --- System Update ---
echo ""
echo "--- Updating system packages ---"
sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# --- Install Essential Packages ---
echo ""
echo "--- Installing essential packages ---"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    tpm2-tools \
    build-essential \
    python3 \
    python3-pip \
    curl \
    jq \
    net-tools

# --- Verify TDX Status ---
echo ""
echo "--- Checking TDX status ---"

# Check if configfs-tsm is available (TDX attestation interface)
if [ -d "/sys/kernel/config/tsm/report" ]; then
    echo "✓ TSM report interface is available (TDX supported)"
else
    echo "⚠ TSM report interface not found"
fi

# Check for TDX guest device
if [ -c "/dev/tdx_guest" ] || [ -c "/dev/tdx-guest" ]; then
    echo "✓ TDX guest device found"
else
    echo "⚠ TDX guest device not found (may use configfs-tsm instead)"
fi

# Check kernel support
if dmesg | grep -qi "tdx"; then
    echo "✓ TDX mentioned in dmesg"
    dmesg | grep -i "tdx" | head -5
fi

# --- Security Hardening ---
echo ""
echo "--- Applying basic security hardening ---"

# Disable password authentication for SSH (already set by GCP, but ensure it)
sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config

# Restart SSH to apply changes
sudo systemctl restart sshd || true

echo ""
echo "=== TDX CVM Initial Setup Complete ==="
echo "IP Address: $(hostname -I | awk '{print $1}')"
