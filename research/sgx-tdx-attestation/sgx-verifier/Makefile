# Gramine SGX TDX Verifier - Makefile
#
# Builds and runs the SGX enclave that verifies TDX attestation.
# Part of the Hierarchical TEE Attestation Protocol.

# ============================================================================
# Configuration
# ============================================================================

# Detect Python version and paths
PYTHON_VERSION := $(shell python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_PATH := $(shell which python3)
ARCH_LIBDIR := /lib/$(shell gcc -dumpmachine)

# Application directory (parent of sgx-verifier)
APP_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))..)

# Gramine signing key
SGX_SIGNING_KEY ?= $(HOME)/.config/gramine/enclave-key.pem

# Log level: error, warning, debug, trace, all
LOG_LEVEL ?= error

# TDX server defaults
TDX_HOST ?= localhost
TDX_PORT ?= 8443

# ============================================================================
# Targets
# ============================================================================

.PHONY: all clean run-sgx run-direct test-network check-setup help

# Default target
all: verifier.manifest.sgx verifier.sig

help:
	@echo "SGX TDX Verifier - Hierarchical Attestation"
	@echo "============================================"
	@echo ""
	@echo "Build Targets:"
	@echo "  all           - Build the Gramine manifest and sign it"
	@echo "  clean         - Remove generated files"
	@echo ""
	@echo "Run Targets:"
	@echo "  run-sgx       - Run verifier inside SGX enclave"
	@echo "  run-direct    - Run verifier in direct mode (no SGX)"
	@echo "  test-network  - Test network connectivity to TDX server"
	@echo ""
	@echo "Setup:"
	@echo "  check-setup   - Verify SGX and Gramine setup"
	@echo "  gen-certs     - Generate TLS certificates"
	@echo ""
	@echo "Configuration:"
	@echo "  PYTHON_VERSION = $(PYTHON_VERSION)"
	@echo "  APP_DIR        = $(APP_DIR)"
	@echo "  TDX_HOST       = $(TDX_HOST)"
	@echo "  TDX_PORT       = $(TDX_PORT)"
	@echo ""
	@echo "Example:"
	@echo "  make run-sgx TDX_HOST=192.168.1.100 TDX_PORT=8443"

# ============================================================================
# Build Steps
# ============================================================================

# Step 1: Generate the manifest from template
verifier.manifest: verifier.manifest.template sgx_tdx_verifier.py ../common/protocol.py
	@echo "[1/2] Generating manifest (this may take a few minutes)..."
	@echo "      Gramine is hashing all trusted files..."
	gramine-manifest \
		-Dlog_level=$(LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dpython_path=$(PYTHON_PATH) \
		-Dpython_version=$(PYTHON_VERSION) \
		-Dapp_dir=$(APP_DIR) \
		$< $@
	@echo "      ✓ Manifest generated ($$(du -h $@ | cut -f1))"

# Step 2: Sign the manifest for SGX
verifier.manifest.sgx verifier.sig: verifier.manifest $(SGX_SIGNING_KEY)
	@echo "[2/2] Signing manifest for SGX..."
	gramine-sgx-sign \
		--manifest $< \
		--key $(SGX_SIGNING_KEY) \
		--output $<.sgx
	@echo "      ✓ Manifest signed"
	@echo ""
	@echo "Enclave ready! Measurements:"
	@gramine-sgx-sigstruct-view verifier.sig

# Generate signing key if it doesn't exist
$(SGX_SIGNING_KEY):
	@echo "Generating SGX signing key..."
	gramine-sgx-gen-private-key $@

# ============================================================================
# Run Targets
# ============================================================================

# Run inside SGX enclave
run-sgx: all
	@echo ""
	@echo "Running TDX verifier inside SGX enclave..."
	@echo "Target: $(TDX_HOST):$(TDX_PORT)"
	@echo "========================================"
	gramine-sgx ./verifier /app/sgx-verifier/sgx_tdx_verifier.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--ca-cert /app/certs/ca.crt \
		--verbose

# Run without SGX (direct mode)
run-direct: verifier.manifest
	@echo ""
	@echo "Running TDX verifier in direct mode..."
	@echo "========================================"
	gramine-direct ./verifier /app/sgx-verifier/sgx_tdx_verifier.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--no-verify \
		--verbose

# Run without Gramine at all (pure Python, for testing)
run-python:
	@echo ""
	@echo "Running TDX verifier in pure Python mode..."
	@echo "============================================"
	PYTHONPATH=$(APP_DIR) python3 sgx_tdx_verifier.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--no-verify \
		--verbose

# Test network connectivity
test-network: all
	@echo ""
	@echo "Testing network connectivity to $(TDX_HOST):$(TDX_PORT)..."
	gramine-sgx ./verifier /app/sgx-verifier/sgx_tdx_verifier.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--no-verify \
		--test-network

# ============================================================================
# Certificate Generation
# ============================================================================

gen-certs:
	@echo "Generating TLS certificates..."
	cd ../certs && ./generate_certs.sh

# ============================================================================
# Setup Verification
# ============================================================================

check-setup:
	@echo "Checking SGX and Gramine setup..."
	@echo "=================================="
	@echo ""
	@echo "[1] Gramine version:"
	@gramine-sgx --version 2>/dev/null || echo "   ✗ Gramine not found"
	@echo ""
	@echo "[2] SGX device:"
	@ls -la /dev/sgx_enclave 2>/dev/null && echo "   ✓ SGX device available" || echo "   ✗ SGX device not found"
	@echo ""
	@echo "[3] AESM service:"
	@systemctl is-active aesmd 2>/dev/null && echo "   ✓ AESM running" || echo "   ✗ AESM not running"
	@echo ""
	@echo "[4] Signing key:"
	@test -f $(SGX_SIGNING_KEY) && echo "   ✓ Key exists" || echo "   ✗ Key not found"
	@echo ""
	@echo "[5] Python version: $(PYTHON_VERSION)"
	@echo "   Path: $(PYTHON_PATH)"
	@echo ""
	@echo "[6] Application directory:"
	@echo "   $(APP_DIR)"
	@test -f $(APP_DIR)/common/protocol.py && echo "   ✓ Common module found" || echo "   ✗ Common module not found"
	@echo ""
	@echo "[7] Certificates:"
	@test -f ../certs/ca.crt && echo "   ✓ CA certificate found" || echo "   ✗ CA certificate not found (run: make gen-certs)"
	@echo ""

# ============================================================================
# Cleanup
# ============================================================================

clean:
	rm -f verifier.manifest verifier.manifest.sgx verifier.sig
	rm -rf __pycache__/

distclean: clean
	# Note: Does not remove signing key for safety

# ============================================================================
# View Measurements
# ============================================================================

view-sig: verifier.sig
	@echo "Viewing enclave signature structure..."
	gramine-sgx-sigstruct-view verifier.sig
